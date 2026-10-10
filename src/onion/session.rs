//! Experimental multiplexed, bidirectionally padded onion sessions.
//! Shaping reduces selected metadata; this is not an anonymity proof.
use super::{
    cell::{CellCommand, OnionCell, ONION_CELL_SIZE, PAYLOAD_SIZE},
    circuit::{OnionCircuit, PeelOutcome, RelayCircuitHop},
    flow::SendWindow,
};
use crate::{
    core::state_machine::{ActiveGuarded, GuardedSocket},
    kernel::ExitPolicy,
    morphing::{JitterEngine, PoissonJitter, RmtEnsemble, RmtTimingEngine},
};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    sync::{mpsc, oneshot},
    task::JoinSet,
    time::Instant,
};
const MAX_STREAMS: usize = 16;
const QUEUE: usize = 32;
const MAX_CONTROLS: usize = 64;
const MAX_IDS: u16 = 1024;
const LIFETIME: Duration = Duration::from_secs(300);
const BUCKET: u64 = 64;
type Error = Box<dyn std::error::Error + Send + Sync>;
fn invalid(message: &'static str) -> Error {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Balanced,
    Strict,
    Rmt,
    Poisson,
}
impl Profile {
    pub fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "balanced" => Ok(Self::Balanced),
            "strict" => Ok(Self::Strict),
            "research-rmt" => Ok(Self::Rmt),
            "research-poisson" => Ok(Self::Poisson),
            _ => Err(invalid("Unknown privacy profile")),
        }
    }
    pub fn encode(self) -> [u8; 2] {
        [
            1,
            match self {
                Self::Balanced => 1,
                Self::Strict => 2,
                Self::Rmt => 3,
                Self::Poisson => 4,
            },
        ]
    }
    pub fn decode(value: &[u8]) -> Result<Self, Error> {
        match value {
            [1, 1] => Ok(Self::Balanced),
            [1, 2] => Ok(Self::Strict),
            [1, 3] => Ok(Self::Rmt),
            [1, 4] => Ok(Self::Poisson),
            _ => Err(invalid("Unsupported session profile/version")),
        }
    }
    fn interval(self) -> Duration {
        match self {
            Self::Balanced => Duration::from_millis(40),
            Self::Strict => Duration::from_millis(20),
            Self::Rmt => JitterEngine::Rmt(RmtTimingEngine::new(RmtEnsemble::GOE, 1.5, 1024))
                .onion_interval(),
            Self::Poisson => JitterEngine::Poisson(PoissonJitter::default()).onion_interval(),
        }
    }
    fn can_finish(self, age: Duration, idle: Duration, cells: u64) -> bool {
        age >= Duration::from_secs(
            ((age.saturating_sub(idle).as_secs() + 10).div_ceil(30) * 30).max(30),
        ) && idle >= Duration::from_secs(10)
            && (cells + 1).is_multiple_of(BUCKET)
    }
}

struct Open {
    host: String,
    port: u16,
    reply: oneshot::Sender<Result<DuplexStream, Error>>,
}
#[derive(Clone)]
pub struct ClientHandle {
    requests: mpsc::Sender<Open>,
}
impl ClientHandle {
    pub fn is_closed(&self) -> bool {
        self.requests.is_closed()
    }
    pub async fn open(&self, host: String, port: u16) -> Result<DuplexStream, Error> {
        let (reply, result) = oneshot::channel();
        self.requests
            .send(Open { host, port, reply })
            .await
            .map_err(|_| invalid("Padded session closed"))?;
        tokio::time::timeout(Duration::from_secs(30), result)
            .await?
            .map_err(|_| invalid("Padded stream setup cancelled"))?
    }
}

struct Stream {
    workers: Vec<tokio::task::AbortHandle>,
    incoming: mpsc::Sender<Option<Vec<u8>>>,
    outgoing: mpsc::Receiver<Vec<u8>>,
    window: SendWindow,
    received: u32,
    written: u32,
    ack: Option<u32>,
    sent_end: bool,
    received_end: bool,
    ready: bool,
    reply: Option<oneshot::Sender<Result<DuplexStream, Error>>>,
    application: Option<DuplexStream>,
}
impl Drop for Stream {
    fn drop(&mut self) {
        for worker in &self.workers {
            worker.abort();
        }
    }
}
enum Event {
    Written(u16, u32),
    Connected(u16, Result<tokio::net::TcpStream, io::Error>),
    Failed(u16),
}
fn attach<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    socket: S,
    id: u16,
    events: mpsc::Sender<Event>,
    tasks: &mut JoinSet<()>,
) -> Stream {
    let (mut reader, mut writer) = tokio::io::split(socket);
    let (incoming, mut input) = mpsc::channel::<Option<Vec<u8>>>(QUEUE + 1);
    let (output, outgoing) = mpsc::channel(QUEUE);
    let written = events.clone();
    let writer_task = tasks.spawn(async move {
        let result = async {
            let mut count = 0u32;
            while let Some(data) = input.recv().await {
                if let Some(data) = data {
                    tokio::time::timeout(Duration::from_secs(30), writer.write_all(&data))
                        .await??;
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| io::Error::other("Write count exhausted"))?;
                    written
                        .send(Event::Written(id, count))
                        .await
                        .map_err(|_| io::Error::other("Session closed"))?;
                } else {
                    writer.shutdown().await?;
                    return Ok::<_, Error>(());
                }
            }
            Ok(())
        }
        .await;
        if result.is_err() {
            let _ = written.send(Event::Failed(id)).await;
        }
    });
    let reader_task = tasks.spawn(async move {
        let result = async {
            loop {
                let mut data = vec![0; PAYLOAD_SIZE];
                let count = reader.read(&mut data).await?;
                if count == 0 {
                    return Ok::<_, Error>(());
                }
                data.truncate(count);
                if output.send(data).await.is_err() {
                    return Ok(());
                }
            }
        }
        .await;
        if result.is_err() {
            let _ = events.send(Event::Failed(id)).await;
        }
    });
    Stream {
        workers: vec![writer_task, reader_task],
        incoming,
        outgoing,
        window: SendWindow::default(),
        received: 0,
        written: 0,
        ack: None,
        sent_end: false,
        received_end: false,
        ready: true,
        reply: None,
        application: None,
    }
}

enum Crypto {
    Client(OnionCircuit),
    Exit(RelayCircuitHop),
}
impl Crypto {
    fn id(&self) -> u32 {
        match self {
            Self::Client(c) => c.circuit_id,
            Self::Exit(c) => c.circuit_id,
        }
    }
    fn outgoing(
        &mut self,
        command: CellCommand,
        id: u16,
        data: &[u8],
    ) -> Result<[u8; ONION_CELL_SIZE], Error> {
        let mut cell = OnionCell::new(self.id(), 0, command, id, data)?;
        match self {
            Self::Client(c) => Ok(c.wrap_forward(&mut cell)?),
            Self::Exit(c) => {
                let mut wire = cell.serialize();
                c.wrap_backward_originate(&mut wire)?;
                Ok(wire)
            }
        }
    }
    fn incoming(&mut self, wire: &mut [u8; ONION_CELL_SIZE]) -> Result<OnionCell, Error> {
        match self {
            Self::Client(c) => {
                let (hop, cell) = c.unwrap_backward(wire)?;
                if hop + 1 != c.hop_count() {
                    return Err(invalid("Session cell originated before exit"));
                }
                Ok(cell)
            }
            Self::Exit(c) => {
                if !matches!(
                    c.peel_forward(wire)?,
                    PeelOutcome::AddressedToThisRelay { .. }
                ) {
                    return Err(invalid("Unaddressed session cell"));
                }
                Ok(OnionCell::parse(wire)?)
            }
        }
    }
}

pub fn start_client(
    socket: GuardedSocket<ActiveGuarded>,
    circuit: OnionCircuit,
    profile: Profile,
) -> (ClientHandle, tokio::task::JoinHandle<Result<(), Error>>) {
    let (requests, receiver) = mpsc::channel(MAX_STREAMS);
    let task = tokio::spawn(async move {
        let (reader, writer) = tokio::io::split(socket);
        let mut workers = JoinSet::new();
        let frames = frame_reader(reader, &mut workers);
        tokio::time::timeout(
            LIFETIME,
            run(
                writer,
                frames,
                Crypto::Client(circuit),
                profile,
                Some(receiver),
                None,
                &mut workers,
            ),
        )
        .await
        .map_err(|_| invalid("Session lifetime expired; no replay"))?
    });
    (ClientHandle { requests }, task)
}
fn frame_reader<R: AsyncRead + Unpin + Send + 'static>(
    mut reader: R,
    tasks: &mut JoinSet<()>,
) -> mpsc::Receiver<[u8; ONION_CELL_SIZE]> {
    let (sender, receiver) = mpsc::channel(4);
    tasks.spawn(async move { loop {
        let mut frame=[0;ONION_CELL_SIZE];
        tokio::select! {
            result=tokio::time::timeout(Duration::from_secs(30),reader.read_exact(&mut frame))=> {if !matches!(result,Ok(Ok(_))) {break;}},
            _=sender.closed()=>break,
        }
        if sender.send(frame).await.is_err() {break;}
    }});
    receiver
}

pub async fn run_exit<W: AsyncWrite + Unpin>(
    writer: W,
    frames: mpsc::Receiver<[u8; ONION_CELL_SIZE]>,
    hop: RelayCircuitHop,
    profile: Profile,
    policy: ExitPolicy,
) -> Result<(), Error> {
    let mut tasks = JoinSet::new();
    tokio::time::timeout(
        LIFETIME,
        run(
            writer,
            frames,
            Crypto::Exit(hop),
            profile,
            None,
            Some(policy),
            &mut tasks,
        ),
    )
    .await
    .map_err(|_| invalid("Session lifetime expired; no replay"))?
}

async fn run<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut frames: mpsc::Receiver<[u8; ONION_CELL_SIZE]>,
    mut crypto: Crypto,
    profile: Profile,
    mut opens: Option<mpsc::Receiver<Open>>,
    policy: Option<ExitPolicy>,
    tasks: &mut JoinSet<()>,
) -> Result<(), Error> {
    let client = opens.is_some();
    let mut streams = BTreeMap::<u16, Stream>::new();
    let mut connecting = std::collections::HashSet::new();
    let mut connect_tasks = std::collections::HashMap::new();
    let mut closed = std::collections::HashSet::new();
    let mut receive_budget = 512.0f64;
    let mut receive_time = Instant::now();
    let (events, mut event_rx) = mpsc::channel(MAX_STREAMS * QUEUE);
    let mut controls = VecDeque::<(CellCommand, u16, Vec<u8>)>::new();
    let mut last_id = 0u16;
    let mut cursor = 0u16;
    let mut cells = 0u64;
    let start = Instant::now();
    let mut activity = start;
    let mut finishing = false;
    let mut peer_finish = false;
    let mut prefer_control = false;
    let clock = tokio::time::sleep(profile.interval());
    tokio::pin!(clock);
    loop {
        if start.elapsed() >= LIFETIME {
            return Err(invalid("Session lifetime expired; no replay"));
        }
        if controls.len() > MAX_CONTROLS {
            return Err(invalid("Session control budget exhausted"));
        }
        tokio::select! {
            _=&mut clock => {
                let idle=streams.is_empty() && connecting.is_empty() && controls.is_empty();
                if idle && profile.can_finish(start.elapsed(),activity.elapsed(),cells) {
                    if client && !finishing { finishing=true; controls.push_back((CellCommand::SessionFinish,0,vec![])); }
                    if !client && peer_finish {
                        let wire=crypto.outgoing(CellCommand::SessionFinished,0,&[])?;
                        tokio::time::timeout(Duration::from_secs(5),async {
                            writer.write_all(&wire).await?;
                            writer.flush().await?;
                            writer.shutdown().await
                        }).await??;
                        return Ok(());
                    }
                }
                prefer_control = !prefer_control;
                let mut selected=None;
                if prefer_control {selected=controls.pop_front();}
                if selected.is_none() && start.elapsed()>=Duration::from_secs(1) {
                    // Round-robin selection, including ACKs and half-close controls.
                    let ids:Vec<_>=streams.keys().copied().collect();
                    for id in ids.iter().copied().filter(|id| *id>cursor).chain(ids.iter().copied().filter(|id| *id<=cursor)) {
                        let stream=streams.get_mut(&id).ok_or_else(||invalid("Missing stream"))?;
                        if !stream.ready {continue;}
                        if let Some(ack)=stream.ack.take() {selected=Some((CellCommand::DataAck,id,ack.to_be_bytes().to_vec()));}
                        else if !stream.sent_end && stream.window.available() {
                            match stream.outgoing.try_recv() {
                                Ok(data)=> {stream.window.sent()?;selected=Some((CellCommand::Data,id,data));},
                                Err(mpsc::error::TryRecvError::Disconnected)=> {stream.sent_end=true;selected=Some((CellCommand::End,id,vec![]));},
                                Err(mpsc::error::TryRecvError::Empty)=>{},
                            }
                        }
                        if selected.is_some() {cursor=id;break;}
                    }
                }
                let (command,id,data)=selected.or_else(||controls.pop_front()).unwrap_or((CellCommand::Dummy,0,vec![]));
                let wire=crypto.outgoing(command,id,&data)?;
                tokio::time::timeout(Duration::from_secs(30),writer.write_all(&wire)).await??;
                // Backpressure must not leave an expired timer and trigger a catch-up burst.
                clock.as_mut().reset(Instant::now()+profile.interval());
                cells=cells.checked_add(1).ok_or_else(||invalid("Cell count exhausted"))?;
                let retired:Vec<_>=streams.iter().filter(|(_,stream)|stream.sent_end && stream.received_end && stream.window.drained() && stream.received==stream.written && stream.ack.is_none()).map(|(id,_)|*id).collect();
                for id in retired {streams.remove(&id);closed.insert(id);}
                let cancelled:Vec<_>=streams.iter().filter(|(_,stream)|stream.reply.as_ref().is_some_and(|reply|reply.is_closed())).map(|(id,_)|*id).collect();
                for id in cancelled {streams.remove(&id);closed.insert(id);controls.push_back((CellCommand::SessionReset,id,vec![]));}
            },
            open=async { if let Some(receiver)=opens.as_mut(){receiver.recv().await}else{std::future::pending().await} }, if !finishing => {
                let Some(open)=open else {return Err(invalid("Session owner closed"));};
                if streams.len()>=MAX_STREAMS || last_id>=MAX_IDS {
                    let _=open.reply.send(Err(invalid("Session stream budget exhausted")));continue;
                }
                if open.port == 0 || open.host.is_empty() {let _=open.reply.send(Err(invalid("Empty target or zero port")));continue;}
                let target=match super::circuit::encode_relay_target(&open.host,open.port) {
                    Ok(target)=>target,
                    Err(error)=> {let _=open.reply.send(Err(error.into()));continue;},
                };
                last_id+=1;
                let (application,local)=tokio::io::duplex(8192);
                let mut stream=attach(local,last_id,events.clone(),tasks);
                stream.ready=false;stream.reply=Some(open.reply);stream.application=Some(application);
                streams.insert(last_id,stream);
                controls.push_back((CellCommand::SessionOpen,last_id,target));
                activity=Instant::now();
            },
            event=event_rx.recv()=>match event.ok_or_else(||invalid("Session event channel closed"))? {
                Event::Written(id,count)=> {
                    let Some(stream)=streams.get_mut(&id) else {continue;};
                    if count!=stream.written+1 || count>stream.received {return Err(invalid("Invalid write acknowledgement"));}
                    stream.written=count;stream.ack=Some(count);
                },
                Event::Connected(id,result)=> {
                    if client {return Err(invalid("Unexpected connect completion"));}
                    connect_tasks.remove(&id);
                    if !connecting.remove(&id) {continue;}
                    match result {
                        Ok(socket)=> {streams.insert(id,attach(socket,id,events.clone(),tasks));controls.push_back((CellCommand::SessionOpened,id,vec![]));},
                        Err(_)=>controls.push_back((CellCommand::SessionRefused,id,vec![1])),
                    }
                },
                Event::Failed(id)=> {
                    if streams.remove(&id).is_some() {closed.insert(id);controls.push_back((CellCommand::SessionReset,id,vec![]));}
                },
            },
            frame=frames.recv()=> {
                let mut frame=frame.ok_or_else(||invalid("Padded session truncated"))?;
                let now=Instant::now();receive_budget=(receive_budget+now.duration_since(receive_time).as_secs_f64()*250.0).min(512.0);receive_time=now;
                if receive_budget<1.0 {return Err(invalid("Session receive rate budget exhausted"));}receive_budget-=1.0;
                let cell=crypto.incoming(&mut frame)?;
                let data=&cell.payload[..cell.length as usize];
                let id=cell.stream_id;
                if closed.contains(&id) && matches!(cell.command,CellCommand::Data|CellCommand::DataAck|CellCommand::End|CellCommand::SessionOpened|CellCommand::SessionRefused) {continue;}
                match cell.command {
                    CellCommand::Dummy if id==0 && data.is_empty()=>{},
                    CellCommand::SessionOpen if !client && !peer_finish && id>last_id && id<=MAX_IDS=> {
                        last_id=id;
                        if streams.len()+connecting.len()>=MAX_STREAMS {controls.push_back((CellCommand::SessionRefused,id,vec![1]));continue;}
                        let (host,port)=super::circuit::decode_relay_target(data)?;
                        if host.is_empty() || port==0 || super::circuit::encode_relay_target(&host,port)? != data {return Err(invalid("Noncanonical session destination"));}
                        let policy=policy.clone().ok_or_else(||invalid("Missing exit policy"))?;
                        let events=events.clone();connecting.insert(id);activity=Instant::now();
                        let task=tasks.spawn(async move {let result=policy.resolve_and_connect(&host,port).await;let _=events.send(Event::Connected(id,result)).await;});
                        connect_tasks.insert(id,task);
                    },
                    CellCommand::SessionOpened if client && data.is_empty()=> {
                        let stream=streams.get_mut(&id).ok_or_else(||invalid("Unknown opened stream"))?;
                        if stream.ready {return Err(invalid("Duplicate stream open acknowledgement"));}
                        stream.ready=true;
                        let reply=stream.reply.take().ok_or_else(||invalid("Missing stream reply"))?;
                        let app=stream.application.take().ok_or_else(||invalid("Missing application stream"))?;
                        if reply.send(Ok(app)).is_err() {streams.remove(&id);closed.insert(id);controls.push_back((CellCommand::SessionReset,id,vec![]));}
                    },
                    CellCommand::SessionRefused if client && data==[1]=> {
                        let mut stream=streams.remove(&id).ok_or_else(||invalid("Unknown refused stream"))?;
                        closed.insert(id);
                        if stream.ready {return Err(invalid("Refusal after stream accepted"));}
                        if let Some(reply)=stream.reply.take(){let _=reply.send(Err(invalid("Exit refused destination")));}
                    },
                    CellCommand::Data=> {
                        let stream=streams.get_mut(&id).ok_or_else(||invalid("Data for unknown stream"))?;
                        if !stream.ready || stream.received_end || data.is_empty() || stream.received-stream.written>=super::flow::WINDOW_CELLS {return Err(invalid("Stream receive credit violation"));}
                        stream.received=stream.received.checked_add(1).ok_or_else(||invalid("Receive count exhausted"))?;
                        stream.incoming.try_send(Some(data.to_vec())).map_err(|_|invalid("Stream receive queue exhausted"))?;
                        activity=Instant::now();
                    },
                    CellCommand::DataAck=> {let stream=streams.get_mut(&id).ok_or_else(||invalid("Ack for unknown stream"))?;if !stream.ready {return Err(invalid("Ack before stream opened"));}stream.window.acknowledge(data)?;},
                    CellCommand::End if data.is_empty()=> {
                        let stream=streams.get_mut(&id).ok_or_else(||invalid("End for unknown stream"))?;
                        if !stream.ready || stream.received_end {return Err(invalid("Duplicate/premature stream end"));}
                        stream.received_end=true;
                        stream.incoming.try_send(None).map_err(|_|invalid("End receive queue exhausted"))?;
                        activity=Instant::now();
                    },
                    CellCommand::SessionReset if id>0 && id<=last_id && data.is_empty()=> {
                        streams.remove(&id);connecting.remove(&id);closed.insert(id);
                        if let Some(task)=connect_tasks.remove(&id) {task.abort();}
                    },
                    CellCommand::SessionFinish if !client && id==0 && data.is_empty() && streams.is_empty() && connecting.is_empty() && !peer_finish=>peer_finish=true,
                    CellCommand::SessionFinished if client && finishing && id==0 && data.is_empty()=>return Ok(()),
                    _=>return Err(invalid("Invalid session command or state")),
                }
            },
            result=tasks.join_next(), if !tasks.is_empty()=> {if result.is_some_and(|result|result.is_err_and(|error| !error.is_cancelled())){return Err(invalid("Session worker panicked"));}},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair() -> (Crypto, Crypto) {
        let (client, exit) = super::super::circuit::perform_client_relay_handshake().unwrap();
        let mut circuit = OnionCircuit::new(101);
        circuit.add_hop(client).unwrap();
        (
            Crypto::Client(circuit),
            Crypto::Exit(RelayCircuitHop::new(101, exit, 0)),
        )
    }
    #[test]
    fn profile_buckets_and_bounds_are_explicit() {
        assert!(!Profile::Balanced.can_finish(
            Duration::from_secs(29),
            Duration::from_secs(29),
            63
        ));
        assert!(!Profile::Balanced.can_finish(Duration::from_secs(30), Duration::from_secs(9), 63));
        assert!(!Profile::Balanced.can_finish(
            Duration::from_secs(30),
            Duration::from_secs(30),
            62
        ));
        assert!(Profile::Balanced.can_finish(Duration::from_secs(30), Duration::from_secs(30), 63));
        assert!(!Profile::Balanced.can_finish(
            Duration::from_secs(59),
            Duration::from_secs(20),
            63
        ));
        for profile in [
            Profile::Balanced,
            Profile::Strict,
            Profile::Rmt,
            Profile::Poisson,
        ] {
            for _ in 0..100 {
                assert!((Duration::from_millis(5)..=Duration::from_millis(100))
                    .contains(&profile.interval()));
            }
        }
    }
    #[tokio::test(start_paused = true)]
    async fn independent_idle_cover_persists_then_finishes_on_volume_boundary() {
        let (mut client, exit) = pair();
        let (tx, rx) = mpsc::channel(4);
        let (writer, mut reader) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            run_exit(
                writer,
                rx,
                match exit {
                    Crypto::Exit(hop) => hop,
                    _ => unreachable!(),
                },
                Profile::Balanced,
                ExitPolicy::new(false),
            )
            .await
        });
        // No application stream/read event triggers this sender.
        let mut count = 0;
        loop {
            let mut wire = [0; ONION_CELL_SIZE];
            reader.read_exact(&mut wire).await.unwrap();
            let cell = client.incoming(&mut wire).unwrap();
            count += 1;
            if count == 8 {
                tx.send(client.outgoing(CellCommand::SessionFinish, 0, &[]).unwrap())
                    .await
                    .unwrap();
            }
            if cell.command == CellCommand::SessionFinished {
                break;
            }
            assert_eq!(cell.command, CellCommand::Dummy);
            assert!(count < 2000);
        }
        assert_eq!(count % 64, 0);
        assert!(count >= 750); // >=30s at 40ms; tail survives an early finish request.
        task.await.unwrap().unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn backpressure_does_not_trigger_a_catch_up_cell() {
        let (client, _) = pair();
        let (_frame_tx, frames) = mpsc::channel(4);
        let (_requests, opens) = mpsc::channel(4);
        let (writer, mut reader) = tokio::io::duplex(ONION_CELL_SIZE);
        let task = tokio::spawn(async move {
            let mut workers = JoinSet::new();
            run(
                writer,
                frames,
                client,
                Profile::Balanced,
                Some(opens),
                None,
                &mut workers,
            )
            .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(40)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(40)).await;
        tokio::task::yield_now().await;
        // The second write is blocked behind the unread first cell.
        tokio::time::advance(Duration::from_millis(200)).await;
        let mut wire = [0; ONION_CELL_SIZE];
        reader.read_exact(&mut wire).await.unwrap();
        tokio::task::yield_now().await;
        reader.read_exact(&mut wire).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(39), reader.read_exact(&mut wire))
                .await
                .is_err()
        );
        reader.read_exact(&mut wire).await.unwrap();
        task.abort();
        let _ = task.await;
    }

    #[tokio::test(start_paused = true)]
    async fn session_without_peer_finish_has_a_hard_lifetime() {
        let (_, exit) = pair();
        let (_sender, receiver) = mpsc::channel(4);
        let started = Instant::now();
        let result = run_exit(
            tokio::io::sink(),
            receiver,
            match exit {
                Crypto::Exit(hop) => hop,
                _ => unreachable!(),
            },
            Profile::Strict,
            ExitPolicy::new(false),
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("lifetime"));
        assert!(started.elapsed() <= LIFETIME);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_open_resets_one_stream_and_keeps_cover_alive() {
        let (client, mut peer) = pair();
        let (frame_tx, frames) = mpsc::channel(4);
        let (requests, opens) = mpsc::channel(4);
        let (writer, mut reader) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            let mut workers = JoinSet::new();
            run(
                writer,
                frames,
                client,
                Profile::Balanced,
                Some(opens),
                None,
                &mut workers,
            )
            .await
        });
        let (reply, result) = oneshot::channel();
        requests
            .send(Open {
                host: "8.8.8.8".into(),
                port: 443,
                reply,
            })
            .await
            .unwrap();
        let mut wire = [0; ONION_CELL_SIZE];
        reader.read_exact(&mut wire).await.unwrap();
        let cell = peer.incoming(&mut wire).unwrap();
        assert_eq!(cell.command, CellCommand::SessionOpen);
        drop(result);
        let mut reset = false;
        for _ in 0..8 {
            reader.read_exact(&mut wire).await.unwrap();
            let cell = peer.incoming(&mut wire).unwrap();
            if cell.command == CellCommand::SessionReset {
                reset = true;
                break;
            }
        }
        assert!(reset);
        // Already in-flight acceptance after reset must not terminate the owner.
        frame_tx
            .send(peer.outgoing(CellCommand::SessionOpened, 1, &[]).unwrap())
            .await
            .unwrap();
        for _ in 0..4 {
            reader.read_exact(&mut wire).await.unwrap();
            assert_eq!(
                peer.incoming(&mut wire).unwrap().command,
                CellCommand::Dummy
            );
        }
        assert!(!task.is_finished());
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn authenticated_noncanonical_destinations_refuse_before_connecting() {
        for target in [
            super::super::circuit::encode_relay_target("", 443).unwrap(),
            super::super::circuit::encode_relay_target("8.8.8.8", 0).unwrap(),
            {
                let mut target =
                    super::super::circuit::encode_relay_target("8.8.8.8", 443).unwrap();
                target.push(0);
                target
            },
        ] {
            let (mut client, exit) = pair();
            let (sender, frames) = mpsc::channel(4);
            sender
                .send(
                    client
                        .outgoing(CellCommand::SessionOpen, 1, &target)
                        .unwrap(),
                )
                .await
                .unwrap();
            let error = run_exit(
                tokio::io::sink(),
                frames,
                match exit {
                    Crypto::Exit(hop) => hop,
                    _ => unreachable!(),
                },
                Profile::Balanced,
                ExitPolicy::new(false),
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("Noncanonical"));
        }
    }

    #[tokio::test]
    async fn authenticated_unknown_stream_and_replay_close_session() {
        for replay in [false, true] {
            let (mut client, exit) = pair();
            let (tx, rx) = mpsc::channel(4);
            let wire = client
                .outgoing(
                    if replay {
                        CellCommand::Dummy
                    } else {
                        CellCommand::DataAck
                    },
                    if replay { 0 } else { 1 },
                    if replay { &[] } else { &[0, 0, 0, 1] },
                )
                .unwrap();
            tx.send(wire).await.unwrap();
            if replay {
                tx.send(wire).await.unwrap();
            }
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                run_exit(
                    tokio::io::sink(),
                    rx,
                    match exit {
                        Crypto::Exit(hop) => hop,
                        _ => unreachable!(),
                    },
                    Profile::Balanced,
                    ExitPolicy::new(false),
                ),
            )
            .await
            .unwrap();
            assert!(result.is_err());
        }
    }
    #[tokio::test(start_paused = true)]
    async fn flooding_authenticated_cover_exhausts_receive_budget() {
        let (mut client, exit) = pair();
        let (tx, rx) = mpsc::channel(600);
        for _ in 0..600 {
            tx.send(client.outgoing(CellCommand::Dummy, 0, &[]).unwrap())
                .await
                .unwrap();
        }
        drop(tx);
        let result = run_exit(
            tokio::io::sink(),
            rx,
            match exit {
                Crypto::Exit(hop) => hop,
                _ => unreachable!(),
            },
            Profile::Balanced,
            ExitPolicy::new(false),
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("rate budget"));
    }
}
