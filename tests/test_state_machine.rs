use anonguard::core::{
    ActiveGuarded, DroppedFailClosed, GuardedSocket, State, Uninitialized, Verifying,
};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn test_state_machine_transition_flow() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream
    });

    let client_stream = TcpStream::connect(addr).await.unwrap();
    let _server_stream = server_task.await.unwrap();

    let kill_switch = Arc::new(AtomicBool::new(false));

    // 1. Initial State: Uninitialized
    let socket: GuardedSocket<Uninitialized> = GuardedSocket::new(client_stream, kill_switch);
    assert_eq!(Uninitialized::name(), "UNINITIALIZED");

    // 2. Transition: Verifying
    let verifying_socket: GuardedSocket<Verifying> = socket.begin_verification();
    assert_eq!(Verifying::name(), "VERIFYING");

    // 3. Transition: ActiveGuarded
    let mut active_socket: GuardedSocket<ActiveGuarded> = verifying_socket.mark_verified();
    assert_eq!(ActiveGuarded::name(), "ACTIVE_GUARDED");

    // 4. Data send is permitted in ActiveGuarded
    let payload = b"PING";
    let sent = active_socket.send_guarded(payload).await;
    assert!(sent.is_ok());

    // 5. Trip kill switch
    let _dropped_socket: GuardedSocket<DroppedFailClosed> = active_socket.trip_kill_switch();
    assert_eq!(DroppedFailClosed::name(), "DROPPED_FAIL_CLOSED");
}

#[tokio::test]
async fn test_guarded_socket_async_read_write() {
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"HELLO");
        stream.write_all(b"WORLD").await.unwrap();
        stream
    });

    let client_stream = TcpStream::connect(addr).await.unwrap();
    let kill_switch = Arc::new(AtomicBool::new(false));

    let uninit = GuardedSocket::new(client_stream, kill_switch.clone());
    let verifying = uninit.begin_verification();
    let mut active = verifying.mark_verified();

    // Verify native AsyncWrite
    active.write_all(b"HELLO").await.unwrap();

    // Verify native AsyncRead
    let mut resp = [0u8; 5];
    active.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"WORLD");

    // Trip kill switch and verify subsequent writes fail immediately with ConnectionAborted
    kill_switch.store(true, Ordering::SeqCst);
    let fail_write = active.write_all(b"FAIL").await;
    assert!(fail_write.is_err());
    assert_eq!(
        fail_write.unwrap_err().kind(),
        std::io::ErrorKind::ConnectionAborted
    );

    let _ = server_task.await;
}
