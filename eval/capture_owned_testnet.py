#!/usr/bin/env python3
"""Capture actual client-to-guard packets for owned lab workloads only.
Requires the opt-in Rust CLI testnet fixture and sudo -n tcpdump. Not a WF proof.
"""
import json, os, random, signal, socket, struct, subprocess, threading, time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SIZES = [8192, 32768, 65536]
def exact(s,n):
    data=b''
    while len(data)<n:
        part=s.recv(n-len(data))
        if not part:raise EOFError('Truncated SOCKS response')
        data+=part
    return data
class Pages(BaseHTTPRequestHandler):
    def do_GET(self):
        label=int(self.path.strip('/')); data=b'x'*SIZES[label]
        self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers()
        for offset in range(0,len(data),4096):
            self.wfile.write(data[offset:offset+4096]);self.wfile.flush();time.sleep(.015)
    def log_message(self,*args):pass

def fetch(gateway,port,context,label):
    with socket.create_connection(('127.0.0.1',gateway),timeout=15) as s:
        s.settimeout(20)
        if os.environ['ANONGUARD_TESTNET_PROFILE']=='strict':
            s.sendall(b'\x05\x01\x02');assert exact(s,2)==b'\x05\x02'
            user=context.encode(); password=b'lab';s.sendall(b'\x01'+bytes([len(user)])+user+bytes([len(password)])+password)
            assert exact(s,2)==b'\x01\x00'
        else:
            # Unpadded gateway supports NOAUTH, not session context labels.
            s.sendall(b'\x05\x01\x00');assert exact(s,2)==b'\x05\x00'
        s.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',port))
        head=exact(s,4);assert head[:2]==b'\x05\x00'
        if head[3]==1:exact(s,4)
        elif head[3]==3:exact(s,exact(s,1)[0])
        elif head[3]==4:exact(s,16)
        else:raise ValueError('Invalid address')
        exact(s,2);s.sendall(f'GET /{label} HTTP/1.0\r\nHost: owned.invalid\r\n\r\n'.encode());s.shutdown(socket.SHUT_WR)
        data=b''
        while True:
            chunk=s.recv(65536)
            if not chunk:break
            data+=chunk
        header,body=data.split(b'\r\n\r\n',1);assert b'200' in header.splitlines()[0] and len(body)==SIZES[label]

def parse_pcap(path,flows):
    data=path.read_bytes();magic=data[:4]
    if magic==b'\xd4\xc3\xb2\xa1':endian='<';scale=1e6
    elif magic==b'\xa1\xb2\xc3\xd4':endian='>';scale=1e6
    else:raise ValueError('Unsupported PCAP magic')
    link=struct.unpack(endian+'I',data[20:24])[0];assert link==1,link
    result=[];offset=24
    while offset<len(data):
        sec,frac,size,_=struct.unpack(endian+'IIII',data[offset:offset+16]);offset+=16
        packet=data[offset:offset+size];offset+=size
        if len(packet)<54 or packet[12:14]!=b'\x08\x00':continue
        ip=packet[14:];ihl=(ip[0]&15)*4
        if ip[9]!=6:continue
        src=socket.inet_ntoa(ip[12:16]);dst=socket.inet_ntoa(ip[16:20]);tcp=ip[ihl:]
        sport,dport=struct.unpack('!HH',tcp[:4]);total=struct.unpack('!H',ip[2:4])[0]
        payload=total-ihl-((tcp[12]>>4)*4)
        if payload<=0:continue
        forward=(src,sport,dst,dport);reverse=(dst,dport,src,sport)
        if forward in flows:direction=1
        elif reverse in flows:direction=-1
        else:continue
        result.append([sec+frac/scale,direction,size])
    assert result,'No client-to-guard payload captured'
    start=result[0][0];return [[round(t-start,6),d,n] for t,d,n in result]

def main():
    gateway=int(os.environ['ANONGUARD_TESTNET_GATEWAY_PORT']);pid=int(os.environ['ANONGUARD_TESTNET_GATEWAY_PID'])
    relays=set(os.environ['ANONGUARD_TESTNET_RELAYS'].split(','));profile=os.environ['ANONGUARD_TESTNET_PROFILE']
    output=Path(os.environ['ANONGUARD_TRAFFIC_EVAL']);output.mkdir(parents=True,exist_ok=True)
    assert profile in ('strict','unpadded') and gateway>1024
    server=ThreadingHTTPServer(('127.0.0.1',0),Pages);server.daemon_threads=True
    threading.Thread(target=server.serve_forever,daemon=True).start()
    traces=[];rng=random.Random(731)
    try:
        for group in range(3):
            context=f'owned-{profile}-{group}'
            order=[label for label in range(3) for _ in range(4)];rng.shuffle(order)
            for index,label in enumerate(order):
                trace_id=f'{profile}-g{group}-n{index}';pcap=output/(trace_id+'.pcap');log=output/(trace_id+'.capture.log')
                flows=set();stop=threading.Event()
                def observe():
                    while not stop.is_set():
                        text=subprocess.check_output(['ss','-tnpH'],text=True,timeout=3)
                        for line in text.splitlines():
                            fields=line.split()
                            if f'pid={pid},' not in line or len(fields)<5 or fields[4] not in relays:continue
                            local,peer=fields[3:5];sip,sport=local.rsplit(':',1);dip,dport=peer.rsplit(':',1)
                            flows.add((sip,int(sport),dip,int(dport)))
                        stop.wait(.01)
                worker=threading.Thread(target=observe,daemon=True);worker.start()
                expression='tcp and ('+' or '.join('port '+r.rsplit(':',1)[1] for r in sorted(relays))+')'
                with log.open('wb') as error:
                    capture=subprocess.Popen(['sudo','-n','tcpdump','-i','lo','-U','-s','0','-w',str(pcap),expression],stdout=subprocess.DEVNULL,stderr=error)
                    try:
                        time.sleep(.15);assert capture.poll() is None,'Capture failed'
                        started=time.monotonic();fetch(gateway,server.server_port,context,label);latency=(time.monotonic()-started)*1000
                        time.sleep(1)
                    finally:
                        subprocess.run(['sudo','-n','kill','-INT',str(capture.pid)],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                        capture.wait(timeout=5);stop.set();worker.join(timeout=2)
                # tcpdump drops privileges to its service account; read through
                # sudo rather than granting global filesystem permissions.
                raw=subprocess.check_output(['sudo','-n','cat',str(pcap)])
                readable=output/(trace_id+'.readable.pcap');readable.write_bytes(raw)
                subprocess.run(['sudo','-n','rm','--',str(pcap)],check=True)
                capture_log=log.read_text()
                assert '0 packets dropped by kernel' in capture_log,'Capture loss invalidates this sample'
                events=parse_pcap(readable,flows)
                traces.append({'id':trace_id,'label':f'owned-size-{label}','group':f'block-{group}','defense':profile,
                    'events':events,'application_bytes':SIZES[label],'latency_ms':latency})
                (output/(profile+'.partial.json')).write_text(json.dumps({'version':1,'observation':'packet','complete':False,'traces':traces}))
                print(json.dumps({'trace':trace_id,'events':len(events),'latency_ms':round(latency,2)}),flush=True)
        document={'version':1,'observation':'packet','traces':traces,'scope':'owned loopback CLI testnet; application lifetime plus 1s; same VM; TCP payload frames include retransmissions and headers'}
        (output/(profile+'.json')).write_text(json.dumps(document))
    finally:server.shutdown();server.server_close()
if __name__=='__main__':main()
