#!/usr/bin/env python3
"""Exploratory matching of client/guard and last-relay/exit-link capture windows.
Same-VM encrypted links only, not destination-side or global-adversary validation.
"""
import argparse,json,struct,socket,math,hashlib
from pathlib import Path
import numpy as np
from evaluate_traces import load
from event_order import chronological_events

def exit_events(path, expected_digest=None, with_order=False):
    data=path.read_bytes()
    if expected_digest is not None and hashlib.sha256(data).hexdigest()!=expected_digest:
        raise ValueError('Source PCAP digest does not match captured trace')
    if len(data)<24:raise ValueError('Truncated PCAP header')
    assert data[:4]==b'\xd4\xc3\xb2\xa1' and struct.unpack('<I',data[20:24])[0]==1
    offset=24;events=[]
    while offset<len(data):
        if len(data)-offset<16:raise ValueError('Truncated PCAP record header')
        sec,frac,size,_=struct.unpack('<IIII',data[offset:offset+16]);offset+=16
        if size>len(data)-offset:raise ValueError('Truncated PCAP packet')
        packet=data[offset:offset+size];offset+=size
        if len(packet)<54 or packet[12:14]!=b'\x08\x00':continue
        ip=packet[14:];ihl=(ip[0]&15)*4
        if ihl<20 or len(ip)<ihl+20 or ip[9]!=6:continue
        src=socket.inet_ntoa(ip[12:16]);dst=socket.inet_ntoa(ip[16:20]);tcp=ip[ihl:]
        payload=struct.unpack('!H',ip[2:4])[0]-ihl-((tcp[12]>>4)*4)
        if payload<=0:continue
        if dst=='127.3.0.1':direction=1
        elif src=='127.3.0.1':direction=-1
        else:continue
        events.append([sec+frac/1e6,direction,size])
    assert events,'Missing exit relay link capture'
    events,ordering=chronological_events(events)
    start=events[0][0];relative=[[t-start,d,n] for t,d,n in events]
    return (relative,ordering) if with_order else relative

def bins(events, window=20):
    if not math.isfinite(window) or not .1<=window<=120:
        raise ValueError('Correlation window must be finite and 0.1..120 seconds')
    count=math.ceil(window/.05)
    result=np.zeros((2,count))
    for t,d,n in events:
        # int() truncates toward zero: a small negative offset otherwise enters
        # bin zero and contaminates the aligned observation window.
        if not 0<=t<window:continue
        index=int(t/.05)
        if 0<=index<count:result[0 if d==1 else 1,index]+=n
    return result

def similarity(a,b):
    if a.shape!=b.shape or len(a.shape)!=2 or a.shape[0]!=2 or a.shape[1]<2:
        raise ValueError('Paired correlation arrays must have equal supported windows')
    count=a.shape[1]
    scores=[]
    lag=min(10,count-2)
    for shift in range(-lag,lag+1):
        left=a[:,max(shift,0):count+min(shift,0)].reshape(-1)
        right=b[:,max(-shift,0):count+min(-shift,0)].reshape(-1)
        if np.std(left)==0 or np.std(right)==0:scores.append(-1.)
        else:scores.append(float(np.corrcoef(left,right)[0,1]))
    return max(scores)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('dataset');p.add_argument('pcap_directory');p.add_argument('--output',required=True);args=p.parse_args()
    doc,digest=load(args.dataset);results={}
    if doc.get('complete') is False:raise ValueError('Incomplete capture must not be evaluated as a complete pilot')
    window=doc.get('fixed_observation_seconds')
    if window is None:window=20
    if type(window) not in (int,float) or not math.isfinite(window) or not .1<=window<=120:
        raise ValueError('Invalid declared correlation observation window')
    for profile in sorted({t['defense'] for t in doc['traces']}):
        traces=[t for t in doc['traces'] if t['defense']==profile and t['group']=='block-2']
        if not traces:raise ValueError('No held-out windows for '+profile)
        clients=[bins(t['events'],window) for t in traces]
        parsed_exits=[exit_events(Path(args.pcap_directory)/(t['id']+'.readable.pcap'),t.get('capture_sha256'),True) for t in traces]
        exit_traces=[events for events,_ in parsed_exits]
        exits=[bins(events,window) for events in exit_traces]
        matrix=[[similarity(client,exit_link) for exit_link in exits] for client in clients]
        correct=0;details=[]
        for i,row in enumerate(matrix):
            winner=int(np.argmax(row));correct+=winner==i
            details.append({'id':traces[i]['id'],'selected_exit_window':traces[winner]['id'],'paired_score':row[i],'best_score':row[winner]})
        results[profile]={'candidate_windows':len(traces),'correct_top1':correct,'top1_rate':correct/len(traces),
                          'random_candidate_chance':1/len(traces),
                          'tied_top_score_rows':sum(sum(abs(value-max(row))<1e-12 for value in row)>1 for row in matrix),
                          'client_events_outside_window':sum(e[0]>=window for t in traces for e in t['events']),
                          'exit_events_outside_window':sum(e[0]>=window for events in exit_traces for e in events),
                          'source_digest_verified_windows':sum('capture_sha256' in t for t in traces),
                          'exit_timestamp_ordering':[ordering for _,ordering in parsed_exits],
                          'details':details}
    report={'dataset_sha256':digest,'bin_ms':50,'maximum_shift_ms':min(10,math.ceil(window/.05)-2)*50,'maximum_window_seconds':window,
            'window_policy':'Use declared fixed observation duration; legacy variable-duration pilots retain a disclosed 20-second cap. No artificial extension of a declared shorter window.',
            'results':results,'scope':'Same-VM capture-window matching, client-to-guard versus last-relay-to-exit, held-out windows per profile. Repeated workloads and ongoing cover/session traffic affect attribution. Exploratory Pearson baseline; no external validation.',
            'alignment':'Each link is independently zeroed at first payload; absolute clock lag is discarded. Scores are exploratory.',
            'uncertainty':'Repeated sequential windows share workload and session state; top-1 matching is not an independent anonymity estimate.',
            'destination_side_correlation':'NOT EVALUATED','global_adversary_resistance':'NOT ESTABLISHED'}
    with open(args.output,'x') as f:json.dump(report,f,indent=2)
    for profile,result in results.items():print(profile,result['correct_top1'],'/',result['candidate_windows'])
if __name__=='__main__':main()
