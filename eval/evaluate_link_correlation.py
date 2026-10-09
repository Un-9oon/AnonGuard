#!/usr/bin/env python3
"""Exploratory matching of client/guard and last-relay/exit-link capture windows.
Same-VM encrypted links only, not destination-side or global-adversary validation.
"""
import argparse,json,struct,socket
from pathlib import Path
import numpy as np
from evaluate_traces import load

def exit_events(path):
    data=path.read_bytes();assert data[:4]==b'\xd4\xc3\xb2\xa1' and struct.unpack('<I',data[20:24])[0]==1
    offset=24;events=[]
    while offset<len(data):
        sec,frac,size,_=struct.unpack('<IIII',data[offset:offset+16]);offset+=16
        packet=data[offset:offset+size];offset+=size
        if len(packet)<54 or packet[12:14]!=b'\x08\x00':continue
        ip=packet[14:];ihl=(ip[0]&15)*4
        if ip[9]!=6:continue
        src=socket.inet_ntoa(ip[12:16]);dst=socket.inet_ntoa(ip[16:20]);tcp=ip[ihl:]
        payload=struct.unpack('!H',ip[2:4])[0]-ihl-((tcp[12]>>4)*4)
        if payload<=0:continue
        if dst=='127.3.0.1':direction=1
        elif src=='127.3.0.1':direction=-1
        else:continue
        events.append([sec+frac/1e6,direction,size])
    assert events,'Missing exit relay link capture'
    start=events[0][0];return [[t-start,d,n] for t,d,n in events]

def bins(events):
    result=np.zeros((2,400))
    for t,d,n in events:
        index=int(t/.05)
        if index<400:result[0 if d==1 else 1,index]+=n
    return result

def similarity(a,b):
    scores=[]
    for shift in range(-10,11):
        left=a[:,max(shift,0):400+min(shift,0)].reshape(-1)
        right=b[:,max(-shift,0):400+min(-shift,0)].reshape(-1)
        if np.std(left)==0 or np.std(right)==0:scores.append(-1.)
        else:scores.append(float(np.corrcoef(left,right)[0,1]))
    return max(scores)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('dataset');p.add_argument('pcap_directory');p.add_argument('--output',required=True);args=p.parse_args()
    doc,digest=load(args.dataset);results={}
    for profile in sorted({t['defense'] for t in doc['traces']}):
        traces=[t for t in doc['traces'] if t['defense']==profile and t['group']=='block-2']
        clients=[bins(t['events']) for t in traces]
        exits=[bins(exit_events(Path(args.pcap_directory)/(t['id']+'.readable.pcap'))) for t in traces]
        matrix=[[similarity(client,exit_link) for exit_link in exits] for client in clients]
        correct=0;details=[]
        for i,row in enumerate(matrix):
            winner=int(np.argmax(row));correct+=winner==i
            details.append({'id':traces[i]['id'],'selected_exit_window':traces[winner]['id'],'paired_score':row[i],'best_score':row[winner]})
        results[profile]={'candidate_windows':len(traces),'correct_top1':correct,'top1_rate':correct/len(traces),
                          'random_candidate_chance':1/len(traces),'details':details}
    report={'dataset_sha256':digest,'bin_ms':50,'maximum_shift_ms':500,'maximum_window_seconds':20,
            'results':results,'scope':'Same-VM capture-window matching, client-to-guard versus last-relay-to-exit, 12 held-out windows per profile. Repeated workloads and ongoing cover/session traffic affect attribution. Exploratory Pearson baseline selected after collection; no external validation.',
            'destination_side_correlation':'NOT EVALUATED','global_adversary_resistance':'NOT ESTABLISHED'}
    with open(args.output,'x') as f:json.dump(report,f,indent=2)
    for profile,result in results.items():print(profile,result['correct_top1'],'/',result['candidate_windows'])
if __name__=='__main__':main()
