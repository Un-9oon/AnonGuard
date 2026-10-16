#!/usr/bin/env python3
"""Defense-aware RF/SVM packet-shape baselines, not a published deep-attack replica."""
import argparse
import json
import math
import os
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from evaluate_traces import load, features
from evaluate_protocol_detection import validate as validate_protocol, calibrate, counts, ranking
from evaluate_open_world import wilson
from collections import Counter

MAX_TRACES = 2048

def vector(trace, window):
    events = trace['events']
    if events[-1][0] > 3600:
        raise ValueError('Advanced baseline trace exceeds one-hour measurement bound')
    base = features(trace)
    bursts = []
    direction = events[0][1]
    total = 0
    for _, d, n in events:
        if d != direction:
            bursts.append(direction*total)
            total = 0
            direction = d
        total += n
    bursts.append(direction*total)
    bins = np.zeros((2, 32))
    for t, d, n in events:
        if 0 <= t < window:
            bins[0 if d == 1 else 1, min(31, int(t/window*32))] += n
    result = base + bursts[:64] + [0]*(64-min(64, len(bursts))) + bins.ravel().tolist()
    if not all(math.isfinite(x) for x in result):
        raise ValueError('Nonfinite attack features')
    return result

def validate(doc, splits, allow_synthetic, task):
    if doc.get('complete') is not True or len(doc['traces']) > MAX_TRACES:
        raise ValueError('Complete capture inventory <=2048 traces required')
    if doc['observation'] != 'packet' and not (allow_synthetic and doc['observation'] == 'synthetic'):
        raise ValueError('Actual packet observations required')
    if any(not g for g in splits) or any(splits[i]&splits[j] for i in range(3) for j in range(i)):
        raise ValueError('Three disjoint nonempty groups required')
    if set.union(*splits) != {t['group'] for t in doc['traces']}:
        raise ValueError('All groups must be assigned exactly once')
    digests = set()
    for t in doc['traces']:
        digest = t.get('capture_sha256')
        if doc['observation'] == 'packet' or digest is not None:
            if not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest) or digest in digests:
                raise ValueError('Unique valid source-PCAP hashes required')
            digests.add(digest)
    if task == 'protocol':
        validate_protocol(doc, splits, allow_synthetic)


def evaluate(doc, splits, task='protocol', allow_synthetic=False, window=10):
    if task not in ('protocol','website') or not math.isfinite(window) or not .1 <= window <= 120:
        raise ValueError('Invalid task or common feature window')
    validate(doc,splits,allow_synthetic,task)
    results = {}
    for profile in sorted({t['defense'] for t in doc['traces']}):
        traces=[t for t in doc['traces'] if t['defense']==profile]
        if task == 'website':
            traces=[t for t in traces if t.get('protocol_label','anonguard')=='anonguard']
        parts=[[t for t in traces if t['group'] in g] for g in splits]
        labels=[['anonguard' if t['protocol_label']=='anonguard' else 'reference' for t in p] if task=='protocol' else [t['label'] for t in p] for p in parts]
        if any(not p for p in parts) or not 2<=len(set(labels[0]))<=128 or any(set(y)!=set(labels[0]) for y in labels[1:]):
            raise ValueError('Every profile/partition needs the same >=2 target classes')
        arrays=[np.asarray([vector(t,window) for t in p],dtype=float) for p in parts]
        mean=arrays[0].mean(axis=0);scale=arrays[0].std(axis=0);scale[scale==0]=1
        arrays=[(x-mean)/scale for x in arrays]
        output=[]
        for name,seed in [('random-forest',11),('random-forest',29),('random-forest',47),('rbf-svm',11)]:
            model=RandomForestClassifier(n_estimators=128,max_depth=12,random_state=seed,n_jobs=1) if name=='random-forest' else SVC(C=1,kernel='rbf',gamma='scale')
            model.fit(arrays[0],labels[0]);entry={'model':name,'seed':seed,'train_count':len(parts[0]),'validation_count':len(parts[1]),'held_out_count':len(parts[2])}
            if task=='protocol':
                def score(x):
                    if name=='random-forest':return model.predict_proba(x)[:,list(model.classes_).index('anonguard')]
                    # SVC's positive margin refers to classes_[1]. Keep the
                    # class orientation explicit; sigmoid is NOT a posterior.
                    margin=model.decision_function(x)
                    if model.classes_[1]!='anonguard':margin=-margin
                    return 1/(1+np.exp(-np.clip(margin,-60,60)))
                validation=list(zip(labels[1],map(float,score(arrays[1]))));held=list(zip(labels[2],map(float,score(arrays[2]))));threshold=calibrate(validation,.01)
                entry.update(threshold=threshold,validation=counts(validation,threshold),held_out=counts(held,threshold),held_out_auroc=ranking(held))
                entry['low_fpr_evidence']='INSUFFICIENT' if entry['held_out']['false_positive_wilson_95'][1]>.01 else 'upper Wilson bound <=1%; attack/dataset-specific only'
            else:
                predictions=model.predict(arrays[2]);classes=sorted(set(labels[0]));matrix={a:{b:0 for b in classes} for a in classes}
                for a,b in zip(labels[2],predictions):matrix[a][b]+=1
                correct=int(np.sum(predictions==labels[2])); histogram=Counter(labels[2])
                entry.update(held_out_accuracy=correct/len(parts[2]),held_out_correct=correct,accuracy_wilson_95=wilson(correct,len(parts[2])),confusion_matrix=matrix,balanced_class_chance=1/len(classes),majority_class_baseline=max(histogram.values())/len(parts[2]),held_out_class_counts=dict(histogram))
            output.append(entry)
        results[profile]=output
    return {'task':task,'results':results,'sklearn_version':sklearn.__version__,'feature_window_seconds':window,
        'features':'training-only-scaled aggregate timing/bytes, first 64 signed packet sizes, first 64 signed burst bytes, 32 fixed time bins per direction',
        'split_groups':dict(zip(('train','validation','test'),map(sorted,splits))),
        'model_selection':'fixed models/hyperparameters; no held-out tuning; protocol thresholds selected on validation only',
        'limitations':'Custom RF/SVM baselines, not DF/Tik-Tok/RF paper replications. Website task is closed world. No metadata/ALPN/active probing. Sequential visits and seeds are not independent populations. Tiny data cannot establish low false-positive rates.',
        'production_anonymity':'NOT ESTABLISHED','ai_undetectability':'NOT ESTABLISHED'}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('dataset');p.add_argument('--task',choices=['protocol','website'],required=True)
    for name in ('train','validation','test'):p.add_argument('--'+name+'-group',action='append',required=True)
    p.add_argument('--feature-window',type=float,default=10);p.add_argument('--allow-synthetic',action='store_true');p.add_argument('--output',required=True)
    a=p.parse_args()
    try:
        doc,digest=load(a.dataset);report=evaluate(doc,tuple(map(set,[a.train_group,a.validation_group,a.test_group])),a.task,a.allow_synthetic,a.feature_window);report['dataset_sha256']=digest
        fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:json.dump(report,f,indent=2,allow_nan=False)
    except (ValueError,OSError,OverflowError) as e:p.exit(1,f'Adaptive evaluation refused: {e}\n')
if __name__=='__main__':main()
