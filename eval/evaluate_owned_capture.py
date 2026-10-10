#!/usr/bin/env python3
"""Small held-out owned-workload pilot using actual captured packets.
This is not Deep Fingerprinting, open-world testing or a production anonymity claim.
"""
import argparse, json, math
from collections import Counter
import numpy as np
from evaluate_traces import load, features, evaluate
from evaluate_classifier import SoftmaxNeuralClassifier

def wilson(correct,total):
    z=1.96;p=correct/total;den=1+z*z/total
    center=(p+z*z/(2*total))/den
    radius=z*math.sqrt(p*(1-p)/total+z*z/(4*total*total))/den
    return [center-radius,center+radius]

def label_control(predictions, truths, seed=731, repeats=1000):
    """Permutation diagnostic; preserves held-out class counts, not a security proof."""
    generator = np.random.default_rng(seed)
    predictions, truths = np.asarray(predictions), np.asarray(truths)
    observed = float(np.mean(predictions == truths))
    scores = [float(np.mean(predictions == generator.permutation(truths))) for _ in range(repeats)]
    return {'seed': seed, 'repeats': repeats, 'observed_accuracy': observed,
            'shuffled_label_mean_accuracy': float(np.mean(scores)),
            'permutation_tail_probability': (1 + sum(score >= observed for score in scores)) / (repeats + 1)}


def validate_split(train, test):
    if not train or not test:
        raise ValueError('Training and held-out samples are required')
    if {t['label'] for t in train} != {t['label'] for t in test}:
        raise ValueError('Closed-world pilot requires every class in both splits')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('dataset');parser.add_argument('--output',required=True)
    args=parser.parse_args();doc,digest=load(args.dataset)
    if doc.get('complete') is False:raise ValueError('Incomplete capture must not be evaluated as a complete pilot')
    report=evaluate(doc,{'block-2'})
    report['dataset_sha256']=digest;report['scope']='3 owned byte-size workloads, same VM, 3 sequential collection blocks, last block held out; no Tor baseline'
    report['capture_scope']=doc.get('scope','not recorded')
    report['fixed_observation_seconds']=doc.get('fixed_observation_seconds')
    for profile in sorted(report['results']):
        traces=[t for t in doc['traces'] if t['defense']==profile];labels=sorted({t['label'] for t in traces})
        train=[t for t in traces if t['group']!='block-2'];test=[t for t in traces if t['group']=='block-2']
        x=np.array([features(t) for t in train]);y=np.array([labels.index(t['label']) for t in train])
        validate_split(train,test)
        tx=np.array([features(t) for t in test]);ty=np.array([labels.index(t['label']) for t in test])
        seeds=[]
        for seed in (11,29,47):
            np.random.seed(seed);model=SoftmaxNeuralClassifier(x.shape[1],num_classes=len(labels),hidden_dim=32)
            model.fit(x,y,epochs=300,lr=.015);predictions,_=model.predict(tx)
            correct=int(np.sum(predictions==ty));matrix=np.zeros((len(labels),len(labels)),dtype=int)
            for truth,prediction in zip(ty,predictions):matrix[truth,prediction]+=1
            seeds.append({'seed':seed,'correct':correct,'test_count':len(test),'accuracy':correct/len(test),
                          'wilson_95_interval':wilson(correct,len(test)),'confusion_matrix':matrix.tolist(),
                          'label_permutation_control':label_control(predictions,ty,seed)})
        result=report['results'][profile];result['small_mlp']=seeds
        result['exploratory_feature_ablation']={}
        for name,columns in [('duration_only',[0]),('counts_and_bytes',[1,2,3,4]),('early_sequence',list(range(7,x.shape[1])))]:
            sx=x[:,columns];stx=tx[:,columns];mean=np.mean(sx,axis=0);scale=np.std(sx,axis=0);scale[scale==0]=1
            fitted=(sx-mean)/scale;queries=(stx-mean)/scale
            predictions=[y[int(np.argmin(np.sum((fitted-query)**2,axis=1)))] for query in queries]
            result['exploratory_feature_ablation'][name]=float(np.mean(np.array(predictions)==ty))
        correct=round(result['accuracy']*len(test));result['nearest_neighbor_wilson_95_interval']=wilson(correct,len(test))
        result['balanced_chance_accuracy']=1/len(labels)
        result['held_out_label_counts']=dict(Counter(t['label'] for t in test))
        result['majority_class_baseline']=max(Counter(t['label'] for t in test).values())/len(test)
        result['capture_window_accounting']={
            'wire_bytes_include': 'headers, retransmissions, other live contexts and idle cover during capture',
            'request_attributed_overhead': 'NOT ESTABLISHED; captured link bytes are not exclusively request bytes',
            'context_policy': 'strict reuses one context per block; earlier contexts may remain active',
            'captured_post_request_bytes': sum(t.get('capture_accounting',{}).get('post_request_wire_bytes',0) for t in test),
            'accounting_available_count': sum('capture_accounting' in t for t in test)}
    report['uncertainty']='Wilson intervals assume independent samples; sequential same-VM visits are dependent and these intervals do not capture deployment uncertainty. Seeds are not independent collections.'
    report['deep_learning_attacks']='Established Deep Fingerprinting NOT evaluated; small MLP pilot only'
    with open(args.output,'x') as output:json.dump(report,output,indent=2)
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
