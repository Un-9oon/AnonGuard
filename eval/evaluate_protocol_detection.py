#!/usr/bin/env python3
"""Shape-only binary protocol-detection baseline. Not a stealth/privacy certificate."""
import argparse
import json
import math
import os
import statistics
from evaluate_open_world import MAX_DISTANCE_PAIRS, wilson
from evaluate_traces import features, load

CLASSES = {'anonguard', 'reference'}


def validate(doc, splits, allow_synthetic):
    if doc.get('complete') is not True or not isinstance(doc.get('reference_population'), str) or not doc['reference_population'].strip():
        raise ValueError('Complete inventory and explicit normal-reference population required')
    if doc['observation'] != 'packet' and not (allow_synthetic and doc['observation'] == 'synthetic'):
        raise ValueError('Packet captures required; synthetic is testing-only opt-in')
    if any(not group for group in splits) or any(splits[i] & splits[j] for i in range(3) for j in range(i)):
        raise ValueError('Three nonempty disjoint collection partitions required')
    if set.union(*splits) != {t['group'] for t in doc['traces']}:
        raise ValueError('Every group must be explicitly assigned once')
    seen = {}
    for trace in doc['traces']:
        if trace.get('protocol_label') not in CLASSES:
            raise ValueError('Explicit anonguard/reference protocol_label required')
        digest = trace.get('capture_sha256')
        if digest is None and doc['observation'] == 'packet':
            raise ValueError('Source PCAP digest required')
        if digest is not None:
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                raise ValueError('Invalid source PCAP digest')
            partition = next(i for i, groups in enumerate(splits) if trace['group'] in groups)
            if digest in seen and (seen[digest][0] != partition or trace['defense'] in seen[digest][1]):
                raise ValueError('Duplicate source PCAP would leak or overweight evidence')
            if digest not in seen:
                seen[digest] = (partition, set())
            seen[digest][1].add(trace['defense'])


def fit(train):
    vectors = [features(trace) for trace in train]
    means = [statistics.mean(column) for column in zip(*vectors)]
    scales = [statistics.pstdev(column) or 1 for column in zip(*vectors)]
    if not all(math.isfinite(value) for value in means + scales):
        raise ValueError('Nonfinite training scale')
    normalized = [[(x-m)/s for x, m, s in zip(vector, means, scales)] for vector in vectors]
    def score(trace):
        query = [(x-m)/s for x, m, s in zip(features(trace), means, scales)]
        distances = {label: min(sum((x-y)**2 for x, y in zip(query, row))
                               for row, original in zip(normalized, train) if original['protocol_label'] == label)
                     for label in CLASSES}
        if not all(math.isfinite(distance) for distance in distances.values()):
            raise ValueError('Nonfinite detector distance')
        total = sum(distances.values())
        if not math.isfinite(total):
            raise ValueError('Nonfinite combined detector distance')
        return distances['reference']/total if total else .5
    return score


def counts(scored, threshold):
    positive = sum(label == 'anonguard' for label, _ in scored)
    negative = len(scored)-positive
    tp = sum(label == 'anonguard' and score >= threshold for label, score in scored)
    fp = sum(label == 'reference' and score >= threshold for label, score in scored)
    return {'positive_visits': positive, 'reference_visits': negative,
            'true_positive': tp, 'false_positive': fp, 'false_negative': positive-tp,
            'true_negative': negative-fp, 'sensitivity': tp/positive,
            'false_positive_rate': fp/negative,
            'precision': tp/(tp+fp) if tp+fp else None,
            'balanced_accuracy': ((tp/positive)+(1-fp/negative))/2,
            'sensitivity_wilson_95': wilson(tp, positive),
            'false_positive_wilson_95': wilson(fp, negative)}


def calibrate(scored, max_fpr):
    negatives = sum(label == 'reference' for label, _ in scored)
    ordered = sorted(scored, key=lambda item: item[1], reverse=True)
    tp = fp = best_tp = 0
    threshold = math.nextafter(1.0, math.inf)  # Explicit reject-all sentinel.
    index = 0
    while index < len(ordered):
        score = ordered[index][1]
        while index < len(ordered) and ordered[index][1] == score:
            tp += ordered[index][0] == 'anonguard'
            fp += ordered[index][0] == 'reference'
            index += 1
        if fp/negatives <= max_fpr and tp > best_tp:
            best_tp, threshold = tp, score
    return threshold


def ranking(scored):
    # Pairwise-equivalent AUROC with half credit for ties, without quadratic work.
    ordered = sorted(scored, key=lambda item: item[1])
    positives = sum(label == 'anonguard' for label, _ in ordered)
    negatives = len(ordered)-positives
    below = favorable = 0
    index = 0
    while index < len(ordered):
        score = ordered[index][1]
        p = n = 0
        while index < len(ordered) and ordered[index][1] == score:
            p += ordered[index][0] == 'anonguard'
            n += ordered[index][0] == 'reference'
            index += 1
        favorable += p*(below+.5*n)
        below += n
    return favorable/(positives*negatives)


def evaluate(doc, splits, max_fpr=.01, allow_synthetic=False):
    if not math.isfinite(max_fpr) or not 0 <= max_fpr < 1:
        raise ValueError('Finite validation FPR in [0,1) required')
    validate(doc, splits, allow_synthetic)
    results = {}
    for profile in sorted({t['defense'] for t in doc['traces']}):
        traces = [t for t in doc['traces'] if t['defense'] == profile]
        train, validation, test = ([t for t in traces if t['group'] in groups] for groups in splits)
        if any({t['protocol_label'] for t in partition} != CLASSES for partition in (train, validation, test)):
            raise ValueError('Every profile/partition needs both protocol classes')
        if len(train)*(len(validation)+len(test)) > MAX_DISTANCE_PAIRS:
            raise ValueError('Detector exceeds bounded distance-pair budget')
        score = fit(train)
        val = [(t['protocol_label'], score(t)) for t in validation]
        held = [(t['protocol_label'], score(t)) for t in test]
        threshold = calibrate(val, max_fpr)
        tested = counts(held, threshold)
        projected = {}
        for prior in (.5, .01, .001):
            denominator = prior*tested['sensitivity']+(1-prior)*tested['false_positive_rate']
            projected[str(prior)] = prior*tested['sensitivity']/denominator if denominator else None
        results[profile] = {'training_count': len(train), 'threshold': threshold,
            'reject_all_operating_point': threshold > 1, 'validation': counts(val, threshold),
            'held_out': tested, 'held_out_auroc': ranking(held),
            'projected_precision_by_anonguard_prevalence': projected,
            'always_reference_balanced_accuracy': .5,
            'train_test_workload_label_overlap': sorted({t['label'] for t in train} & {t['label'] for t in test}),
            'threshold_selected_on': 'validation only; held-out ROC is reporting, not tuning'}
    return {'schema_version': 1, 'observation': doc['observation'],
        'reference_population': doc['reference_population'], 'results': results,
        'attack': 'training-scaled nearest-class shape distance; score is not a probability',
        'split_groups': dict(zip(('train', 'validation', 'test'), map(sorted, splits))),
        'validation_max_fpr': max_fpr,
        'feature_scope': 'packet timing/directions/sizes only; no IP, TLS/ALPN, certificate or active-probing features',
        'limitations': 'No established deep detector or independent population claim; shape-only failure does not hide direct ALPN/known relay addresses. Wilson assumes independent visits; prevalence projections are point estimates.',
        'production_anonymity': 'NOT ESTABLISHED', 'protocol_indistinguishability': 'NOT ESTABLISHED'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset')
    for name in ('train', 'validation', 'test'):
        parser.add_argument('--'+name+'-group', action='append', required=True)
    parser.add_argument('--validation-max-fpr', type=float, default=.01)
    parser.add_argument('--allow-synthetic', action='store_true')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        doc, digest = load(args.dataset)
        splits = tuple(map(set, (args.train_group, args.validation_group, args.test_group)))
        report = evaluate(doc, splits, args.validation_max_fpr, args.allow_synthetic)
        report['dataset_sha256'] = digest
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(report, stream, indent=2, allow_nan=False)
            stream.write('\n')
    except (ValueError, OSError, OverflowError) as error:
        parser.exit(1, f'Detector evaluation refused: {error}\n')


if __name__ == '__main__':
    main()
