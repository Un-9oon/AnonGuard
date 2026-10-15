#!/usr/bin/env python3
"""Validation-calibrated open-world WF baseline; never an anonymity certificate."""
import argparse
import hashlib
import json
import math
import os
import statistics
from evaluate_traces import features, load

MAX_DISTANCE_PAIRS = 1_000_000


def wilson(successes, total):
    if not total:
        return None
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z*z/total
    center = (p + z*z/(2*total)) / denominator
    radius = z*math.sqrt(p*(1-p)/total + z*z/(4*total*total)) / denominator
    return [max(0, center-radius), min(1, center+radius)]


def metrics(scored, threshold, monitored):
    positive = [s for s in scored if s[0] in monitored]
    negative = [s for s in scored if s[0] not in monitored]
    correct = sum(pred == truth and distance <= threshold for truth, pred, distance in positive)
    wrong = sum(pred is not None and pred != truth and distance <= threshold for truth, pred, distance in positive)
    false = sum(pred is not None and distance <= threshold for _, pred, distance in negative)
    alarms = correct + wrong + false
    return {'monitored_count': len(positive), 'background_count': len(negative),
            'correct_monitored': correct, 'wrong_monitored_label': wrong,
            'background_false_alarms': false,
            'correct_identification_rate': correct/len(positive),
            'background_false_positive_rate': false/len(negative),
            'correct_alarm_precision': correct/alarms if alarms else None,
            'identification_wilson_95': wilson(correct, len(positive)),
            'false_positive_wilson_95': wilson(false, len(negative))}


def fit(train):
    vectors = [features(t) for t in train]
    means = [statistics.mean(column) for column in zip(*vectors)]
    scales = [statistics.pstdev(column) or 1 for column in zip(*vectors)]
    if not all(math.isfinite(v) for v in means + scales):
        raise ValueError('Nonfinite feature scaling')
    normalized = [[(v-m)/s for v, m, s in zip(row, means, scales)] for row in vectors]
    def score(trace):
        query = [(v-m)/s for v, m, s in zip(features(trace), means, scales)]
        distances = [sum((a-b)**2 for a, b in zip(query, row)) for row in normalized]
        if not all(math.isfinite(d) for d in distances):
            raise ValueError('Nonfinite attack distance')
        nearest = min(distances)
        winners = {train[i]['label'] for i, distance in enumerate(distances) if distance == nearest}
        # Equally close different labels are ambiguous, not a training-order win.
        return trace['label'], next(iter(winners)) if len(winners) == 1 else None, nearest
    return score


def calibrate(scored, monitored, max_fpr):
    # Sweep validation distances once; equal-distance groups move together.
    negatives = sum(truth not in monitored for truth, _, _ in scored)
    correct = false = 0
    best = (0, -1.0)
    ordered = sorted(scored, key=lambda item: item[2])
    index = 0
    while index < len(ordered):
        distance = ordered[index][2]
        while index < len(ordered) and ordered[index][2] == distance:
            truth, pred, _ = ordered[index]
            correct += pred == truth and truth in monitored
            false += pred is not None and truth not in monitored
            index += 1
        if false / negatives <= max_fpr and correct > best[0]:
            best = correct, distance
    return best[1]


def evaluate(doc, monitored, train_groups, validation_groups, test_groups, max_fpr=.01, allow_synthetic=False):
    if doc.get('complete') is not True:
        raise ValueError('Explicit complete=true capture inventory required')
    if doc['observation'] != 'packet' and not (allow_synthetic and doc['observation'] == 'synthetic'):
        raise ValueError('Packet captures required; synthetic is test-only opt-in')
    if not monitored or not math.isfinite(max_fpr) or not 0 <= max_fpr < 1:
        raise ValueError('Monitored labels and finite validation FPR in [0,1) required')
    splits = (set(train_groups), set(validation_groups), set(test_groups))
    if any(not group for group in splits) or any(splits[i] & splits[j] for i in range(3) for j in range(i)):
        raise ValueError('Three nonempty disjoint collection-group splits required')
    if set.union(*splits) != {t['group'] for t in doc['traces']}:
        raise ValueError('Every collection group must be explicitly assigned once')
    hashes = {}
    profile_captures = set()
    for trace in doc['traces']:
        digest = trace.get('capture_sha256')
        if digest is None and doc['observation'] == 'packet':
            raise ValueError('Packet trace requires source-PCAP capture_sha256')
        if digest is not None:
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                raise ValueError('Invalid source capture digest')
            partition = next(i for i, groups in enumerate(splits) if trace['group'] in groups)
            if digest in hashes and hashes[digest] != partition:
                raise ValueError('Source PCAP reused across evaluation splits')
            identity = trace['defense'], digest
            if identity in profile_captures:
                raise ValueError('Each profile requires one source PCAP per visit; duplicate capture would overweight evidence')
            profile_captures.add(identity)
            hashes[digest] = partition
    results = {}
    for profile in sorted({t['defense'] for t in doc['traces']}):
        traces = [t for t in doc['traces'] if t['defense'] == profile]
        train, validation, test = ([t for t in traces if t['group'] in groups] for groups in splits)
        if not train or {t['label'] for t in train} != monitored:
            raise ValueError('Training must contain every monitored label and no background labels')
        for partition in (validation, test):
            labels = {t['label'] for t in partition}
            if not monitored <= labels or not labels - monitored:
                raise ValueError('Validation/test each need every monitored label and background visits')
        if ({t['label'] for t in validation} - monitored) & ({t['label'] for t in test} - monitored):
            raise ValueError('Validation and test background sites must be disjoint')
        if len(train) * (len(validation) + len(test)) > MAX_DISTANCE_PAIRS:
            raise ValueError('Baseline exceeds one million distance pairs; use a separately validated scalable attack')
        score = fit(train)
        scored_validation = [score(t) for t in validation]
        threshold = calibrate(scored_validation, monitored, max_fpr)
        tested = metrics([score(t) for t in test], threshold, monitored)
        validation_metrics = metrics(scored_validation, threshold, monitored)
        tp = tested['correct_identification_rate']
        wrong = tested['wrong_monitored_label']/tested['monitored_count']
        fp = tested['background_false_positive_rate']
        projected = {}
        for prior in (.5, .01, .001):
            denominator = prior*(tp+wrong) + (1-prior)*fp
            projected[str(prior)] = prior*tp/denominator if denominator else None
        event_splits = {}
        for index, partition in enumerate((train, validation, test)):
            for trace in partition:
                shape = hashlib.sha256(json.dumps(trace['events'], separators=(',', ':')).encode()).hexdigest()
                event_splits.setdefault(shape, set()).add(index)
        results[profile] = {'training_count': len(train), 'validation_count': len(validation),
            'test_count': len(test), 'squared_distance_threshold': threshold,
            'reject_all_operating_point': threshold < 0, 'validation': validation_metrics,
            'held_out': tested, 'projected_precision_by_monitored_visit_prior': projected,
            'identical_event_shapes_across_splits': sum(len(groups)>1 for groups in event_splits.values()),
            'independence': 'Group labels/digests cannot prove independent devices or collection; identical shapes are reported, not automatically treated as copied captures.'}
    return {'schema_version': 1, 'observation': doc['observation'], 'results': results,
            'attack': 'defense-aware training-scaled 1-NN with ambiguous-label abstention',
            'distance_pair_limit_per_profile': MAX_DISTANCE_PAIRS,
            'threshold_policy': 'Maximize correct identification subject to empirical validation FPR; never fitted on held-out data',
            'validation_max_fpr': max_fpr, 'monitored_labels': sorted(monitored),
            'split_groups': dict(zip(('train', 'validation', 'test'), map(sorted, splits))),
            'uncertainty': 'Wilson intervals assume independent visits; zero observed false alarms does not establish zero FPR. Base-rate projections use point estimates, not guarantees.',
            'deep_learning_attacks': 'NOT EVALUATED', 'flow_correlation': 'NOT EVALUATED',
            'production_anonymity': 'NOT ESTABLISHED'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset')
    parser.add_argument('--monitored-label', action='append', required=True)
    for name in ('train', 'validation', 'test'):
        parser.add_argument('--'+name+'-group', action='append', required=True)
    parser.add_argument('--validation-max-fpr', type=float, default=.01)
    parser.add_argument('--allow-synthetic', action='store_true')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        doc, digest = load(args.dataset)
        report = evaluate(doc, set(args.monitored_label), args.train_group, args.validation_group,
                          args.test_group, args.validation_max_fpr, args.allow_synthetic)
        report['dataset_sha256'] = digest
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(report, stream, indent=2, allow_nan=False)
            stream.write('\n')
    except (ValueError, OSError, OverflowError) as error:
        parser.exit(1, f'Evaluation refused: {error}\n')


if __name__ == '__main__':
    main()
