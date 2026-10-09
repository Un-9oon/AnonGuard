#!/usr/bin/env python3
"""Defense-aware, group-held-out baseline. Input must already be observed/defended traces.

This lightweight 1-NN baseline does not establish resistance to deep fingerprinting.
No packet collection or traffic transformation is performed here.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics

MAX_TRACES = 10000
MAX_EVENTS = 20000


def load(path):
    data = Path(path).read_bytes()
    if len(data) > 64 * 1024 * 1024:
        raise ValueError('Dataset exceeds 64 MiB')
    doc = json.loads(data)
    if (not isinstance(doc, dict) or doc.get('version') != 1
            or doc.get('observation') not in ('packet', 'onion-cell', 'synthetic')
            or not isinstance(doc.get('traces'), list)
            or not 2 <= len(doc['traces']) <= MAX_TRACES):
        raise ValueError('Invalid dataset header')
    ids = set()
    for trace in doc['traces']:
        if not isinstance(trace, dict) or not all(isinstance(trace.get(k), str) and trace[k]
                                               for k in ('id', 'label', 'group', 'defense')):
            raise ValueError('Trace requires opaque id, label, group and defense')
        if trace['id'] in ids:
            raise ValueError('Duplicate trace id')
        ids.add(trace['id'])
        events = trace.get('events')
        if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
            raise ValueError('Invalid event count')
        previous = -1.0
        for event in events:
            if (not isinstance(event, list) or len(event) != 3
                    or type(event[0]) not in (int, float) or not math.isfinite(event[0])
                    or event[0] < previous or event[0] < 0
                    or type(event[1]) is not int or event[1] not in (-1, 1)
                    or type(event[2]) is not int or not 1 <= event[2] <= 65535):
                raise ValueError('Event must be [nondecreasing seconds, direction +/-1, bytes]')
            previous = event[0]
        for name in ('application_bytes', 'latency_ms'):
            value = trace.get(name)
            if value is not None and (type(value) not in (int, float) or not math.isfinite(value) or value < 0):
                raise ValueError('Invalid optional measurement')
    return doc, hashlib.sha256(data).hexdigest()


def features(trace):
    events = trace['events']
    duration = events[-1][0] - events[0][0]
    up = [e for e in events if e[1] == 1]
    down = [e for e in events if e[1] == -1]
    intervals = [b[0] - a[0] for a, b in zip(events, events[1:])]
    # Include early direction/size pattern, not merely the total duration.
    sequence = [e[1] * e[2] for e in events[:64]]
    return [duration, len(up), len(down), sum(e[2] for e in up), sum(e[2] for e in down),
            statistics.mean(intervals) if intervals else 0,
            statistics.pstdev(intervals) if intervals else 0] + sequence + [0] * (64 - len(sequence))


def evaluate(doc, test_groups):
    profiles = sorted({t['defense'] for t in doc['traces']})
    reports = {}
    for profile in profiles:
        traces = [t for t in doc['traces'] if t['defense'] == profile]
        train = [t for t in traces if t['group'] not in test_groups]
        test = [t for t in traces if t['group'] in test_groups]
        if not train or not test:
            raise ValueError('Each defense requires independent training and held-out traces')
        # Defense-aware fitting; scaling uses training samples only.
        vectors = [features(t) for t in train]
        means = [statistics.mean(column) for column in zip(*vectors)]
        scales = [statistics.pstdev(column) or 1 for column in zip(*vectors)]
        def normalized(vector):
            return [(x - m) / s for x, m, s in zip(vector, means, scales)]
        fitted = [normalized(v) for v in vectors]
        labels = sorted({t['label'] for t in traces})
        matrix = {label: {other: 0 for other in labels} for label in labels}
        for trace in test:
            vector = normalized(features(trace))
            winner = min(range(len(train)), key=lambda i: sum((a-b)**2 for a, b in zip(vector, fitted[i])))
            matrix[trace['label']][train[winner]['label']] += 1
        per_label = {}
        for label in labels:
            tp = matrix[label][label]
            fp = sum(matrix[other][label] for other in labels if other != label)
            fn = sum(matrix[label][other] for other in labels if other != label)
            tn = len(test) - tp - fp - fn
            per_label[label] = {'precision': tp / (tp + fp) if tp + fp else 0,
                                'recall': tp / (tp + fn) if tp + fn else 0,
                                'false_positive_rate': fp / (fp + tn) if fp + tn else None}
        wire = sum(e[2] for t in test for e in t['events'])
        measured = [t for t in test if t.get('application_bytes', 0) > 0]
        latencies = sorted(t['latency_ms'] for t in test if t.get('latency_ms') is not None)
        reports[profile] = {'train_count': len(train), 'test_count': len(test),
            'unseen_test_labels': sorted({t['label'] for t in test} - {t['label'] for t in train}),
            'accuracy': sum(matrix[label][label] for label in labels) / len(test),
            'confusion_matrix': matrix, 'per_label': per_label, 'wire_bytes': wire,
            'wire_to_application_ratio': (sum(e[2] for t in measured for e in t['events']) /
                sum(t['application_bytes'] for t in measured)) if measured else None,
            'p95_latency_ms': latencies[max(0, math.ceil(.95 * len(latencies)) - 1)] if latencies else None}
    return {'schema_version': 1, 'observation': doc['observation'],
            'attack': 'defense-aware training-only-scaled 1-nearest-neighbor',
            'test_groups': sorted(test_groups), 'results': reports,
            'flow_correlation': 'NOT EVALUATED',
            'deep_learning_attacks': 'NOT EVALUATED',
            'production_anonymity': 'NOT ESTABLISHED'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset', type=Path)
    parser.add_argument('--test-group', action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        doc, digest = load(args.dataset)
        groups = set(args.test_group)
        if not groups <= {t['group'] for t in doc['traces']}:
            raise ValueError('Unknown held-out group')
        report = evaluate(doc, groups)
        report['dataset_sha256'] = digest
        import os
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(report, stream, indent=2, allow_nan=False)
            stream.write('\n')
        return 0
    except (ValueError, OSError) as error:
        parser.exit(1, f'Evaluation refused: {error}\n')


if __name__ == '__main__':
    raise SystemExit(main())
