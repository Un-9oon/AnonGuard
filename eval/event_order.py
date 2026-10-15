"""Explicit bounded capture-timestamp ordering; original PCAPs remain authoritative."""
import math

MAX_BACKSTEP_SECONDS = .000002


def chronological_events(events):
    """Stable-sort only timestamp reorder within two microseconds; reject jumps.

    This is capture timestamp canonicalization, not TCP reassembly or a clock
    synchronization correction. Return a new list and explicit ordering evidence.
    """
    if not events:
        raise ValueError('Missing captured events')
    maximum = None
    backsteps = 0
    largest = 0.0
    for event in events:
        if not isinstance(event, (list, tuple)) or len(event) != 3:
            raise ValueError('Malformed capture event')
        timestamp = event[0]
        if type(timestamp) not in (int, float) or not math.isfinite(timestamp):
            raise ValueError('Invalid capture timestamp')
        if maximum is not None and timestamp < maximum:
            backwards = maximum-timestamp
            if backwards > MAX_BACKSTEP_SECONDS:
                raise ValueError('Capture clock backstep exceeds declared two-microsecond tolerance')
            backsteps += 1
            largest = max(largest, backwards)
        maximum = timestamp if maximum is None else max(maximum, timestamp)
    ordered = sorted((list(event) for event in events), key=lambda event: event[0])
    return ordered, {'policy': 'stable capture-timestamp order; original packet-file order retained in PCAP',
                     'backstep_events': backsteps, 'largest_backstep_seconds': largest,
                     'maximum_allowed_backstep_seconds': MAX_BACKSTEP_SECONDS,
                     'clock_synchronization': 'NOT ESTABLISHED'}


def main():
    """Create a provenance-linked derivative; never overwrite the raw dataset."""
    import argparse
    import hashlib
    import json
    import os
    from pathlib import Path
    import tempfile
    from evaluate_traces import load, MAX_TRACES, MAX_EVENTS
    parser = argparse.ArgumentParser(description=main.__doc__)
    parser.add_argument('dataset', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        with args.dataset.open('rb') as stream:
            raw = stream.read(64*1024*1024+1)
        if len(raw)>64*1024*1024:
            raise ValueError('Dataset exceeds 64 MiB')
        doc = json.loads(raw)
        if not isinstance(doc, dict) or doc.get('complete') is not True:
            raise ValueError('Explicit complete capture inventory required')
        traces = doc.get('traces')
        if not isinstance(traces, list) or not 2<=len(traces)<=MAX_TRACES:
            raise ValueError('Invalid trace inventory')
        changed = []
        for trace in traces:
            if not isinstance(trace, dict) or not isinstance(trace.get('events'), list) or not 1<=len(trace['events'])<=MAX_EVENTS:
                raise ValueError('Invalid captured event inventory')
            events, ordering = chronological_events(trace['events'])
            trace['events'], trace['event_ordering'] = events, ordering
            if ordering['backstep_events']:
                changed.append({'id': trace.get('id'), **ordering})
        doc['timestamp_canonicalization'] = {
            'source_dataset_sha256': hashlib.sha256(raw).hexdigest(),
            'source_file_modified': False, 'source_pcaps_modified': False,
            'source_pcap_hashes': 'retained, not independently reverified by this timestamp-only tool',
            'changed_traces': changed, 'maximum_allowed_backstep_seconds': MAX_BACKSTEP_SECONDS,
            'purpose': 'chronological capture timestamps, not attack-score optimization or clock synchronization'}
        encoded = json.dumps(doc, allow_nan=False, separators=(',', ':')).encode()+b'\n'
        # Validate the complete derived schema before publishing any output.
        with tempfile.TemporaryDirectory(prefix='ag-timestamp-check-') as directory:
            staged = Path(directory)/'derived.json'
            staged.write_bytes(encoded)
            staged.chmod(0o600)
            load(staged)
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(encoded)
        print(json.dumps({'traces': len(traces), 'changed_traces': len(changed),
                          'source_dataset_sha256': hashlib.sha256(raw).hexdigest()}))
    except (ValueError, OSError, TypeError) as error:
        parser.exit(1, f'Timestamp derivative refused: {error}\n')


if __name__ == '__main__':
    main()
