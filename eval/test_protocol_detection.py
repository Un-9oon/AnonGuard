"""Synthetic binary-detector integrity tests; no product resistance result."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from evaluate_protocol_detection import calibrate, evaluate, ranking


def fixture():
    traces = []
    for group, offset in (('train', 0), ('validation', .01), ('test', .02)):
        for protocol, duration in (('anonguard', 1), ('reference', 10)):
            traces.append({'id': group+'-'+protocol, 'group': group, 'label': 'workload-'+group,
                'defense': 'strict', 'protocol_label': protocol,
                'events': [[0, 1, 100], [duration+offset, -1, 100]]})
    return {'version': 1, 'complete': True, 'observation': 'synthetic',
            'reference_population': 'synthetic unit fixture, not real traffic', 'traces': traces}


def run(doc):
    return evaluate(doc, ({'train'}, {'validation'}, {'test'}), allow_synthetic=True)


class ProtocolDetectionTests(unittest.TestCase):
    def test_threshold_is_frozen_before_held_out_and_task_is_explicit(self):
        doc = fixture()
        first = run(doc)
        doc['traces'][-1]['events'][-1][0] = 1.01
        second = run(doc)
        a, b = (report['results']['strict'] for report in (first, second))
        self.assertEqual(a['threshold'], b['threshold'])
        self.assertEqual(a['validation'], b['validation'])
        self.assertGreater(b['held_out']['false_positive_rate'], a['held_out']['false_positive_rate'])
        self.assertEqual(second['protocol_indistinguishability'], 'NOT ESTABLISHED')
        self.assertIn('no IP', second['feature_scope'])
        self.assertEqual(a['train_test_workload_label_overlap'], [])

    def test_ranking_ties_perfect_and_reversed(self):
        self.assertEqual(ranking([('anonguard', .5), ('reference', .5)]), .5)
        self.assertEqual(ranking([('anonguard', 1), ('reference', 0)]), 1)
        self.assertEqual(ranking([('anonguard', 0), ('reference', 1)]), 0)
        self.assertEqual(calibrate([('anonguard', .5), ('reference', .5)], 0),
                         __import__('math').nextafter(1, __import__('math').inf))

    def test_incomplete_unknown_protocol_and_undefined_reference_refuse(self):
        for name, value in (('complete', False), ('reference_population', ''), ('observation', 'packet')):
            doc = fixture()
            doc[name] = value
            with self.assertRaises(ValueError):run(doc)
        doc = fixture()
        doc['traces'][0]['protocol_label'] = 'guess'
        with self.assertRaises(ValueError):run(doc)
        with self.assertRaises(ValueError):evaluate(fixture(), ({'train'}, {'validation'}, {'test'}))

    def test_every_partition_needs_both_classes_and_no_group_overlap(self):
        doc = fixture()
        doc['traces'].pop()
        with self.assertRaises(ValueError):run(doc)
        with self.assertRaises(ValueError):
            evaluate(fixture(), ({'train'}, {'train', 'validation'}, {'test'}), allow_synthetic=True)

    def test_packet_digests_prevent_reused_visits_or_cross_split_leakage(self):
        doc = fixture()
        doc['observation'] = 'packet'
        for trace in doc['traces']:
            trace['capture_sha256'] = hashlib.sha256(trace['id'].encode()).hexdigest()
        run(doc)
        duplicate = copy.deepcopy(doc['traces'][0])
        duplicate['id'] = 'copied-visit'
        doc['traces'].append(duplicate)
        with self.assertRaises(ValueError):run(doc)
        doc['traces'].pop()
        doc['traces'][-1]['capture_sha256'] = doc['traces'][0]['capture_sha256']
        with self.assertRaises(ValueError):run(doc)

    def test_cli_output_is_private_exclusive_and_provenance_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, output = Path(temporary)/'data.json', Path(temporary)/'report.json'
            source.write_text(json.dumps(fixture()))
            command = [sys.executable, str(Path(__file__).with_name('evaluate_protocol_detection.py')),
                str(source), '--train-group', 'train', '--validation-group', 'validation',
                '--test-group', 'test', '--allow-synthetic', '--output', str(output)]
            first = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            before = output.read_bytes()
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(before)['dataset_sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(before, output.read_bytes())


if __name__ == '__main__':unittest.main()
