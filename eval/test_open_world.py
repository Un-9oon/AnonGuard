"""Synthetic evaluator-integrity tests; no measured anonymity results."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from evaluate_open_world import evaluate, metrics, wilson


def fixture():
    traces = []
    for group, entries in (
        ('train', [('a', 1), ('b', 10)]),
        ('validation', [('a', 1.1), ('b', 10.1), ('background-v', 100)]),
        ('test', [('a', 1.2), ('b', 10.2), ('background-t', 200)]),
    ):
        for label, duration in entries:
            traces.append({'id': group+'-'+label, 'label': label, 'group': group,
                           'defense': 'strict', 'events': [[0, 1, 100], [duration, -1, 100]]})
    return {'version': 1, 'complete': True, 'observation': 'synthetic', 'traces': traces}


def run(doc):
    return evaluate(doc, {'a', 'b'}, {'train'}, {'validation'}, {'test'}, allow_synthetic=True)


class OpenWorldTests(unittest.TestCase):
    def test_held_out_data_cannot_tune_threshold_or_scaling(self):
        doc = fixture()
        first = run(doc)['results']['strict']
        doc['traces'][-1]['events'][-1][0] = 1.1
        second = run(doc)['results']['strict']
        self.assertEqual(first['squared_distance_threshold'], second['squared_distance_threshold'])
        self.assertEqual(first['validation'], second['validation'])
        self.assertGreater(second['held_out']['background_false_positive_rate'],
                           first['held_out']['background_false_positive_rate'])
        self.assertEqual(run(doc)['production_anonymity'], 'NOT ESTABLISHED')

    def test_missing_background_or_overlapping_groups_refuse(self):
        doc = fixture()
        doc['traces'] = [t for t in doc['traces'] if t['label'] != 'background-v']
        with self.assertRaises(ValueError):
            run(doc)
        with self.assertRaises(ValueError):
            evaluate(fixture(), {'a', 'b'}, {'train'}, {'train', 'validation'}, {'test'}, allow_synthetic=True)
        doc = fixture()
        doc['traces'][-1]['label'] = 'background-v'
        with self.assertRaises(ValueError):
            run(doc)

    def test_incomplete_nonpacket_and_missing_source_digests_refuse(self):
        for field, value in (('complete', False), ('complete', None), ('observation', 'onion-cell'), ('observation', 'packet')):
            doc = fixture()
            doc[field] = value
            with self.assertRaises(ValueError):
                run(doc)
        with self.assertRaises(ValueError):
            evaluate(fixture(), {'a', 'b'}, {'train'}, {'validation'}, {'test'})

    def test_copied_source_captures_refuse_but_identical_shapes_are_disclosed(self):
        doc = fixture()
        doc['observation'] = 'packet'
        for trace in doc['traces']:
            trace['capture_sha256'] = hashlib.sha256(trace['id'].encode()).hexdigest()
        doc['traces'][2]['events'] = copy.deepcopy(doc['traces'][0]['events'])
        self.assertGreater(run(doc)['results']['strict']['identical_event_shapes_across_splits'], 0)
        doc['traces'][2]['capture_sha256'] = doc['traces'][0]['capture_sha256']
        with self.assertRaises(ValueError):
            run(doc)

    def test_zero_observed_false_alarms_keeps_nonzero_uncertainty(self):
        self.assertGreater(wilson(0, 100)[1], 0)
        self.assertIsNone(wilson(0, 0))
        report = run(fixture())['results']['strict']['held_out']
        self.assertGreater(report['false_positive_wilson_95'][1], 0)
        measured = metrics([('a', 'a', 0), ('background', 'a', 0),
                            ('other', None, 0)], 0, {'a'})
        self.assertEqual(measured['background_false_positive_rate'], .5)
        self.assertEqual(measured['correct_alarm_precision'], .5)

    def test_duplicate_visits_cannot_inflate_background_sample_count(self):
        doc = fixture()
        doc['observation'] = 'packet'
        for trace in doc['traces']:
            trace['capture_sha256'] = hashlib.sha256(trace['id'].encode()).hexdigest()
        duplicate = copy.deepcopy(doc['traces'][-1])
        duplicate['id'] = 'apparently-new-background-visit'
        doc['traces'].append(duplicate)
        with self.assertRaisesRegex(ValueError, 'overweight'):
            run(doc)

    def test_equal_distance_different_labels_abstain(self):
        doc = fixture()
        doc['traces'][1]['events'] = copy.deepcopy(doc['traces'][0]['events'])
        result = run(doc)['results']['strict']
        self.assertTrue(result['reject_all_operating_point'])
        self.assertEqual(result['held_out']['correct_identification_rate'], 0)
        self.assertIsNone(result['held_out']['correct_alarm_precision'])

    def test_cli_preserves_evidence_and_private_output(self):
        script = Path(__file__).with_name('evaluate_open_world.py')
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory)/'source.json', Path(directory)/'report.json'
            source.write_text(json.dumps(fixture()))
            command = [sys.executable, str(script), str(source), '--monitored-label', 'a',
                       '--monitored-label', 'b', '--train-group', 'train', '--validation-group',
                       'validation', '--test-group', 'test', '--allow-synthetic', '--output', str(output)]
            first = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            before = output.read_bytes()
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(before)['dataset_sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(before, output.read_bytes())


if __name__ == '__main__':
    unittest.main()
