import copy
import importlib.util
from pathlib import Path
import json
import tempfile
import unittest
spec = importlib.util.spec_from_file_location('evaluation', Path(__file__).with_name('evaluate_traces.py'))
evaluation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluation)

class EvaluationTests(unittest.TestCase):
    def document(self):
        return {'version': 1, 'observation': 'synthetic', 'traces': [
            {'id': f'{group}-{label}', 'label': label, 'group': group, 'defense': 'balanced',
             'events': [[0, 1, 100], [length, -1, 100]], 'application_bytes': 100, 'latency_ms': length * 1000}
            for group in ('training-day', 'heldout-day') for label, length in [('a', 1), ('b', 10)]]}
    def test_group_split_attack_retraining_and_explicit_limits(self):
        report = evaluation.evaluate(self.document(), {'heldout-day'})
        result = report['results']['balanced']
        self.assertEqual(result['accuracy'], 1)
        self.assertEqual(result['train_count'], 2)
        self.assertEqual(result['wire_to_application_ratio'], 2)
        self.assertEqual(report['flow_correlation'], 'NOT EVALUATED')
        self.assertEqual(report['observation'], 'synthetic')
    def test_untrained_defense_cannot_get_false_success(self):
        doc = self.document()
        doc['traces'][2]['defense'] = 'other'
        with self.assertRaises(ValueError):
            evaluation.evaluate(doc, {'heldout-day'})
    def test_duplicate_nonfinite_and_out_of_order_refused(self):
        for case in range(3):
            doc = copy.deepcopy(self.document())
            if case == 0: doc['traces'][1]['id'] = doc['traces'][0]['id']
            if case == 1: doc['traces'][0]['events'][1][0] = float('nan')
            if case == 2: doc['traces'][0]['events'][1][0] = -1
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'data.json'; path.write_text(json.dumps(doc))
                with self.assertRaises(ValueError): evaluation.load(path)
if __name__ == '__main__': unittest.main()
