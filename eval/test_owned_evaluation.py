"""Evidence integrity regression tests; synthetic inputs are not security results."""
import tempfile
import unittest
from pathlib import Path
import numpy as np
from capture_owned_testnet import parse_pcap, capture_window
from evaluate_link_correlation import exit_events, bins
from evaluate_owned_capture import label_control, validate_split


class OwnedEvaluationTests(unittest.TestCase):
    def test_fixed_capture_window_refuses_nonfinite_or_unbounded_durations(self):
        for value in ('nan','inf','0','4.99','121'):
            with self.assertRaises(ValueError):capture_window(value)
        self.assertIsNone(capture_window(None))
        self.assertEqual(capture_window('5'),5)

    def test_truncated_pcaps_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'bad.pcap'
            for content in (b'', b'\xd4\xc3\xb2\xa1'+b'\x00'*16+b'\x01\x00\x00\x00'+b'\x00'):
                path.write_bytes(content)
                for parser in (lambda p: parse_pcap(p,set()), exit_events):
                    with self.assertRaises(ValueError):
                        parser(path)

    def test_permutation_preserves_counts_and_is_deterministic(self):
        predictions = np.array([0,0,1,1,2,2])
        first = label_control(predictions,predictions,seed=29,repeats=100)
        self.assertEqual(first,label_control(predictions,predictions,seed=29,repeats=100))
        self.assertEqual(first['observed_accuracy'],1)
        self.assertGreater(first['permutation_tail_probability'],0)
        self.assertLess(first['shuffled_label_mean_accuracy'],.6)

    def test_closed_world_split_requires_classes(self):
        with self.assertRaises(ValueError):
            validate_split([{'label':'a'}],[{'label':'b'}])
        with self.assertRaises(ValueError):
            validate_split([],[])
        validate_split([{'label':'a'}],[{'label':'a'}])

    def test_negative_and_long_events_do_not_wrap_bins(self):
        actual = bins([[-1,1,100],[20,1,100],[0,-1,50]])
        self.assertEqual(float(actual.sum()),50)
        self.assertEqual(actual[1,0],50)

if __name__=='__main__':unittest.main()
