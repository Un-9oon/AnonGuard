"""Evidence integrity regression tests; synthetic inputs are not security results."""
import tempfile
import unittest
import hashlib
import socket
import struct
from pathlib import Path
import numpy as np
from capture_owned_testnet import parse_pcap, capture_window
from evaluate_link_correlation import exit_events, bins, similarity
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
        actual = bins([[-1,1,100],[-.001,1,100],[20,1,100],[0,-1,50]])
        self.assertEqual(float(actual.sum()),50)
        self.assertEqual(actual[1,0],50)

    def test_short_capture_windows_are_not_extended_with_zero_tail(self):
        short=bins([[0,1,100],[4.9,-1,50],[5,1,999]],5)
        self.assertEqual(short.shape,(2,100))
        self.assertEqual(float(short.sum()),150)
        self.assertTrue(np.isfinite(similarity(short,short)))
        with self.assertRaises(ValueError):similarity(short,bins([],20))
        for window in (float('nan'),float('inf'),0,121):
            with self.assertRaises(ValueError):bins([],window)

    def test_link_capture_digest_is_verified_before_using_events(self):
        ethernet=bytes(12)+b'\x08\x00'
        ip=bytearray(20);ip[0]=0x45;ip[2:4]=struct.pack('!H',41);ip[9]=6
        ip[12:16]=socket.inet_aton('127.0.0.1');ip[16:20]=socket.inet_aton('127.3.0.1')
        tcp=bytearray(20);tcp[12]=0x50
        packet=ethernet+ip+tcp+b'x'
        header=b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII',2,4,0,0,65535,1)
        raw=header+struct.pack('<IIII',1,0,len(packet),len(packet))+packet
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'owned.pcap';path.write_bytes(raw)
            self.assertEqual(exit_events(path,hashlib.sha256(raw).hexdigest()),[[0.0,1,len(packet)]])
            with self.assertRaisesRegex(ValueError,'digest'):
                exit_events(path,'0'*64)

if __name__=='__main__':unittest.main()
