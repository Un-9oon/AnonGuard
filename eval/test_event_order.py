"""Synthetic timestamp-integrity fixtures, not an anonymity evaluation."""
import copy
import math
import unittest
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from event_order import chronological_events


class EventOrderTests(unittest.TestCase):
    def test_tiny_reordering_is_stable_explicit_and_nonmutating(self):
        events = [[0,1,100],[.010001,1,100],[.01,-1,200],[.010001,-1,300]]
        original = copy.deepcopy(events)
        ordered, report = chronological_events(events)
        self.assertEqual(events, original)
        self.assertEqual(ordered, [events[0],events[2],events[1],events[3]])
        self.assertEqual(report['backstep_events'], 1)
        self.assertAlmostEqual(report['largest_backstep_seconds'], .000001)
        self.assertEqual(report['clock_synchronization'], 'NOT ESTABLISHED')

    def test_clock_jump_and_cumulative_drift_refuse(self):
        for times in ([0,.1,.099], [0,.1,.099999,.099997], [0,math.nan], [0,math.inf]):
            with self.assertRaises(ValueError):
                chronological_events([[t,1,100] for t in times])
        with self.assertRaises(ValueError):chronological_events([])

    def test_already_ordered_events_do_not_get_claimed_as_a_repair(self):
        source = [[-1,1,10],[0,-1,20]]  # Request-relative accounting can be negative.
        ordered, report = chronological_events(source)
        self.assertEqual(ordered,source)
        self.assertEqual(report['backstep_events'],0)

    def test_cli_derivative_is_exclusive_private_and_source_linked(self):
        doc={'version':1,'complete':True,'observation':'synthetic','traces':[
            {'id':str(i),'label':'owned','group':'g'+str(i),'defense':'strict',
             'events':[[0,1,100],[.010001,1,100],[.01,-1,200]]} for i in range(2)]}
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'raw.json';output=Path(directory)/'ordered.json'
            source.write_text(json.dumps(doc));before=source.read_bytes()
            command=[sys.executable,str(Path(__file__).with_name('event_order.py')),str(source),'--output',str(output)]
            result=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            derived=json.loads(output.read_text())
            provenance=derived['timestamp_canonicalization']
            self.assertEqual(provenance['source_dataset_sha256'],hashlib.sha256(before).hexdigest())
            self.assertEqual(len(provenance['changed_traces']),2)
            self.assertEqual(source.read_bytes(),before)
            self.assertEqual(output.stat().st_mode & 0o777,0o600)
            saved=output.read_bytes()
            self.assertNotEqual(subprocess.run(command,capture_output=True).returncode,0)
            self.assertEqual(output.read_bytes(),saved)

    def test_invalid_clock_jump_does_not_publish_a_derivative(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'raw.json';output=Path(directory)/'ordered.json'
            source.write_text(json.dumps({'complete':True,'traces':[
                {'events':[[0,1,100],[1,1,100],[.9,-1,100]]}, {'events':[[0,1,100]]}]}))
            result=subprocess.run([sys.executable,str(Path(__file__).with_name('event_order.py')),
                str(source),'--output',str(output)],capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(output.exists())


if __name__ == '__main__':unittest.main()
