import copy
import math
import unittest
from evaluate_adaptive import evaluate, vector
from test_protocol_detection import fixture

SPLITS=({'train'},{'validation'},{'test'})

class AdaptiveTests(unittest.TestCase):
    def test_positive_class_orientation_and_frozen_calibration(self):
        doc=fixture();a=evaluate(doc,SPLITS,allow_synthetic=True)
        for trace in doc['traces']:
            if trace['group']=='test':trace['protocol_label']='reference' if trace['protocol_label']=='anonguard' else 'anonguard'
        b=evaluate(doc,SPLITS,allow_synthetic=True)
        for first,second in zip(a['results']['strict'],b['results']['strict']):
            self.assertEqual(first['threshold'],second['threshold'])
            self.assertEqual(first['validation'],second['validation'])
            self.assertGreater(first['held_out_auroc'],.99)
            self.assertLess(second['held_out_auroc'],.01)
            self.assertEqual(first['low_fpr_evidence'],'INSUFFICIENT')

    def test_capture_and_partition_integrity_fail_closed(self):
        for field,value in [('complete',False),('observation','packet')]:
            doc=fixture();doc[field]=value
            with self.assertRaises(ValueError):evaluate(doc,SPLITS,allow_synthetic=True)
        with self.assertRaises(ValueError):evaluate(fixture(),({'train'},{'train'},{'test'}),allow_synthetic=True)
        with self.assertRaises(ValueError):evaluate(fixture(),SPLITS)
        doc=fixture();doc['traces'][-1]['capture_sha256']='0'*64;doc['traces'][0]['capture_sha256']='0'*64
        with self.assertRaises(ValueError):evaluate(doc,SPLITS,allow_synthetic=True)

    def test_website_does_not_treat_direct_reference_as_anon_activity(self):
        with self.assertRaises(ValueError):evaluate(fixture(),SPLITS,task='website',allow_synthetic=True)
        doc=fixture()
        for t in doc['traces']:t['label']=t.pop('protocol_label')
        result=evaluate(doc,SPLITS,task='website',allow_synthetic=True)
        self.assertTrue(all(r['held_out_accuracy']==1 for r in result['results']['strict']))

    def test_common_feature_horizon_and_resource_bounds(self):
        doc=fixture()
        for horizon in (0,float('nan'),float('inf'),121):
            with self.assertRaises(ValueError):evaluate(doc,SPLITS,allow_synthetic=True,window=horizon)
        bad=copy.deepcopy(doc['traces'][0]);bad['events'][-1][0]=3601
        with self.assertRaises(ValueError):vector(bad,10)
        values=vector(doc['traces'][0],10)
        self.assertTrue(all(math.isfinite(x) for x in values))

if __name__=='__main__':unittest.main()
