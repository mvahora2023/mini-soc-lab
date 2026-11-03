#!/usr/bin/env python3
"""Static validation for synthetic Mini SOC artifacts, not detection efficacy."""
from pathlib import Path
import json, unittest, uuid
import yaml

ROOT=Path(__file__).resolve().parents[1]
CASES=('brute_force_windows','phishing_email','suspicious_powershell')

class ArtifactTests(unittest.TestCase):
    def test_sigma_rules_parse_and_reference_existing_base_rules(self):
        for case in CASES:
            path=ROOT/'detections'/case/'sigma_rule.yml'
            with self.subTest(case=case):
                rules=list(yaml.safe_load_all(path.read_text(encoding='utf-8')))
                self.assertGreaterEqual(len(rules),1)
                names={rule.get('name') for rule in rules if isinstance(rule,dict)}
                for rule in rules:
                    self.assertIsInstance(rule,dict)
                    self.assertIn('title',rule)
                    self.assertIn('id',rule)
                    uuid.UUID(str(rule['id']))
                    if 'correlation' in rule:
                        corr=rule['correlation']
                        self.assertIn(corr['type'],('event_count','value_count','temporal','temporal_ordered'))
                        self.assertIn('timespan',corr)
                        self.assertIn('group-by',corr)
                        for base in corr['rules']:
                            self.assertIn(base,names)
                    else:
                        self.assertIn('detection',rule)
                        self.assertIn('condition',rule['detection'])
                        self.assertNotIn('| count(',str(rule['detection']['condition']))
    def test_sample_alerts_are_json_and_synthetic(self):
        for case in CASES:
            path=ROOT/'detections'/case/'alert.json'
            with self.subTest(case=case):
                doc=json.loads(path.read_text(encoding='utf-8'))
                self.assertIn('SYNTHETIC',str(doc.get('_comment','')).upper())
    def test_attack_navigator_is_json(self):
        obj=json.loads((ROOT/'coverage'/'navigator_layer.json').read_text(encoding='utf-8'))
        self.assertEqual(obj['domain'],'enterprise-attack')
        self.assertGreater(len(obj['techniques']),0)
if __name__=='__main__':
    unittest.main()
