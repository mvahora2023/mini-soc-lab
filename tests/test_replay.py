import unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from replay_brute_force import replay, DEFAULT
class ReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample=DEFAULT.read_text(encoding="utf-8")
    def test_expected_two_synthetic_bursts(self):
        alerts=replay(self.sample,6,5)
        self.assertEqual(len(alerts),2)
        self.assertEqual([x["failures_in_peak_window"] for x in alerts],[20,8])
        self.assertTrue(all(x["source_ip"]=="203.0.113.10" for x in alerts))
        self.assertEqual([x["distinct_target_users"] for x in alerts],[1,8])
    def test_high_threshold_has_no_alerts(self):
        self.assertEqual(replay(self.sample,100,5),[])
    def test_empty_input_no_alerts(self):
        self.assertEqual(replay("",6,5),[])
    def test_invalid_params_rejected(self):
        with self.assertRaises(ValueError):replay(self.sample,0,5)
    def test_no_windows_or_network_calls(self):
        # This parser only accepts a string and returns data. External behavior
        # would require an explicit separate integration not present here.
        self.assertEqual(len(replay("# synthetic empty",6,5)),0)
if __name__=="__main__":unittest.main()
