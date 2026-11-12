import sys
sys.path.append(r'C:\Users\Admin\real time\PrivacyShield\backend')
from metrics import MetricsEngine
from detector import PIIDetector
from masker import PIIMasker
from reinserter import LocalReinserter

d = PIIDetector()
m = PIIMasker()
r = LocalReinserter()
me = MetricsEngine(d, m, r)
bench = me.run_benchmark(limit=50)
print("Benchmark false_negatives:", bench["false_negatives"])
print("Benchmark false_positives:", bench["false_positives"])
