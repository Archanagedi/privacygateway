import sys
sys.path.append(r'C:\Users\Admin\real time\PrivacyShield\backend')
from detector import PIIDetector

d = PIIDetector()
text2 = """Employee Form
Employee Name: Amit Kumar
Email: amit.kumar@company.com
Savings Account No: 309812345678
IFSC Code: SBIN0001234
PIN Code: 560001
Voter ID: ABC1234567
Passport No: K1234567"""

res2 = d.detect(text2)
print("Detected entities count:", len(res2))
for e in res2:
    print(f"[{e.entity_type}] '{e.value}' ({e.start}:{e.end})")
