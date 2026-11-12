import sys
sys.path.append(r'C:\Users\Admin\real time\PrivacyShield\backend')
from detector import PIIDetector

d = PIIDetector()

# Test Kannada text
kan_text = 'ನನ್ನ ಹೆಸರು ರಾಹುಲ್ ಶರ್ಮಾ. ನನ್ನ ಆಧಾರ್ ಸಂಖ್ಯೆ ೧೨೩೪ ೫೬೭೮ ೯೦೧೨ ಮತ್ತು ಮೊಬೈಲ್ ೯೮೭೬೫೪೩೨೧೦. ಪ್ಯಾನ್ ಸಂಖ್ಯೆ: ABCDE1234F. ವಿಳಾಸ: ಶಾಂತಿ ನಗರ, ಬೆಂಗಳೂರು 560038.'
res_k = d.detect(kan_text)
print('--- KANNADA RESULTS ---')
for e in res_k:
    print(f'[{e.entity_type}] "{e.value}" ({e.start}:{e.end})')

# Test Hindi text
hin_text = 'मेरा नाम राहुल शर्मा है। आधार संख्या: १२३४ ५६७८ ९०१२, फोन: ९८७६५४३२१०, जन्म तिथि: 15/08/1990। पता: फ्लैट 402, शांति नगर, नई दिल्ली 110001।'
res_h = d.detect(hin_text)
print('\n--- HINDI RESULTS ---')
for e in res_h:
    print(f'[{e.entity_type}] "{e.value}" ({e.start}:{e.end})')

# Test Mixed Kannada + Hindi + English text
mix_text = 'ಅರ್ಜಿದಾರರ ಹೆಸರು: ರಾಹುಲ್ ಶರ್ಮಾ. पिता का नाम: श्री रमेश शर्मा. Aadhaar: 1234 5678 9012. PAN: ABCDE1234F. Contact: 9876543210. ವಿಳಾಸ: Bangalore 560001.'
res_m = d.detect(mix_text)
print('\n--- MIXED RESULTS ---')
for e in res_m:
    print(f'[{e.entity_type}] "{e.value}" ({e.start}:{e.end})')
