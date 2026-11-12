import json

with open('c:/Users/Admin/real time/PrivacyShield/dataset/synthetic_documents.json', 'r', encoding='utf-8') as f:
    docs = json.load(f)

for d in docs:
    for word in ['account', 'ifsc', 'bank', 'dob', 'birth']:
        if word in d['text'].lower():
            print(f"{d['id']} has '{word}': {d['text'][:70]}...")
