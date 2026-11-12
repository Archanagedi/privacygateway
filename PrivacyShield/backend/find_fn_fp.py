import os
import sys
import json

sys.path.insert(0, r'c:\Users\Admin\real time\PrivacyShield\backend')
from detector import PIIDetector
from masker import PIIMasker
from reinserter import LocalReinserter
from metrics import MetricsEngine, SYNTHETIC_DATASET_PATH

detector = PIIDetector(sensitivity=0.5)
masker = PIIMasker()
reinserter = LocalReinserter()

with open(SYNTHETIC_DATASET_PATH, 'r', encoding='utf-8') as f:
    dataset = json.load(f)

fn_list = []
fp_list = []

for doc in dataset:
    text = doc['text']
    expected = doc.get('expected_entities', [])
    doc_id = doc['id']
    title = doc.get('title', '')

    detected = detector.detect(text)

    matched_exp_idx = set()
    for det in detected:
        det_type = det.entity_type
        det_val = det.value.strip().lower()
        matched = False
        for i, exp in enumerate(expected):
            if i in matched_exp_idx:
                continue
            exp_type = exp['type']
            exp_val = exp['value'].strip().lower()
            if (det_type == exp_type) and (det_val == exp_val or det_val in exp_val or exp_val in det_val):
                matched = True
                matched_exp_idx.add(i)
                break
        if not matched:
            s = max(0, det.start - 40)
            e = min(len(text), det.end + 40)
            ctx = text[s:e].replace('\n', ' ')
            fp_list.append({
                'doc_id': doc_id,
                'doc_title': title,
                'detected_value': det.value,
                'predicted_type': det.entity_type,
                'score': det.score,
                'context': f'...{ctx}...'
            })

    for i, exp in enumerate(expected):
        if i not in matched_exp_idx:
            val = exp['value']
            pos = text.find(val)
            if pos != -1:
                s = max(0, pos - 40)
                e = min(len(text), pos + len(val) + 40)
                ctx = text[s:e].replace('\n', ' ')
            else:
                ctx = text[:80].replace('\n', ' ')
            fn_list.append({
                'doc_id': doc_id,
                'doc_title': title,
                'entity_type': exp['type'],
                'missed_value': exp['value'],
                'description': exp.get('description', ''),
                'context': f'...{ctx}...'
            })

print(f'Total FN (Missed): {len(fn_list)}')
for idx, fn in enumerate(fn_list, 1):
    print(f'FN #{idx}: [{fn["doc_id"]}] {fn["doc_title"]} | Type: {fn["entity_type"]} | Value: "{fn["missed_value"]}" | Context: {fn["context"]}')

print(f'\nTotal FP (False Detections): {len(fp_list)}')
for idx, fp in enumerate(fp_list, 1):
    print(f'FP #{idx}: [{fp["doc_id"]}] {fp["doc_title"]} | Type: {fp["predicted_type"]} | Value: "{fp["detected_value"]}" | Context: {fp["context"]}')
