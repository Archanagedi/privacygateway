"""
PrivacyShield - Multilingual Synthetic Dataset Evaluation & Benchmark
Evaluates detection across English, Kannada, Hindi, Kannada-English, and Hindi-English
across 50 labeled documents covering identity cards, loan forms, banking, and employee records.
Calculates TP, FP, FN, Precision, Recall, and F1 score with breakdown by language and entity type.
"""

import os
import sys
import json
import time
import re
from typing import Dict, Any, List

sys.path.insert(0, os.path.dirname(__file__))

from detector import PIIDetector, DetectedEntity
from multilingual import normalize_indic_numerals

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "dataset", "multilingual_synthetic_documents.json")

def evaluate_multilingual_dataset(dataset_path: str = DATASET_PATH) -> Dict[str, Any]:
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Multilingual dataset not found at {dataset_path}")

    with open(dataset_path, "r", encoding="utf-8") as f:
        docs = json.load(f)

    detector = PIIDetector(sensitivity=0.5)

    total_expected = 0
    total_detected = 0
    tp = 0
    fp = 0
    fn = 0

    lang_stats: Dict[str, Dict[str, int]] = {
        "English": {"docs": 0, "expected": 0, "tp": 0, "fp": 0, "fn": 0},
        "Kannada": {"docs": 0, "expected": 0, "tp": 0, "fp": 0, "fn": 0},
        "Hindi": {"docs": 0, "expected": 0, "tp": 0, "fp": 0, "fn": 0},
        "Kannada-English": {"docs": 0, "expected": 0, "tp": 0, "fp": 0, "fn": 0},
        "Hindi-English": {"docs": 0, "expected": 0, "tp": 0, "fp": 0, "fn": 0}
    }

    entity_stats: Dict[str, Dict[str, int]] = {}
    missed_list: List[Dict[str, Any]] = []
    false_list: List[Dict[str, Any]] = []

    t_start = time.time()

    for doc in docs:
        doc_id = doc["id"]
        lang = doc.get("language", "General")
        text = doc["text"]
        expected = doc.get("expected_entities", [])

        if lang not in lang_stats:
            lang_stats[lang] = {"docs": 0, "expected": 0, "tp": 0, "fp": 0, "fn": 0}
        lang_stats[lang]["docs"] += 1
        lang_stats[lang]["expected"] += len(expected)
        total_expected += len(expected)

        for exp in expected:
            etype = exp["type"]
            if etype not in entity_stats:
                entity_stats[etype] = {"expected": 0, "tp": 0, "fp": 0, "fn": 0}
            entity_stats[etype]["expected"] += 1

        detected = detector.detect(text)
        total_detected += len(detected)

        matched_expected = set()

        for det in detected:
            det_type = det.entity_type
            det_val = normalize_indic_numerals(det.value.strip().lower())
            if det_type not in entity_stats:
                entity_stats[det_type] = {"expected": 0, "tp": 0, "fp": 0, "fn": 0}

            matched = False
            for i, exp in enumerate(expected):
                if i in matched_expected:
                    continue
                exp_type = exp["type"]
                exp_val = normalize_indic_numerals(exp["value"].strip().lower())

                # Clean comparison (strip punctuation and spaces)
                clean_det = re.sub(r'[\s\-_/.,:;]', '', det_val)
                clean_exp = re.sub(r'[\s\-_/.,:;]', '', exp_val)

                is_type_match = (det_type == exp_type)
                is_val_match = (clean_det == clean_exp or clean_det in clean_exp or clean_exp in clean_det)

                if is_type_match and is_val_match:
                    matched = True
                    matched_expected.add(i)
                    tp += 1
                    lang_stats[lang]["tp"] += 1
                    entity_stats[det_type]["tp"] += 1
                    break

            if not matched:
                fp += 1
                lang_stats[lang]["fp"] += 1
                entity_stats[det_type]["fp"] += 1
                false_list.append({
                    "doc_id": doc_id,
                    "lang": lang,
                    "type": det.entity_type,
                    "value": det.value,
                    "score": round(det.score, 2),
                    "method": det.detection_method
                })

        for i, exp in enumerate(expected):
            if i not in matched_expected:
                fn += 1
                etype = exp["type"]
                lang_stats[lang]["fn"] += 1
                entity_stats[etype]["fn"] += 1
                missed_list.append({
                    "doc_id": doc_id,
                    "lang": lang,
                    "type": exp["type"],
                    "value": exp["value"]
                })

    elapsed_ms = (time.time() - t_start) * 1000.0

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    print("==================================================================")
    print(" PRIVACYSHIELD - MULTILINGUAL 50-DOCUMENT BENCHMARK REPORT")
    print("==================================================================")
    print(f"Total Documents Evaluated: {len(docs)}")
    print(f"Execution Latency: {elapsed_ms:.1f} ms (avg {elapsed_ms/len(docs):.2f} ms/doc)")
    print(f"Total Expected Entities:  {total_expected}")
    print(f"Total Detected Entities:  {total_detected}")
    print(f"True Positives (TP):      {tp}")
    print(f"False Positives (FP):     {fp}")
    print(f"False Negatives (FN):     {fn}")
    print(f"Precision:                {precision * 100:.2f}%")
    print(f"Recall:                   {recall * 100:.2f}%")
    print(f"F1-Score:                 {f1 * 100:.2f}%\n")

    print("------------------------------------------------------------------")
    print(" BREAKDOWN BY LANGUAGE")
    print("------------------------------------------------------------------")
    for lang, s in lang_stats.items():
        l_p = s["tp"] / (s["tp"] + s["fp"]) if (s["tp"] + s["fp"]) > 0 else 0.0
        l_r = s["tp"] / (s["tp"] + s["fn"]) if (s["tp"] + s["fn"]) > 0 else 0.0
        l_f1 = (2 * l_p * l_r) / (l_p + l_r) if (l_p + l_r) > 0 else 0.0
        print(f"  • {lang:18s} | Docs: {s['docs']:2d} | Exp: {s['expected']:2d} | TP: {s['tp']:2d} | FP: {s['fp']:2d} | FN: {s['fn']:2d} | P: {l_p*100:5.1f}% | R: {l_r*100:5.1f}% | F1: {l_f1*100:5.1f}%")

    print("\n------------------------------------------------------------------")
    print(" BREAKDOWN BY ENTITY TYPE")
    print("------------------------------------------------------------------")
    for etype, s in sorted(entity_stats.items()):
        e_p = s["tp"] / (s["tp"] + s["fp"]) if (s["tp"] + s["fp"]) > 0 else 0.0
        e_r = s["tp"] / (s["tp"] + s["fn"]) if (s["tp"] + s["fn"]) > 0 else 0.0
        e_f1 = (2 * e_p * e_r) / (e_p + e_r) if (e_p + e_r) > 0 else 0.0
        print(f"  • {etype:18s} | Exp: {s['expected']:2d} | TP: {s['tp']:2d} | FP: {s['fp']:2d} | FN: {s['fn']:2d} | P: {e_p*100:5.1f}% | R: {e_r*100:5.1f}% | F1: {e_f1*100:5.1f}%")

    if missed_list:
        print(f"\n[!] MISSED ENTITIES (FN = {len(missed_list)}):")
        for m in missed_list:
            print(f"    - [{m['doc_id']}] ({m['lang']}) {m['type']}: '{m['value']}'")

    if false_list:
        print(f"\n[!] FALSE DETECTIONS (FP = {len(false_list)}):")
        for f_det in false_list:
            print(f"    - [{f_det['doc_id']}] ({f_det['lang']}) {f_det['type']}: '{f_det['value']}' (Score: {f_det['score']}, Method: {f_det['method']})")

    print("==================================================================\n")

    return {
        "total_documents": len(docs),
        "total_expected": total_expected,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "language_breakdown": lang_stats,
        "entity_breakdown": entity_stats,
        "missed_entities": missed_list,
        "false_detections": false_list
    }

if __name__ == "__main__":
    evaluate_multilingual_dataset()
