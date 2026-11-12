"""
PrivacyShield - Performance Metrics & Benchmark Engine
Calculates real-time precision, recall, F1-score, reinsertion accuracy,
latency, and PII leakage count against the labeled synthetic Indian enterprise dataset.
"""

import os
import json
import time
import logging
from typing import Dict, Any, List, Tuple
from detector import PIIDetector, DetectedEntity
from masker import PIIMasker
from reinserter import LocalReinserter

logger = logging.getLogger("PrivacyShield.Metrics")
logger.setLevel(logging.INFO)

SYNTHETIC_DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "dataset", "synthetic_documents.json")
LOCAL_METRICS_FILE = "local_metrics.json"

class MetricsEngine:
    """
    Evaluates PII detection quality, reinsertion fidelity, and zero-leakage guarantee.
    """

    def __init__(self, detector: PIIDetector, masker: PIIMasker, reinserter: LocalReinserter):
        self.detector = detector
        self.masker = masker
        self.reinserter = reinserter
        self.cached_benchmark: Dict[str, Any] = {}
        self._load_cached_metrics()

    def _load_cached_metrics(self):
        if os.path.exists(LOCAL_METRICS_FILE):
            try:
                with open(LOCAL_METRICS_FILE, "r", encoding="utf-8") as f:
                    self.cached_benchmark = json.load(f)
            except Exception:
                self.cached_benchmark = {}

    def _save_cached_metrics(self):
        try:
            with open(LOCAL_METRICS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.cached_benchmark, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving cached metrics: {e}")

    def run_benchmark(self, limit: int = 50) -> Dict[str, Any]:
        """
        Executes an end-to-end evaluation run against the synthetic documents dataset.
        Computes true positives, false positives, false negatives, precision, recall,
        reinsertion accuracy, latency, and leakage violations.
        """
        if not os.path.exists(SYNTHETIC_DATASET_PATH):
            return {
                "error": f"Synthetic dataset not found at {SYNTHETIC_DATASET_PATH}",
                "documents_tested": 0
            }

        with open(SYNTHETIC_DATASET_PATH, "r", encoding="utf-8") as f:
            dataset: List[Dict[str, Any]] = json.load(f)

        if limit > 0:
            dataset = dataset[:limit]

        start_time = time.time()

        total_expected = 0
        total_detected = 0
        true_positives = 0
        false_positives = 0
        false_negatives = 0
        leakage_violations = 0
        reinsertion_successes = 0

        # Detailed breakdown per entity type
        entity_breakdown: Dict[str, Dict[str, int]] = {
            "PERSON": {"expected": 0, "detected": 0, "tp": 0, "fp": 0, "fn": 0},
            "AADHAAR": {"expected": 0, "detected": 0, "tp": 0, "fp": 0, "fn": 0},
            "PAN": {"expected": 0, "detected": 0, "tp": 0, "fp": 0, "fn": 0},
            "GSTIN": {"expected": 0, "detected": 0, "tp": 0, "fp": 0, "fn": 0},
            "VOTER_ID": {"expected": 0, "detected": 0, "tp": 0, "fp": 0, "fn": 0},
            "PASSPORT": {"expected": 0, "detected": 0, "tp": 0, "fp": 0, "fn": 0},
            "PHONE_NUMBER": {"expected": 0, "detected": 0, "tp": 0, "fp": 0, "fn": 0},
            "ADDRESS": {"expected": 0, "detected": 0, "tp": 0, "fp": 0, "fn": 0}
        }

        doc_results: List[Dict[str, Any]] = []
        false_negatives_list: List[Dict[str, Any]] = []
        false_positives_list: List[Dict[str, Any]] = []

        for doc in dataset:
            text = doc["text"]
            expected = doc.get("expected_entities", [])
            doc_id = doc["id"]
            category = doc.get("category", "General")

            # Update expected counts
            for exp in expected:
                etype = exp["type"]
                total_expected += 1
                if etype in entity_breakdown:
                    entity_breakdown[etype]["expected"] += 1

            # 1. Detection
            t_doc_start = time.time()
            detected_entities = self.detector.detect(text)
            t_doc_elapsed = (time.time() - t_doc_start) * 1000.0

            total_detected += len(detected_entities)

            # Match detected with expected
            matched_expected_indices = set()
            doc_tp = 0
            doc_fp = 0

            for det in detected_entities:
                det_type = det.entity_type
                det_val = det.value.strip().lower()
                if det_type in entity_breakdown:
                    entity_breakdown[det_type]["detected"] += 1

                # Check if matches any expected entity of same type or overlapping value
                matched = False
                for i, exp in enumerate(expected):
                    if i in matched_expected_indices:
                        continue
                    exp_type = exp["type"]
                    exp_val = exp["value"].strip().lower()

                    # Exact or strong sub-string match for address/names
                    is_type_match = (det_type == exp_type)
                    is_val_match = (det_val == exp_val or det_val in exp_val or exp_val in det_val)

                    if is_type_match and is_val_match:
                        matched = True
                        matched_expected_indices.add(i)
                        true_positives += 1
                        doc_tp += 1
                        if det_type in entity_breakdown:
                            entity_breakdown[det_type]["tp"] += 1
                        break

                if not matched:
                    false_positives += 1
                    doc_fp += 1
                    if det_type in entity_breakdown:
                        entity_breakdown[det_type]["fp"] += 1
                    
                    # Context snippet around false detection
                    snippet_start = max(0, det.start - 45)
                    snippet_end = min(len(text), det.end + 45)
                    ctx_before = text[snippet_start:det.start].replace("\n", " ")
                    ctx_match = text[det.start:det.end].replace("\n", " ")
                    ctx_after = text[det.end:snippet_end].replace("\n", " ")
                    false_positives_list.append({
                        "serial_no": len(false_positives_list) + 1,
                        "doc_id": doc_id,
                        "doc_title": doc.get("title", ""),
                        "category": category,
                        "detected_value": det.value,
                        "predicted_type": det.entity_type,
                        "score": round(det.score, 2),
                        "context": f"...{ctx_before}<mark class=\"highlight-fp\">{ctx_match}</mark>{ctx_after}...",
                        "explanation": det.explanation
                    })

            doc_fn = len(expected) - len(matched_expected_indices)
            false_negatives += doc_fn

            for i, exp in enumerate(expected):
                if i not in matched_expected_indices:
                    etype = exp["type"]
                    if etype in entity_breakdown:
                        entity_breakdown[etype]["fn"] += 1

                    # Context snippet around missed expected entity
                    val = exp["value"]
                    pos = text.find(val)
                    if pos != -1:
                        snippet_start = max(0, pos - 45)
                        snippet_end = min(len(text), pos + len(val) + 45)
                        ctx_before = text[snippet_start:pos].replace("\n", " ")
                        ctx_match = text[pos:pos + len(val)].replace("\n", " ")
                        ctx_after = text[pos + len(val):snippet_end].replace("\n", " ")
                        ctx_str = f"...{ctx_before}<mark class=\"highlight-fn\">{ctx_match}</mark>{ctx_after}..."
                    else:
                        ctx_str = f"...{text[:90].replace(chr(10), ' ')}..."

                    false_negatives_list.append({
                        "serial_no": len(false_negatives_list) + 1,
                        "doc_id": doc_id,
                        "doc_title": doc.get("title", ""),
                        "category": category,
                        "entity_type": etype,
                        "missed_value": val,
                        "description": exp.get("description", ""),
                        "context": ctx_str
                    })

            # 2. Masking & Zero Leakage Check
            mask_res = self.masker.mask(text, detected_entities)

            # Check if any original detected value leaked into sanitized text
            for ph, orig_val in mask_res.placeholder_map.items():
                if len(orig_val.strip()) > 3 and orig_val.strip().lower() in mask_res.sanitized_text.lower():
                    leakage_violations += 1

            # 3. Reinsertion
            reinsert_res = self.reinserter.reinsert(
                mask_res.sanitized_text,
                mask_res.placeholder_map
            )
            # Check if all placeholders were cleanly replaced back
            if reinsert_res.reinsertion_status in ("PERFECT", "NO_PLACEHOLDERS"):
                reinsertion_successes += 1

            doc_results.append({
                "id": doc_id,
                "title": doc.get("title", ""),
                "category": category,
                "expected_count": len(expected),
                "detected_count": len(detected_entities),
                "true_positives": doc_tp,
                "false_positives": doc_fp,
                "false_negatives": doc_fn,
                "latency_ms": round(t_doc_elapsed, 1),
                "sanitized_preview": mask_res.sanitized_text[:120] + "..." if len(mask_res.sanitized_text) > 120 else mask_res.sanitized_text
            })

        total_elapsed = time.time() - start_time
        avg_latency = (total_elapsed / len(dataset)) * 1000.0 if dataset else 0.0

        # Calculations
        precision = (true_positives / (true_positives + false_positives)) if (true_positives + false_positives) > 0 else 1.0
        recall = (true_positives / (true_positives + false_negatives)) if (true_positives + false_negatives) > 0 else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        reinsertion_accuracy = (reinsertion_successes / len(dataset)) if dataset else 1.0

        benchmark_summary = {
            "total_documents": len(dataset),
            "expected_entities": total_expected,
            "detected_entities": total_detected,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "reinsertion_accuracy": round(reinsertion_accuracy, 4),
            "leakage_count": leakage_violations,
            "average_latency_ms": round(avg_latency, 2),
            "total_benchmark_time_seconds": round(total_elapsed, 2),
            "entity_breakdown": entity_breakdown,
            "document_results": doc_results,
            "false_negatives_list": false_negatives_list,
            "false_positives_list": false_positives_list
        }

        self.cached_benchmark = benchmark_summary
        self._save_cached_metrics()
        return benchmark_summary

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Returns cached benchmark summary, or runs a fresh test if empty."""
        if not self.cached_benchmark:
            return self.run_benchmark(limit=50)
        return self.cached_benchmark
