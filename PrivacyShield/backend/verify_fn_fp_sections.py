"""
Verification script for Section 1 (Missed Entities - FN) and Section 2 (False Detections - FP).
Verifies:
1. FN count == 5
2. FP count == 2
3. All fields present in each item (serial_no, doc_id, doc_title, category, entity_type/predicted_type, missed_value/detected_value, context)
4. Verify HTTP endpoints /api/metrics and /api/test-dataset
"""

import urllib.request
import json
import sys

BASE_URL = "http://127.0.0.1:8000"

def verify_sections():
    print("==================================================================")
    print(" PRIVACYSHIELD - MISSED ENTITIES (FN) & FALSE DETECTIONS (FP) TEST")
    print("==================================================================")

    # 1. Test POST /api/test-dataset
    print("\n[1/2] Testing POST /api/test-dataset...")
    req = urllib.request.Request(
        f"{BASE_URL}/api/test-dataset",
        data=b"{}",
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())

    fn_count = data.get("false_negatives", 0)
    fn_list = data.get("false_negatives_list", [])
    fp_count = data.get("false_positives", 0)
    fp_list = data.get("false_positives_list", [])

    print(f"  • False Negatives (FN) Count: {fn_count}")
    print(f"  • False Negatives (FN) List Length: {len(fn_list)}")
    print(f"  • False Positives (FP) Count: {fp_count}")
    print(f"  • False Positives (FP) List Length: {len(fp_list)}")

    assert fn_count == 5, f"Expected 5 FN, got {fn_count}"
    assert len(fn_list) == 5, f"Expected 5 items in FN list, got {len(fn_list)}"
    assert fp_count == 2, f"Expected 2 FP, got {fp_count}"
    assert len(fp_list) == 2, f"Expected 2 items in FP list, got {len(fp_list)}"

    print("\n--- SECTION 1: ALL 5 ACTUAL MISSED ENTITIES (FN) ---")
    for fn in fn_list:
        print(f"  #{fn['serial_no']} | Doc: {fn['doc_id']} - {fn['doc_title']}")
        print(f"     Entity Type: {fn['entity_type']}")
        print(f"     Missed Value: \"{fn['missed_value']}\"")
        print(f"     Context Snippet: {fn['context'][:100]}...\n")
        assert "serial_no" in fn
        assert "doc_id" in fn
        assert "doc_title" in fn
        assert "entity_type" in fn
        assert "missed_value" in fn
        assert "context" in fn

    print("--- SECTION 2: ALL 2 ACTUAL FALSE DETECTIONS (FP) ---")
    for fp in fp_list:
        print(f"  #{fp['serial_no']} | Doc: {fp['doc_id']} - {fp['doc_title']}")
        print(f"     Predicted Type: {fp['predicted_type']} (Confidence: {fp.get('score')})")
        print(f"     Incorrectly Detected Value: \"{fp['detected_value']}\"")
        print(f"     Context Snippet: {fp['context'][:100]}...\n")
        assert "serial_no" in fp
        assert "doc_id" in fp
        assert "doc_title" in fp
        assert "predicted_type" in fp
        assert "detected_value" in fp
        assert "context" in fp

    # 2. Test GET /api/metrics
    print("[2/2] Testing GET /api/metrics (Cached Benchmark)...")
    req = urllib.request.Request(f"{BASE_URL}/api/metrics")
    with urllib.request.urlopen(req) as resp:
        m_data = json.loads(resp.read().decode())
    
    bench = m_data.get("benchmark", {})
    assert bench.get("false_negatives") == 5, f"Expected 5 FN in metrics, got {bench.get('false_negatives')}"
    assert len(bench.get("false_negatives_list", [])) == 5, "Expected 5 items in metrics FN list"
    assert bench.get("false_positives") == 2, f"Expected 2 FP in metrics, got {bench.get('false_positives')}"
    assert len(bench.get("false_positives_list", [])) == 2, "Expected 2 items in metrics FP list"
    print("  ✓ GET /api/metrics returns identical 5 FN and 2 FP lists.")

    print("\n==================================================================")
    print(" ALL VERIFICATIONS PASSED: FN=5 AND FP=2 CONFIRMED ACCURATELY!")
    print("==================================================================")

if __name__ == "__main__":
    verify_sections()
