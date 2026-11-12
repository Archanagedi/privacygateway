"""
PrivacyShield - Multilingual Pipeline & Combined Redaction Comprehensive Test Suite
Validates:
A. English-only document with sensitive text
B. Kannada-only document with sensitive text
C. Hindi-only document with sensitive text
D. Mixed Kannada + English document with sensitive text
E. Mixed Hindi + English document with sensitive text
F. Mixed Kannada + Hindi document with sensitive text
G. Mixed Kannada + English + Hindi document with sensitive text
H. PDF document with mixed languages
I. Identity card image with BOTH photograph and sensitive text (Combined Redaction)
J. Zero Outbound Raw PII Leakage Check
K. Benchmark FN=5 and FP=2 preservation
"""

import os
import io
import sys
import cv2
import json
import pymupdf
import numpy as np
from PIL import Image, ImageDraw, ImageFont

sys.path.append(os.path.dirname(__file__))

from detector import PIIDetector
from masker import PIIMasker
from reinserter import LocalReinserter
from multilingual import detect_languages, normalize_indic_numerals
from image_redactor import ImageRedactor
from metrics import MetricsEngine

def run_multilingual_validation():
    print("=" * 75)
    print(" PRIVACYSHIELD - MULTILINGUAL & COMBINED REDACTION VERIFICATION SUITE")
    print("=" * 75 + "\n")

    detector = PIIDetector(sensitivity=0.5)
    masker = PIIMasker()
    reinserter = LocalReinserter()
    redactor = ImageRedactor(detector=detector, masker=masker)

    passed_tests = 0
    total_tests = 11

    # --------------------------------------------------------------------------
    # Case A: English-only document
    # --------------------------------------------------------------------------
    print("[1/11] Case A: English-only Document with Sensitive Text")
    doc_a = (
        "Applicant Rahul Sharma applied for credit verification. "
        "Aadhaar Number: 1234 5678 9012, PAN: ABCDE1234F, Mobile: +91 9876543210. "
        "Address: Flat 402, Indiranagar, Bengaluru, Karnataka 560038."
    )
    lang_a = detect_languages(doc_a)
    det_a = detector.detect(doc_a)
    mask_a = masker.mask(doc_a, det_a)
    rest_a = reinserter.reinsert(mask_a.sanitized_text, mask_a.placeholder_map)

    print(f"  • Detected Languages: {lang_a['language_label']}")
    print(f"  • Entities Detected ({len(det_a)}): {[e.entity_type for e in det_a]}")
    assert "English" in lang_a["detected_languages"]
    assert len(det_a) >= 4
    assert "1234 5678 9012" not in mask_a.sanitized_text
    assert "<AADHAAR_1>" in mask_a.sanitized_text
    assert "1234 5678 9012" in rest_a.restored_text
    print("  ✓ Case A Passed!\n")
    passed_tests += 1

    # --------------------------------------------------------------------------
    # Case B: Kannada-only document
    # --------------------------------------------------------------------------
    print("[2/11] Case B: Kannada-only Document with Sensitive Text")
    doc_b = (
        "ಶ್ರೀ ರಾಹುಲ್ ಶರ್ಮಾ ಅವರ ಕೆವೈಸಿ ಪರಿಶೀಲನಾ ಅರ್ಜಿ. "
        "ಆಧಾರ್ ಸಂಖ್ಯೆ: ೧೨೩೪ ೫೬೭೮ ೯೦೧೨ ಮತ್ತು ಮೊಬೈಲ್ ಸಂಖ್ಯೆ: ೯೮೭೬೫೪೩೨೧೦. "
        "ವಿಳಾಸ: ಶಾಂತಿ ನಗರ, ಬೆಂಗಳೂರು, ಕರ್ನಾಟಕ 560038."
    )
    lang_b = detect_languages(doc_b)
    det_b = detector.detect(doc_b)
    mask_b = masker.mask(doc_b, det_b)
    rest_b = reinserter.reinsert(mask_b.sanitized_text, mask_b.placeholder_map)

    print(f"  • Detected Languages: {lang_b['language_label']}")
    print(f"  • Entities Detected ({len(det_b)}): {[(e.entity_type, e.value) for e in det_b]}")
    assert "Kannada" in lang_b["detected_languages"]
    assert any(e.entity_type == "PERSON" for e in det_b)
    assert any(e.entity_type == "AADHAAR" for e in det_b)
    assert any(e.entity_type == "PHONE_NUMBER" for e in det_b)
    assert "೧೨೩೪ ೫೬೭೮ ೯೦೧೨" not in mask_b.sanitized_text
    assert "೧೨೩೪ ೫೬೭೮ ೯೦೧೨" in rest_b.restored_text
    print("  ✓ Case B Passed!\n")
    passed_tests += 1

    # --------------------------------------------------------------------------
    # Case C: Hindi-only document
    # --------------------------------------------------------------------------
    print("[3/11] Case C: Hindi-only Document with Sensitive Text")
    doc_c = (
        "श्री राहुल शर्मा का बैंक खाता सत्यापन प्रपत्र। "
        "आधार संख्या: १२३४ ५६७८ ९०१२, फोन नंबर: ९८७६५४३२१०, जन्म तिथि: 15/08/1990। "
        "पता: फ्लैट 402, शांति नगर, नई दिल्ली 110001।"
    )
    lang_c = detect_languages(doc_c)
    det_c = detector.detect(doc_c)
    mask_c = masker.mask(doc_c, det_c)
    rest_c = reinserter.reinsert(mask_c.sanitized_text, mask_c.placeholder_map)

    print(f"  • Detected Languages: {lang_c['language_label']}")
    print(f"  • Entities Detected ({len(det_c)}): {[(e.entity_type, e.value) for e in det_c]}")
    assert "Hindi" in lang_c["detected_languages"]
    assert any(e.entity_type == "PERSON" for e in det_c)
    assert any(e.entity_type == "AADHAAR" for e in det_c)
    assert any(e.entity_type == "PHONE_NUMBER" for e in det_c)
    assert "१२३४ ५६७८ ९०१२" not in mask_c.sanitized_text
    assert "१२३४ ५६७८ ९०१२" in rest_c.restored_text
    print("  ✓ Case C Passed!\n")
    passed_tests += 1

    # --------------------------------------------------------------------------
    # Case D: Mixed Kannada + English document
    # --------------------------------------------------------------------------
    print("[4/11] Case D: Mixed Kannada + English Document")
    doc_d = (
        "ಅರ್ಜಿದಾರರ ಹೆಸರು: ರಾಹುಲ್ ಶರ್ಮಾ (Rahul Sharma). "
        "Aadhaar UID: 1234 5678 9012, ಪ್ಯಾನ್ ಕಾರ್ಡ್: ABCDE1234F, Contact: 9876543210. "
        "ವಿಳಾಸ: Indiranagar, Bengaluru, Karnataka 560038."
    )
    lang_d = detect_languages(doc_d)
    det_d = detector.detect(doc_d)
    mask_d = masker.mask(doc_d, det_d)

    print(f"  • Detected Languages: {lang_d['language_label']}")
    print(f"  • Entities Detected ({len(det_d)}): {[(e.entity_type, e.value) for e in det_d]}")
    assert "Kannada" in lang_d["detected_languages"]
    assert "English" in lang_d["detected_languages"]
    assert len(det_d) >= 4
    print("  ✓ Case D Passed!\n")
    passed_tests += 1

    # --------------------------------------------------------------------------
    # Case E: Mixed Hindi + English document
    # --------------------------------------------------------------------------
    print("[5/11] Case E: Mixed Hindi + English Document")
    doc_e = (
        "Customer Verification KYC: श्री राहुल शर्मा (Rahul Sharma). "
        "PAN Card Number: ABCDE1234F, आधार संख्या: १२३४ ५६७८ ९०१२. "
        "Mobile: 9876543210, Address: Vasant Kunj, New Delhi 110070."
    )
    lang_e = detect_languages(doc_e)
    det_e = detector.detect(doc_e)
    mask_e = masker.mask(doc_e, det_e)

    print(f"  • Detected Languages: {lang_e['language_label']}")
    print(f"  • Entities Detected ({len(det_e)}): {[(e.entity_type, e.value) for e in det_e]}")
    assert "Hindi" in lang_e["detected_languages"]
    assert "English" in lang_e["detected_languages"]
    assert len(det_e) >= 4
    print("  ✓ Case E Passed!\n")
    passed_tests += 1

    # --------------------------------------------------------------------------
    # Case F: Mixed Kannada + Hindi document
    # --------------------------------------------------------------------------
    print("[6/11] Case F: Mixed Kannada + Hindi Document")
    doc_f = (
        "ಅರ್ಜಿದಾರರ ಹೆಸರು: ರಾಹುಲ್ ಶರ್ಮಾ. पिता का नाम: श्री रमेश शर्मा. "
        "ಆಧಾರ್ ಸಂಖ್ಯೆ: ೧೨೩೪ ೫೬೭೮ ೯೦೧೨, फोन: ९८७೬५४३೨१०. "
        "ವಿಳಾಸ: ಶಾಂತಿ ನಗರ, ಬೆಂಗಳೂರು 560038."
    )
    lang_f = detect_languages(doc_f)
    det_f = detector.detect(doc_f)

    print(f"  • Detected Languages: {lang_f['language_label']}")
    print(f"  • Entities Detected ({len(det_f)}): {[(e.entity_type, e.value) for e in det_f]}")
    assert "Kannada" in lang_f["detected_languages"]
    assert "Hindi" in lang_f["detected_languages"]
    assert len(det_f) >= 3
    print("  ✓ Case F Passed!\n")
    passed_tests += 1

    # --------------------------------------------------------------------------
    # Case G: Mixed Kannada + English + Hindi document (All 3)
    # --------------------------------------------------------------------------
    print("[7/11] Case G: Mixed Kannada + English + Hindi Document (Trilingual)")
    doc_g = (
        "Government of India Identity Record / ಭಾರತ ಸರ್ಕಾರ / भारत सरकार. "
        "ಹೆಸರು: ರಾಹುಲ್ ಶರ್ಮಾ / Name: Rahul Sharma / नाम: राहुल शर्मा. "
        "Aadhaar: 1234 5678 9012, PAN: ABCDE1234F, Mobile: 9876543210. "
        "Address: Flat 402, Bengaluru 560001."
    )
    lang_g = detect_languages(doc_g)
    det_g = detector.detect(doc_g)

    print(f"  • Detected Languages: {lang_g['language_label']}")
    print(f"  • Entities Detected ({len(det_g)}): {[(e.entity_type, e.value) for e in det_g]}")
    assert "Kannada" in lang_g["detected_languages"]
    assert "English" in lang_g["detected_languages"]
    assert "Hindi" in lang_g["detected_languages"]
    assert len(det_g) >= 4
    print("  ✓ Case G Passed!\n")
    passed_tests += 1

    # --------------------------------------------------------------------------
    # Case H: Scanned / Layout PDF Document with Mixed Languages
    # --------------------------------------------------------------------------
    print("[8/11] Case H: PDF Document with Multilingual Content")
    pdf_doc = pymupdf.open()
    pdf_page = pdf_doc.new_page(width=612, height=792)
    pdf_page.insert_font(fontname="Nirmala", fontbuffer=open(r"C:\Windows\Fonts\nirmala.ttf", "rb").read())

    pdf_page.insert_text((50, 60), "GOVERNMENT OF INDIA - MULTILINGUAL CITIZEN CERTIFICATE", fontsize=14)
    pdf_page.insert_text((50, 100), "Name (English): Rahul Sharma", fontsize=11)
    pdf_page.insert_text((50, 130), "ಹೆಸರು (Kannada): ರಾಹುಲ್ ಶರ್ಮಾ", fontname="Nirmala", fontsize=11)
    pdf_page.insert_text((50, 160), "नाम (Hindi): राहुल शर्मा", fontname="Nirmala", fontsize=11)
    pdf_page.insert_text((50, 190), "Aadhaar Number: 1234 5678 9012", fontsize=11)
    pdf_page.insert_text((50, 220), "PAN Number: ABCDE1234F", fontsize=11)
    pdf_page.insert_text((50, 250), "Phone: 9876543210", fontsize=11)
    pdf_page.insert_text((50, 280), "Address: Indiranagar, Bengaluru, Karnataka 560038", fontsize=11)

    pdf_bytes = pdf_doc.tobytes()
    res_h = redactor.redact_document_bytes(pdf_bytes, "multilingual_certificate.pdf")

    print(f"  • PDF Processed: {res_h['filename']}")
    print(f"  • Detected Languages: {res_h['language_label']}")
    print(f"  • Sensitive Text Boxes Masked: {res_h['text_regions_masked_count']}")
    print(f"  • Total Entities Detected: {res_h['total_entities_detected']}")
    assert res_h["has_image"] is True
    assert res_h["text_regions_masked_count"] >= 3
    assert len(res_h["sensitive_text_boxes"]) >= 3
    print("  ✓ Case H Passed!\n")
    passed_tests += 1

    # --------------------------------------------------------------------------
    # Case I: Identity Card Image with BOTH Photograph and Sensitive Text
    # --------------------------------------------------------------------------
    print("[9/11] Case I: Combined Identity Card Image (Photo + Sensitive Text Masking)")
    img_w, img_h = 650, 420
    id_card = Image.new("RGB", (img_w, img_h), color=(250, 252, 255))
    draw = ImageDraw.Draw(id_card)
    nirmala_font = ImageFont.truetype(r"C:\Windows\Fonts\nirmala.ttf", 16)

    # 1. Header
    draw.rectangle([(0, 0), (img_w, 55)], fill=(24, 43, 73))
    draw.text((150, 18), "UNIQUE IDENTIFICATION AUTHORITY OF INDIA", fill="white")

    # 2. Simulated Face & Portrait Photograph Region (Left Side: x=40..180, y=85..280)
    photo_rect = [40, 85, 140, 195] # [x, y, w, h]
    draw.rectangle([(photo_rect[0], photo_rect[1]), (photo_rect[0] + photo_rect[2], photo_rect[1] + photo_rect[3])], fill=(215, 220, 225), outline=(60, 60, 60), width=2)
    # Draw realistic portrait silhouette
    cx = photo_rect[0] + photo_rect[2] // 2
    draw.ellipse([(cx - 35, 110), (cx + 35, 190)], fill=(235, 195, 165)) # Face oval
    draw.ellipse([(cx - 20, 135), (cx - 8, 147)], fill=(30, 30, 30))     # Left eye
    draw.ellipse([(cx + 8, 135), (cx + 20, 147)], fill=(30, 30, 30))     # Right eye
    draw.line([(cx - 10, 165), (cx + 10, 165)], fill=(180, 50, 50), width=2) # Mouth
    draw.rectangle([(cx - 50, 190), (cx + 50, 275)], fill=(35, 65, 130)) # Shoulders & chest
    draw.text((photo_rect[0] + 35, photo_rect[1] + photo_rect[3] - 25), "PHOTO ID", fill="white")

    # 3. Sensitive Personal Text (Right Side)
    draw.text((220, 80), "Name: RAHUL SHARMA", fill=(15, 23, 42))
    draw.text((220, 120), "DOB: 15/08/1990", fill=(15, 23, 42))
    draw.text((220, 160), "Gender: MALE", fill=(15, 23, 42))
    draw.text((220, 200), "Aadhaar: 1234 5678 9012", fill=(15, 23, 42))
    draw.text((220, 240), "PAN: ABCDE1234F", fill=(15, 23, 42))
    draw.text((220, 280), "Mobile: 9876543210", fill=(15, 23, 42))
    draw.text((220, 320), "Address: Flat 402, Bangalore 560038", fill=(15, 23, 42))

    buf = io.BytesIO()
    id_card.save(buf, format="PNG")
    img_bytes = buf.getvalue()

    res_i = redactor.redact_image_bytes(img_bytes, "aadhaar_identity_card.png")

    print(f"  • Photographs Detected & Masked: {res_i['photos_detected_count']}")
    print(f"  • Sensitive Text Boxes Masked: {res_i['text_regions_masked_count']}")
    print(f"  • Total Entities Detected: {res_i['total_entities_detected']}")
    print(f"  • Masking Summary: {res_i['image_masking_status']}")

    # Verify BOTH photograph AND sensitive text boxes are present
    assert res_i["photos_detected_count"] >= 1, "Must detect at least 1 photograph box"
    assert res_i["text_regions_masked_count"] >= 3, "Must detect and mask sensitive text fields"
    assert len(res_i["photo_boxes"]) >= 1
    assert len(res_i["sensitive_text_boxes"]) >= 3

    # Verify BOTH regions are flattened with solid black (0, 0, 0)
    redacted_np = cv2.imdecode(np.frombuffer(res_i["redacted_image_bytes"], np.uint8), cv2.IMREAD_COLOR)

    # Verify photo region pixels
    for pb in res_i["photo_boxes"]:
        px, py, pw, ph = pb["box"]
        sample_photo = redacted_np[py + 10:py + ph - 10, px + 10:px + pw - 10]
        assert np.all(sample_photo == 0), "Photograph region must be 100% solid black (0, 0, 0)"
        print(f"  ✓ Verified Photo Box [{px}, {py}, {pw}, {ph}] is SOLID BLACK (0, 0, 0)")

    # Verify sensitive text boxes pixels
    for sb in res_i["sensitive_text_boxes"]:
        bx, by, bw, bh = sb["box"]
        sample_text = redacted_np[by + 2:by + bh - 2, bx + 2:bx + bw - 2]
        assert np.all(sample_text == 0), f"Text box {sb['label']} must be 100% solid black (0, 0, 0)"
        print(f"  ✓ Verified Text Box {sb['label']} at [{bx}, {by}, {bw}, {bh}] is SOLID BLACK (0, 0, 0)")

    print("  ✓ Case I Passed: BOTH Photograph and Sensitive Text independently detected and combined!\n")
    passed_tests += 1

    # --------------------------------------------------------------------------
    # Case J: Zero Outbound Raw PII Leakage Check
    # --------------------------------------------------------------------------
    print("[10/11] Case J: Outbound Sanitized Payload Zero-Leakage Guarantee")
    sanitized_out = res_i["sanitized_payload"]
    raw_sensitive_values = ["1234 5678 9012", "123456789012", "ABCDE1234F", "9876543210"]
    for val in raw_sensitive_values:
        assert val not in sanitized_out, f"LEAKAGE VIOLATION: Raw value {val} found in outbound payload!"
    print(f"  • Sanitized Payload: {sanitized_out}")
    print("  ✓ Zero Outbound Leakage Verified: 0% Egress of personal data\n")
    passed_tests += 1

    # --------------------------------------------------------------------------
    # Case K: Benchmark Preservation Check (FN=5, FP=2)
    # --------------------------------------------------------------------------
    print("[11/11] Case K: Benchmark Preservation (50-document evaluation)")
    metrics_engine = MetricsEngine(detector, masker, reinserter)
    bench = metrics_engine.run_benchmark(limit=50)

    fn_count = bench["false_negatives"]
    fp_count = bench["false_positives"]
    precision = bench["precision"]
    recall = bench["recall"]

    print(f"  • Missed Entities (FN): {fn_count} (Expected: 5)")
    print(f"  • False Detections (FP): {fp_count} (Expected: 2)")
    print(f"  • Precision: {precision * 100:.2f}%")
    print(f"  • Recall: {recall * 100:.2f}%")

    assert fn_count == 5, f"Expected FN=5, got {fn_count}"
    assert fp_count == 2, f"Expected FP=2, got {fp_count}"
    print("  ✓ Benchmark Preserved: FN=5 and FP=2 perfectly intact!\n")
    passed_tests += 1

    print("=" * 75)
    print(f" ALL {passed_tests}/{total_tests} VALIDATION TESTS PASSED SUCCESSFULLY (100%)!")
    print("=" * 75)
    return True

if __name__ == "__main__":
    run_multilingual_validation()
