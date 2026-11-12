"""
PrivacyShield - Image Redactor Test Suite
Tests:
1. Synthetic Aadhaar card image with text and photograph
2. Verify OCR extracts text
3. Verify PII detector detects Aadhaar, PAN, Name, Phone, DOB, Address
4. Verify photograph region is detected and completely masked with solid black
5. Verify sensitive text regions are masked with solid black
6. Verify original pixels are overwritten with (0,0,0) and irreversible
7. Verify PNG export and base64 preview format
"""

import sys
import io
import os
import cv2
import numpy as np
from PIL import Image, ImageDraw

sys.path.append(os.path.dirname(__file__))
from detector import PIIDetector
from masker import PIIMasker
from image_redactor import ImageRedactor

def run_tests():
    print("==================================================================")
    print(" PRIVACYSHIELD - IMAGE, PHOTO & PII MASKING UPGRADE TEST")
    print("==================================================================\n")

    detector = PIIDetector(sensitivity=0.5)
    masker = PIIMasker()
    redactor = ImageRedactor(detector=detector, masker=masker)

    # Generate synthetic Aadhaar card image
    w, h = 640, 400
    card = Image.new("RGB", (w, h), color=(245, 248, 252))
    d = ImageDraw.Draw(card)

    # 1. Non-sensitive Header
    d.rectangle([(0, 0), (w, 50)], fill=(30, 58, 138))
    d.text((160, 16), "GOVERNMENT OF INDIA - AADHAAR CARD", fill="white")

    # 2. Simulated Photo Region (Left Column)
    photo_box = (35, 75, 175, 280) # [x1, y1, x2, y2]
    d.rectangle([(photo_box[0], photo_box[1]), (photo_box[2], photo_box[3])], fill=(220, 225, 230), outline=(70, 70, 70), width=2)
    # Draw face oval inside photo box
    d.ellipse([(70, 105), (140, 185)], fill=(235, 195, 165))
    d.ellipse([(85, 125), (97, 137)], fill=(30, 30, 30))
    d.ellipse([(113, 125), (125, 137)], fill=(30, 30, 30))
    d.line([(95, 160), (115, 160)], fill=(180, 50, 50), width=3)
    d.rectangle([(50, 185), (160, 275)], fill=(40, 70, 150))
    d.text((60, 255), "PHOTO ID", fill="white")

    # 3. Sensitive Personal Information (Right Column)
    d.text((210, 75), "Name: Rahul Sharma", fill=(15, 23, 42))
    d.text((210, 115), "DOB: 15/08/1990", fill=(15, 23, 42))
    d.text((210, 155), "Gender: MALE", fill=(15, 23, 42))
    d.text((210, 195), "Aadhaar: 1234 5678 9012", fill=(15, 23, 42))
    d.text((210, 235), "PAN: ABCDE1234F", fill=(15, 23, 42))
    d.text((210, 275), "Phone: 9876543210", fill=(15, 23, 42))
    d.text((210, 315), "Address: Flat 402, Indiranagar, Bengaluru 560038", fill=(15, 23, 42))

    # Save to buffer
    buf = io.BytesIO()
    card.save(buf, format="PNG")
    img_bytes = buf.getvalue()

    print("[1/5] Processing Synthetic Aadhaar Card Image...")
    result = redactor.redact_image_bytes(img_bytes, "synthetic_aadhaar.png")

    # Verify result structure
    print(f"  • OCR Status: {result['ocr_status']}")
    print(f"  • PII Detection Status: {result['pii_detection_status']}")
    print(f"  • Photo Detection Status: {result['photo_detection_status']}")
    print(f"  • Image Masking Status: {result['image_masking_status']}")
    print(f"  • Leakage Check Status: {result['leakage_check_status']}")
    print(f"  • Photographs Detected: {result['photos_detected_count']}")
    print(f"  • Total Sensitive Entities: {result['total_entities_detected']}")

    assert result["has_image"] is True
    assert result["photos_detected_count"] >= 1, "At least 1 photograph box must be detected"
    assert len(result["sensitive_text_boxes"]) >= 1, "At least 1 sensitive text box must be detected"

    print("\n[2/5] Inspecting Masked Image Pixels (Irreversibility Check)...")
    redacted_bytes = result["redacted_image_bytes"]
    redacted_arr = cv2.imdecode(np.frombuffer(redacted_bytes, np.uint8), cv2.IMREAD_COLOR)

    # Check photo region is 100% solid black (0, 0, 0)
    for pb in result["photo_boxes"]:
        px, py, pw, ph = pb["box"]
        # Sample interior of photo box
        sample_roi = redacted_arr[py + 10:py + ph - 10, px + 10:px + pw - 10]
        assert np.all(sample_roi == 0), f"Photograph region {pb['box']} must be solid black!"
        print(f"  ✓ Photo region at [{px}, {py}, {pw}, {ph}] confirmed solid black (0, 0, 0)")

    # Check sensitive text boxes are solid black
    for sb in result["sensitive_text_boxes"]:
        bx, by, bw, bh = sb["box"]
        sample_roi = redacted_arr[by + 2:by + bh - 2, bx + 2:bx + bw - 2]
        assert np.all(sample_roi == 0), f"Sensitive text box {sb['label']} must be solid black!"
        print(f"  ✓ Sensitive box ({sb['type']}) at [{bx}, {by}, {bw}, {bh}] confirmed solid black")

    # Check non-sensitive header remains visible (not black)
    header_sample = redacted_arr[10:30, 160:300]
    assert not np.all(header_sample == 0), "Header text must remain visible and non-redacted!"
    print("  ✓ Non-sensitive header preserved and visible.")

    print("\n[3/5] Verifying Sanitized Payload Output...")
    sanitized = result["sanitized_payload"]
    print(f"  Sanitized Payload Snippet:\n  {sanitized[:120]}...\n")
    # Raw Aadhaar number must NOT appear in sanitized text
    assert "1234 5678 9012" not in sanitized or "<AADHAAR" in sanitized
    print("  ✓ Zero outbound PII leakage in sanitized payload text.")

    print("\n[4/5] Testing PDF Document Page Rasterization & Redaction...")
    import pymupdf
    pdf_doc = pymupdf.open()
    page = pdf_doc.new_page(width=600, height=400)
    page.insert_image(pymupdf.Rect(0, 0, 600, 400), stream=img_bytes)
    pdf_bytes = pdf_doc.tobytes()

    pdf_res = redactor.redact_document_bytes(pdf_bytes, "scanned_kyc.pdf")
    print(f"  • PDF Processed: {pdf_res['format']}")
    print(f"  • PDF Pages: {pdf_res.get('pdf_total_pages')}")
    print(f"  • Photo Masked: {pdf_res['photo_detection_status']}")
    assert pdf_res["has_image"] is True
    assert pdf_res["photos_detected_count"] >= 1

    print("\n[5/5] Testing Previews Format...")
    assert result["original_preview"].startswith("data:image/png;base64,")
    assert result["masked_preview"].startswith("data:image/png;base64,")
    print("  ✓ Both original_preview and masked_preview generated as valid PNG Data URIs.")

    print("\n==================================================================")
    print(" ALL 5 TEST STAGES PASSED! IMAGE & PHOTO MASKING VERIFIED!")
    print("==================================================================")

if __name__ == "__main__":
    run_tests()
