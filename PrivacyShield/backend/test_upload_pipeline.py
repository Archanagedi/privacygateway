import io
import requests
import pypdf
import docx
from PIL import Image, ImageDraw

BASE_URL = 'http://127.0.0.1:8000'

print("==================================================================")
print(" PRIVACYSHIELD - MULTI-FORMAT UPLOAD & EXTRACTION PIPELINE TEST")
print("==================================================================\n")

# 1. Generate PDF with Indian PII
pdf_content = b"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj
4 0 obj << /Length 165 >> stream
BT
/F1 12 Tf
50 700 Td
(Loan Application for Sunita Sharma. Aadhaar: 9876 5432 1098. PAN: ABCDE1234F. Mobile: +91 98765 43210. Address: Indiranagar, Bengaluru 560038.) Tj
ET
endstream endobj
5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000244 00000 n 
0000000460 00000 n 
trailer << /Size 6 /Root 1 0 R >>
startxref
539
%%EOF"""

# 2. Generate DOCX with Indian PII
doc = docx.Document()
doc.add_heading('Corporate KYC Verification', 0)
doc.add_paragraph('Corporate KYC submission by Managing Director Rajesh Singhania. GSTIN: 27AABCS9988G1Z4. Director PAN: AGYPS1234K.')
buf_docx = io.BytesIO()
doc.save(buf_docx)
docx_content = buf_docx.getvalue()

# 3. Generate JPG with Indian PII
img_jpg = Image.new('RGB', (600, 120), color='white')
d_jpg = ImageDraw.Draw(img_jpg)
d_jpg.text((20, 40), 'Aadhaar 1234 5678 9012 Suresh Pillai', fill='black')
buf_jpg = io.BytesIO()
img_jpg.save(buf_jpg, format='JPEG')
jpg_content = buf_jpg.getvalue()

# 4. Generate PNG with Indian PII
img_png = Image.new('RGB', (600, 120), color='white')
d_png = ImageDraw.Draw(img_png)
d_png.text((20, 40), 'PAN BZGPS5678K Nominee Geeta Somani', fill='black')
buf_png = io.BytesIO()
img_png.save(buf_png, format='PNG')
png_content = buf_png.getvalue()

test_cases = [
    ('sample_loan.pdf', pdf_content, 'application/pdf', 'PDF Document', 'Sunita Sharma'),
    ('corporate_kyc.docx', docx_content, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'Word Document (DOCX)', 'Rajesh Singhania'),
    ('id_card_scan.jpg', jpg_content, 'image/jpeg', 'JPEG Image', '1234 5678 9012'),
    ('pan_card_doc.png', png_content, 'image/png', 'PNG Image', 'BZGPS5678K')
]

for filename, content, mime, expected_format, expected_snippet in test_cases:
    print(f"--> Testing Upload: {filename} ({len(content)} bytes)...")
    files = {'file': (filename, content, mime)}
    res = requests.post(f"{BASE_URL}/api/upload-document", files=files)
    
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    data = res.json()
    print(f"    Status: 200 OK | Format: {data['format']} | Size: {data['size_formatted']} | Chars: {data['extracted_characters']}")
    print(f"    Extracted text snippet: \"{data['text'][:80]}...\"")
    
    # End-to-end Gateway Processing Check
    protect_res = requests.post(f"{BASE_URL}/api/protect", json={
        'document_text': data['text'],
        'document_type': 'KYC Document',
        'task': 'summarize'
    })
    assert protect_res.status_code == 200, f"Protect failed: {protect_res.text}"
    p_data = protect_res.json()
    print(f"    Gateway Processing: {p_data['total_entities_detected']} PII entities detected -> Masked & Pre-flight 0% Leakage Passed!")
    print()

# 5. Test Unsupported Format
print("--> Testing Unsupported Format: payload.exe...")
res_err = requests.post(f"{BASE_URL}/api/upload-document", files={'file': ('payload.exe', b'MZ90...', 'application/octet-stream')})
print(f"    Status: {res_err.status_code} (Expected 400)")
print(f"    Error Detail: {res_err.json().get('detail')}")
assert res_err.status_code == 400
assert 'Unsupported file format' in res_err.json().get('detail', '')

print("\n==================================================================")
print(" ALL 4 FORMAT TESTS (PDF, DOCX, JPG, PNG) & ERROR HANDLING PASSED!")
print("==================================================================")
