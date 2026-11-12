import urllib.request
import io
import json
from PIL import Image, ImageDraw

# Create image with photo and multilingual text
w, h = 600, 360
card = Image.new('RGB', (w, h), color=(245, 248, 252))
d = ImageDraw.Draw(card)
d.rectangle([(0, 0), (w, 45)], fill=(30, 58, 138))
d.text((160, 14), 'GOVERNMENT OF INDIA - MULTILINGUAL ID', fill='white')

# Photo box
photo_box = (35, 65, 175, 260)
d.rectangle([(photo_box[0], photo_box[1]), (photo_box[2], photo_box[3])], fill=(220, 225, 230), outline=(70, 70, 70), width=2)
d.ellipse([(70, 95), (140, 175)], fill=(235, 195, 165))
d.ellipse([(85, 115), (97, 127)], fill=(30, 30, 30))
d.ellipse([(113, 115), (125, 127)], fill=(30, 30, 30))
d.line([(95, 150), (115, 150)], fill=(180, 50, 50), width=3)
d.rectangle([(50, 175), (160, 255)], fill=(40, 70, 150))
d.text((60, 235), 'PHOTO ID', fill='white')

# Text
d.text((210, 70), 'Name: RAHUL SHARMA', fill=(15, 23, 42))
d.text((210, 110), 'DOB: 15/08/1990', fill=(15, 23, 42))
d.text((210, 150), 'Aadhaar: 1234 5678 9012', fill=(15, 23, 42))
d.text((210, 190), 'PAN: ABCDE1234F', fill=(15, 23, 42))
d.text((210, 230), 'Phone: 9876543210', fill=(15, 23, 42))
d.text((210, 270), 'Address: Indiranagar, Bengaluru 560038', fill=(15, 23, 42))

buf = io.BytesIO()
card.save(buf, format='PNG')
file_bytes = buf.getvalue()

boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
body = io.BytesIO()
body.write(f'--{boundary}\r\n'.encode())
body.write(b'Content-Disposition: form-data; name="file"; filename="multilingual_id_card.png"\r\n')
body.write(b'Content-Type: image/png\r\n\r\n')
body.write(file_bytes)
body.write(f'\r\n--{boundary}--\r\n'.encode())

req = urllib.request.Request(
    'http://127.0.0.1:8000/api/upload-document',
    data=body.getvalue(),
    headers={'Content-Type': f'multipart/form-data; boundary={boundary}'}
)
res = urllib.request.urlopen(req)
data = json.loads(res.read().decode())
print('Upload success:', data.get('success'))
print('Has image:', data.get('has_image'))
print('Detected languages:', data.get('detected_languages'))
print('Photos detected count:', data.get('photos_detected_count'))
print('Photos masked count:', data.get('photos_masked_count'))
print('Text regions masked count:', data.get('text_regions_masked_count'))
print('Total entities detected:', data.get('total_entities_detected'))
print('Image masking status:', data.get('image_masking_status'))
print('Leakage status:', data.get('leakage_check_status'))
