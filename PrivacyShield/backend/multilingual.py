"""
PrivacyShield - Multilingual Language Integration Engine
Compliance: Digital Personal Data Protection (DPDP) Act, 2023

Capabilities:
1. Script & Language Detection for Kannada, Hindi (Devanagari), English (Latin), and Mixed-Language documents.
2. Indic Numeral Normalization (Kannada ೦-೯, Devanagari ०-९ to 0-9) preserving exact 1-to-1 character index offsets.
3. Multilingual PII keyword gazetteers and honorific dictionaries.
4. Multilingual OCR adapter with zero-leakage preservation.
"""

import re
import unicodedata
from typing import Dict, Any, List, Tuple, Set, Optional

# ==============================================================================
# UNICODE RANGES FOR SUPPORTED SCRIPTS
# ==============================================================================
# Kannada: U+0C80 - U+0CFF
KANNADA_RANGE = (0x0C80, 0x0CFF)
# Devanagari (Hindi): U+0900 - U+097F
DEVANAGARI_RANGE = (0x0900, 0x097F)
# Latin (English): A-Z, a-z
LATIN_RANGE_1 = (0x0041, 0x005A) # A-Z
LATIN_RANGE_2 = (0x0061, 0x007A) # a-z

# Indic Numerals Mapping Table
KANNADA_DIGITS = "೦೧೨೩೪೫೬೭೮೯"
DEVANAGARI_DIGITS = "०१२३४५६७८९"
ARABIC_DIGITS = "0123456789"

INDIC_TO_ARABIC_MAP = {
    # Kannada
    '೦': '0', '೧': '1', '೨': '2', '೩': '3', '೪': '4',
    '೫': '5', '೬': '6', '೭': '7', '೮': '8', '೯': '9',
    # Devanagari
    '०': '0', '१': '1', '२': '2', '३': '3', '४': '4',
    '५': '5', '६': '6', '७': '7', '८': '8', '९': '9'
}

INDIC_TO_ARABIC_TRANS = str.maketrans(
    "०१२३४५६७८९೦೧೨೩೪೫೬೭೮೯",
    "01234567890123456789"
)

def normalize_indic_numerals(text: str) -> str:
    """
    Normalizes Kannada and Devanagari numerals to standard Arabic digits (0-9).
    Crucially, because each Indic digit is a single Unicode code point,
    the normalized string maintains the EXACT character length and 1-to-1 index
    mapping with the original input text.
    """
    if not text:
        return ""
    return text.translate(INDIC_TO_ARABIC_TRANS)


# ==============================================================================
# MULTILINGUAL LANGUAGE DETECTOR
# ==============================================================================
def detect_languages(text: str) -> Dict[str, Any]:
    """
    Automatically detects the languages present in a document by analyzing
    script character distributions.
    Supports:
    - Kannada (ಕನ್ನಡ)
    - Hindi (हिन्दी)
    - English
    - Mixed: Kannada + English, Hindi + English, Kannada + Hindi, Kannada + Hindi + English
    """
    if not text or not text.strip():
        return {
            "primary_language": "English",
            "detected_languages": ["English"],
            "language_label": "English",
            "is_multilingual": False,
            "script_counts": {"kannada": 0, "hindi": 0, "english": 0, "other": 0}
        }

    kannada_count = 0
    devanagari_count = 0
    latin_count = 0
    other_count = 0

    for ch in text:
        cp = ord(ch)
        if 0x0C80 <= cp <= 0x0CFF:
            kannada_count += 1
        elif 0x0900 <= cp <= 0x097F:
            devanagari_count += 1
        elif (0x0041 <= cp <= 0x005A) or (0x0061 <= cp <= 0x007A):
            latin_count += 1
        elif not ch.isspace() and not ch.isdigit() and ch not in ".,:;-_/\\()[]{}'\"!?@#$%^&*+=<>~`|":
            other_count += 1

    total_script_chars = kannada_count + devanagari_count + latin_count
    detected: List[str] = []

    # Detection threshold: at least 3 script characters or >= 5% of script content
    kannada_present = kannada_count >= 3
    hindi_present = devanagari_count >= 3
    english_present = latin_count >= 5 or (latin_count > 0 and not kannada_present and not hindi_present)

    if kannada_present:
        detected.append("Kannada")
    if hindi_present:
        detected.append("Hindi")
    if english_present:
        detected.append("English")

    if not detected:
        detected = ["English"]

    # Determine primary language
    counts = [("Kannada", kannada_count), ("Hindi", devanagari_count), ("English", latin_count)]
    counts.sort(key=lambda x: x[1], reverse=True)
    primary = counts[0][0] if counts[0][1] > 0 else "English"

    is_multilingual = len(detected) > 1
    language_label = ", ".join(detected)

    return {
        "primary_language": primary,
        "detected_languages": detected,
        "language_label": language_label,
        "is_multilingual": is_multilingual,
        "script_counts": {
            "kannada": kannada_count,
            "hindi": devanagari_count,
            "english": latin_count,
            "other": other_count
        }
    }


# ==============================================================================
# MULTILINGUAL PII KEYWORDS & GAZETTEERS
# ==============================================================================

# 1. Aadhaar Keywords across Kannada, Hindi, English
MULTILINGUAL_AADHAAR_KEYWORDS = [
    # English
    'aadhaar', 'aadhar', 'uid', 'uidai', 'unique identification', 'adhaar',
    'mera aadhaar', 'aadhar card', 'aadhaar card', 'identity proof',
    # Kannada
    'ಆಧಾರ್', 'ಆಧಾರ್ ಸಂಖ್ಯೆ', 'ಆಧಾರ್ ಕಾರ್ಡ್', 'ಯುಐಡಿಎಐ', 'ವಿಶಿಷ್ಟ ಗುರುತು',
    'ಮೇರಾ ಆಧಾರ್', 'ಗುರುತಿನ ಚೀಟಿ', 'ಆಧಾರ್ ನಂ',
    # Hindi
    'आधार', 'आधार संख्या', 'आधार नंबर', 'आधार कार्ड', 'यूआईडीएआई', 'विशिष्ट पहचान',
    'मेरा आधार', 'पहचान पत्र', 'आधार कार्ड संख्या'
]

# 2. PAN Keywords across Kannada, Hindi, English
MULTILINGUAL_PAN_KEYWORDS = [
    # English
    'pan', 'pan card', 'permanent account number', 'income tax', 'nsdl',
    'utiitsl', 'taxpayer', 'form 16', 'pan no', 'pan number',
    # Kannada
    'ಪ್ಯಾನ್', 'ಪ್ಯಾನ್ ಕಾರ್ಡ್', 'ಶಾಶ್ವತ ಖಾತೆ ಸಂಖ್ಯೆ', 'ಆದಾಯ ತೆರಿಗೆ', 'ಪ್ಯಾನ್ ನಂ',
    # Hindi
    'पैन', 'पैन कार्ड', 'स्थायी खाता संख्या', 'आयकर', 'पैन नंबर', 'पैन कार्ड नंबर'
]

# 3. Voter ID Keywords across Kannada, Hindi, English
MULTILINGUAL_VOTER_KEYWORDS = [
    # English
    'voter', 'voter id', 'epic', 'election card', 'elector', 'eci',
    'voter card', 'election commission', 'voting identity',
    # Kannada
    'ಮತದಾರರ ಗುರುತಿನ ಚೀಟಿ', 'ಮತದಾರರ ಸಂಖ್ಯೆ', 'ಚುನಾವಣಾ ಕಾರ್ಡ್', 'ಎಪಿಕ್', 'ಮತದಾರ',
    # Hindi
    'मतदाता पहचान पत्र', 'मतदाता संख्या', 'चुनाव कार्ड', 'एपिक', 'मतदाता कार्ड', 'निर्वाचन'
]

# 4. Passport Keywords across Kannada, Hindi, English
MULTILINGUAL_PASSPORT_KEYWORDS = [
    # English
    'passport', 'indian passport', 'republic of india', 'passport no',
    'passport number', 'travel document', 'visa', 'consular',
    # Kannada
    'ಪಾಸ್‌ಪೋರ್ಟ್', 'ಪಾಸ್ಪೋರ್ಟ್', 'ಪಾಸ್‌ಪೋರ್ಟ್ ಸಂಖ್ಯೆ', 'ಭಾರತ ಗಣರಾಜ್ಯ',
    # Hindi
    'पासपोर्ट', 'पासपोर्ट संख्या', 'पासपोर्ट नंबर', 'भारत गणराज्य'
]

# 5. Phone / Mobile Keywords across Kannada, Hindi, English
MULTILINGUAL_PHONE_KEYWORDS = [
    # English
    'phone', 'mobile', 'tel', 'contact', 'cell', 'telephone', 'call',
    'mobile number', 'contact number', 'phone no',
    # Kannada
    'ದೂರವಾಣಿ', 'ದೂರವಾಣಿ ಸಂಖ್ಯೆ', 'ಮೊಬೈಲ್', 'ಮೊಬೈಲ್ ಸಂಖ್ಯೆ', 'ಸಂಪರ್ಕ ಸಂಖ್ಯೆ', 'ಫೋನ್',
    # Hindi
    'मोबाइल', 'मोबाइल नंबर', 'फोन', 'फोन नंबर', 'संपर्क नंबर', 'दूरभाष', 'संपर्क सूत्र'
]

# 6. Honorifics for Name Detection
MULTILINGUAL_HONORIFICS = [
    # English
    'mr', 'mr.', 'mrs', 'mrs.', 'ms', 'ms.', 'shri', 'shree', 'smt', 'smt.',
    'dr', 'dr.', 'prof', 'prof.', 'kumar', 'kumari', 'master', 'sri',
    # Kannada
    'ಶ್ರೀ', 'ಶ್ರೀಮತಿ', 'ಕುಮಾರಿ', 'ಡಾ.', 'ಡಾ', 'ಪ್ರೊ.', 'ಶ್ರೀಯುತ',
    # Hindi
    'श्री', 'श्रीमती', 'सुश्री', 'डॉ.', 'डॉ', 'प्रो.', 'श्रीमान', 'पं.', 'पंडित'
]

# 7. Name Context Indicators & Prefixes
MULTILINGUAL_NAME_CUES = [
    # English
    'name', 'applicant', 'customer', 'nominee', 'policyholder', 'patient',
    'investor', 'proprietor', 'traveller', 'father', 'husband', 'wife',
    # Kannada
    'ಹೆಸರು', 'ಅರ್ಜಿದಾರರ ಹೆಸರು', 'ಗ್ರಾಹಕರ ಹೆಸರು', 'ತಂದೆಯ ಹೆಸರು', 'ಪತಿಯ ಹೆಸರು',
    'ತಾಯಿಯ ಹೆಸರು', 'ಖಾತೆದಾರರ ಹೆಸರು', 'ನನ್ನ ಹೆಸರು',
    # Hindi
    'नाम', 'आवेदक का नाम', 'ग्राहक का नाम', 'पिता का नाम', 'पति का नाम',
    'माता का नाम', 'खाताधारक का नाम', 'मेरा नाम'
]

# 8. Address Keywords & Geographic Entities
MULTILINGUAL_ADDRESS_KEYWORDS = [
    # English
    'address', 'residence', 'residing at', 'flat', 'house', 'plot', 'apartment',
    'street', 'road', 'layout', 'cross', 'main', 'nagar', 'colony', 'bengaluru',
    'bangalore', 'mumbai', 'delhi', 'karnataka', 'pin', 'pincode',
    # Kannada
    'ವಿಳಾಸ', 'ಮನೆ ಸಂಖ್ಯೆ', 'ಮನೆ ನಂ', 'ಫ್ಲ್ಯಾಟ್', 'ಬಡಾವಣೆ', 'ರಸ್ತೆ', 'ಕ್ರಾಸ್',
    'ಮೇನ್', 'ನಗರ', 'ತಾಲ್ಲೂಕು', 'ಜಿಲ್ಲೆ', 'ಬೆಂಗಳೂರು', 'ಮೈಸೂರು', 'ಹುಬ್ಬಳ್ಳಿ',
    'ಮಂಗಳೂರು', 'ಬೆಳಗಾವಿ', 'ಕರ್ನಾಟಕ', 'ಪಿನ್ ಕೋಡ್', 'ಅಂಚೆ ಸಂಖ್ಯೆ',
    # Hindi
    'पता', 'मकान नंबर', 'मकान संख्या', 'फ्लैट', 'गली', 'मार्ग', 'सड़क',
    'नगर', 'कॉलोनी', 'सेक्टर', 'तहसील', 'जिला', 'नई दिल्ली', 'दिल्ली',
    'मुंबई', 'लखनऊ', 'जयपुर', 'कानपुर', 'उत्तर प्रदेश', 'मध्य प्रदेश', 'पिन कोड'
]

# 9. Date of Birth Keywords
MULTILINGUAL_DOB_KEYWORDS = [
    # English
    'dob', 'date of birth', 'birth date', 'born on',
    # Kannada
    'ಜನ್ಮ ದಿನಾಂಕ', 'ಹುಟ್ಟಿದ ದಿನಾಂಕ', 'ಜನ್ಮ ದಿನ',
    # Hindi
    'जन्म तिथि', 'जन्म तारीख', 'जन्म दिन'
]

# 10. Common Indian First & Last Names (Multilingual Representations)
KANNADA_NAMES = {
    'ರಾಹುಲ್', 'ಶರ್ಮಾ', 'ಸುರೇಶ್', 'ರಮೇಶ್', 'ಪ್ರಿಯಾ', 'ಕಾರ್ತಿಕ್', 'ವೆಂಕಟೇಶ್',
    'ಮಂಜುನಾಥ್', 'ಲಕ್ಷ್ಮೀ', 'ದೀಪಾ', 'ಅನನ್ಯ', 'ಸವಿತಾ', 'ಸುನಿತಾ', 'ಆನಂದ್',
    'ಪ್ರಕಾಶ್', 'ಕುಮಾರ್', 'ಗೌಡ', 'ಶೆಟ್ಟಿ', 'ರಾವ್', 'ಹೆಗಡೆ', 'ಭಟ್', 'ನಾಯಕ್',
    'ಕುಲಕರ್ಣಿ', 'ದೇಶಪಾಂಡೆ', 'ಜೋಶಿ', 'ಪಾಟೀಲ್', 'ರಾಘವೇಂದ್ರ', 'ವಿನಯ್', 'ಸುನಿಲ್',
    'ಅರ್ಜುನ್', 'ರಾಜೇಶ್', 'ಕವಿತಾ', 'ಸ್ನೇಹಾ', 'ಪೂಜಾ', 'ದಿವ್ಯಾ', 'ದೀಪಕ್'
}

HINDI_NAMES = {
    'राहुल', 'शर्मा', 'अमित', 'वर्मा', 'प्रिया', 'राजेश', 'गुप्ता', 'सिंह',
    'यादव', 'नेहा', 'पूजा', 'अनिल', 'सुनील', 'मनोज', 'विजय', 'संजय',
    'अशोक', 'अजय', 'राकेश', 'सुरेश', 'दिनेश', 'तिवारी', 'पांडेय', 'दुबे',
    'मिश्रा', 'चौधरी', 'विकास', 'दीपक', 'कवि', 'सुनीता', 'अनीता', 'रेखा',
    'किरण', 'सविता', 'संदीप', 'रोहित', 'आलोक', 'मनीष', 'गौरव', 'कविता'
}
