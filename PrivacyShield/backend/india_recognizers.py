"""
PrivacyShield - India-Specific PII Recognizers
Comprehensive regular expressions, validation checksums (Verhoeff for Aadhaar),
and contextual patterns for Indian personal and enterprise identifiers.
"""

import re
from typing import List, Dict, Any, Optional, Tuple

try:
    from multilingual import (
        MULTILINGUAL_AADHAAR_KEYWORDS,
        MULTILINGUAL_PAN_KEYWORDS,
        MULTILINGUAL_VOTER_KEYWORDS,
        MULTILINGUAL_PASSPORT_KEYWORDS,
        MULTILINGUAL_PHONE_KEYWORDS,
        MULTILINGUAL_HONORIFICS,
        MULTILINGUAL_NAME_CUES,
        MULTILINGUAL_ADDRESS_KEYWORDS,
        MULTILINGUAL_DOB_KEYWORDS,
        KANNADA_NAMES,
        HINDI_NAMES,
        normalize_indic_numerals
    )
except ImportError:
    MULTILINGUAL_AADHAAR_KEYWORDS = []
    MULTILINGUAL_PAN_KEYWORDS = []
    MULTILINGUAL_VOTER_KEYWORDS = []
    MULTILINGUAL_PASSPORT_KEYWORDS = []
    MULTILINGUAL_PHONE_KEYWORDS = []
    MULTILINGUAL_HONORIFICS = []
    MULTILINGUAL_NAME_CUES = []
    MULTILINGUAL_ADDRESS_KEYWORDS = []
    MULTILINGUAL_DOB_KEYWORDS = []
    KANNADA_NAMES = set()
    HINDI_NAMES = set()
    def normalize_indic_numerals(t): return t

# ==============================================================================
# VERHOEFF ALGORITHM (Official UIDAI checksum for Aadhaar validation)
# ==============================================================================
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
]

VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
]

VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]

def validate_verhoeff(num_str: str) -> bool:
    """Validates an Indian Aadhaar number using the official Verhoeff check-digit algorithm."""
    clean = re.sub(r'[\s\-]', '', num_str)
    if len(clean) != 12 or not clean.isdigit() or clean[0] in ('0', '1'):
        return False
    c = 0
    for i, item in enumerate(reversed(clean)):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][int(item)]]
    return c == 0


# ==============================================================================
# INDIAN IDENTIFIER PATTERNS & REGEX RECOGNIZERS
# ==============================================================================

# 1. Aadhaar Card Pattern (12 digits, spaced 4-4-4 or dashed or contiguous)
AADHAAR_REGEX = re.compile(
    r'\b[1-9]{1}[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b'
)

AADHAAR_CONTEXT = [
    'aadhaar', 'aadhar', 'uid', 'uidai', 'unique identification', 'adhaar',
    'mera aadhaar', 'aadhar card', 'aadhaar card', 'identity proof'
]

# 2. PAN (Permanent Account Number): 5 uppercase letters + 4 digits + 1 uppercase letter
PAN_REGEX = re.compile(
    r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'
)

PAN_CONTEXT = [
    'pan', 'pan card', 'permanent account number', 'income tax', 'nsdl',
    'utiitsl', 'taxpayer', 'form 16', 'pan no', 'pan number'
]

# 3. GSTIN (Goods and Services Tax Identification Number):
# 2-digit state code (01-38) + 10-char PAN + 1 entity code + Z + 1 check digit
GSTIN_REGEX = re.compile(
    r'\b(0[1-9]|[1-3][0-9])[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b'
)

GSTIN_CONTEXT = [
    'gst', 'gstin', 'goods and services tax', 'gst invoice', 'gst number',
    'tax identification', 'input tax credit', 'state code'
]

# 4. Voter ID (EPIC - Electors Photo Identity Card): 3 uppercase letters followed by 7 digits, or state format
VOTER_ID_REGEX = re.compile(
    r'\b(?:[A-Z]{3}[0-9]{7}|[A-Z]{2}/[0-9]{2}/[0-9]{3}/[0-9]{6})\b'
)

VOTER_ID_CONTEXT = [
    'voter', 'voter id', 'epic', 'election card', 'elector', 'eci',
    'voter card', 'election commission', 'voting identity'
]

# 5. Indian Passport: 1 uppercase letter followed by 7 digits (e.g., A1234567, K4567890)
PASSPORT_REGEX = re.compile(
    r'\b[A-PR-WYa-pr-wy][0-9]{7}\b'
)

PASSPORT_CONTEXT = [
    'passport', 'indian passport', 'republic of india', 'passport no',
    'passport number', 'travel document', 'visa', 'consular'
]

# 6. Indian Mobile / Phone Numbers: +91 or 0 followed by 10 digits starting with 6, 7, 8, 9
PHONE_REGEX = re.compile(
    r'(?:\+91[\s\-]?)?(?:0)?[6-9]\d{4}[\s\-]?\d{5}\b'
)

PHONE_CONTEXT = [
    'phone', 'mobile', 'tel', 'contact', 'cell', 'telephone', 'call',
    'mobile number', 'contact number', 'phone no'
]

# 6b. Email Addresses (RFC 5322 compliant pattern)
EMAIL_REGEX = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
)

EMAIL_CONTEXT = [
    'email', 'e-mail', 'mail', 'email address', 'contact email',
    'official email', 'personal email', 'electronic mail'
]

# 7. Indian PIN Codes (6 digits starting with 1-9)
PINCODE_REGEX = re.compile(
    r'\b[1-9][0-9]{2}[\s]?[0-9]{3}\b'
)

# 7b. Date of Birth (DOB) across English, Kannada, and Hindi
DOB_REGEX = re.compile(
    r'\b(?:DOB|Date of Birth|D\.O\.B|ಜನ್ಮ ದಿನಾಂಕ|ಹುಟ್ಟಿದ ದಿನಾಂಕ|ಜನ್ಮ ದಿನ|जन्म तिथि|जन्म तारीख|जन्म दिन)[:\s]*([0-9]{1,2}[/-][0-9]{1,2}[/-][0-9]{4})\b',
    re.IGNORECASE
)

DOB_CONTEXT = [
    'dob', 'date of birth', 'birth date', 'born on',
    'ಜನ್ಮ ದಿನಾಂಕ', 'ಹುಟ್ಟಿದ ದಿನಾಂಕ', 'ಜನ್ಮ ದಿನ',
    'जन्म तिथि', 'जन्म तारीख', 'जन्म दिन'
] + MULTILINGUAL_DOB_KEYWORDS

# Extend contexts with multilingual keywords
AADHAAR_CONTEXT.extend([k for k in MULTILINGUAL_AADHAAR_KEYWORDS if k not in AADHAAR_CONTEXT])
PAN_CONTEXT.extend([k for k in MULTILINGUAL_PAN_KEYWORDS if k not in PAN_CONTEXT])
VOTER_ID_CONTEXT.extend([k for k in MULTILINGUAL_VOTER_KEYWORDS if k not in VOTER_ID_CONTEXT])
PASSPORT_CONTEXT.extend([k for k in MULTILINGUAL_PASSPORT_KEYWORDS if k not in PASSPORT_CONTEXT])
PHONE_CONTEXT.extend([k for k in MULTILINGUAL_PHONE_KEYWORDS if k not in PHONE_CONTEXT])

# 8. Address Context Keywords & Markers
ADDRESS_MARKERS = [
    'flat', 'apartment', 'apt', 'room', 'house', 'plot', 'plot no', 'house no',
    'bldg', 'building', 'floor', 'tower', 'residency', 'enclave', 'vihar',
    'nagar', 'colony', 'marg', 'road', 'rd', 'street', 'lane', 'gali', 'sector',
    'phase', 'layout', 'cross', 'main', 'chowk', 'bazaar', 'market', 'tehsil',
    'district', 'village', 'vpo', 'post', 'po', 'taluk', 'taluka', 'near',
    'behind', 'opposite', 'opp', 'beside', 'adjacent'
]

INDIAN_CITIES_STATES = [
    'bengaluru', 'bangalore', 'mumbai', 'delhi', 'new delhi', 'kolkata', 'chennai',
    'hyderabad', 'pune', 'ahmedabad', 'surat', 'jaipur', 'lucknow', 'kanpur',
    'nagpur', 'indore', 'thane', 'bhopal', 'visakhapatnam', 'patna', 'vadodara',
    'ghaziabad', 'ludhiana', 'agra', 'nashik', 'faridabad', 'meerut', 'rajkot',
    'varanasi', 'srinagar', 'aurangabad', 'dhanbad', 'amritsar', 'navi mumbai',
    'allahabad', 'prayagraj', 'ranchi', 'howrah', 'coimbatore', 'jabalpur',
    'gwalior', 'vijayawada', 'jodhpur', 'madurai', 'raipur', 'kota', 'chandigarh',
    'guwahati', 'solapur', 'hubballi', 'mysuru', 'mysore', 'tiruchirappalli',
    'bareilly', 'aligarh', 'tiruppur', 'moradabad', 'jalandhar', 'bhubaneswar',
    'salem', 'warangal', 'mira-bhayandar', 'thiruvananthapuram', 'bhiwandi',
    'saharanpur', 'gorakhpur', 'guntur', 'bikaner', 'amravati', 'noida',
    'gurugram', 'gurgaon', 'kerala', 'karnataka', 'tamil nadu', 'maharashtra',
    'gujarat', 'rajasthan', 'uttar pradesh', 'madhya pradesh', 'west bengal',
    'punjab', 'haryana', 'bihar', 'odisha', 'andhra pradesh', 'telangana',
    'assam', 'jharkhand', 'chhattisgarh', 'uttarakhand', 'goa', 'himachal pradesh'
]

# 9. Indian Names - Honorifics and context indicators
INDIAN_HONORIFICS = [
    'mr', 'mr.', 'mrs', 'mrs.', 'ms', 'ms.', 'shri', 'shree', 'smt', 'smt.',
    'dr', 'dr.', 'prof', 'prof.', 'kumar', 'kumari', 'master', 'sri'
]

RELATION_CONTEXT = [
    's/o', 'd/o', 'w/o', 'c/o', 'son of', 'daughter of', 'wife of', 'care of',
    'applicant', 'applicant name', 'customer', 'customer name', 'nominee',
    'nominee name', 'policyholder', 'patient', 'investor', 'proprietor',
    'director', 'managing director', 'signatory', 'subscriber', 'traveller'
]

COMMON_INDIAN_FIRST_NAMES = set([
    'rahul', 'priya', 'amit', 'sneha', 'vikram', 'vikramaditya', 'lakshmi',
    'harpreet', 'rameshwar', 'ananya', 'karthik', 'sunita', 'alok', 'deepa',
    'rohan', 'meenakshi', 'rajesh', 'tanvi', 'arjun', 'kavita', 'manish',
    'suresh', 'ramachandra', 'sandeep', 'pooja', 'balwinder', 'divya', 'deepak',
    'shweta', 'gaurav', 'naresh', 'fatima', 'hemant', 'arvind', 'ritu',
    'ashwin', 'ashok', 'meghna', 'vinay', 'sunil', 'varun', 'geeta', 'siddharth',
    'bharat', 'sukhdev', 'sangeeta', 'rajeshwari', 'debabrata', 'pankaj',
    'bhupendra', 'nitesh', 'neha', 'sachin', 'anita', 'ajay', 'sanjay', 'manoj',
    'vijay', 'anil', 'dinesh', 'ramesh', 'mukesh', 'sunil', 'abhishek', 'vivek'
])

COMMON_INDIAN_LAST_NAMES = set([
    'sharma', 'nair', 'patel', 'kulkarni', 'singh', 'sundaram', 'dhillon',
    'yadav', 'mukherjee', 'venkatraman', 'devi', 'chawla', 'ranganathan',
    'deshmukh', 'singhania', 'agarwal', 'reddy', 'joshi', 'malhotra', 'pillai',
    'murthy', 'goyal', 'bhatia', 'swaminathan', 'verma', 'bhattacharya',
    'bansal', 'sheikh', 'chougule', 'swamy', 'saxena', 'padmanabhan', 'singhal',
    'sen', 'hegde', 'kapoor', 'somani', 'jain', 'mann', 'menon', 'subramanian',
    'das', 'mishra', 'vora', 'tiwari', 'gupta', 'rao', 'iyer', 'kumar', 'mehta',
    'shah', 'shukla', 'pandey', 'tripathi', 'choudhury', 'banerjee', 'chatterjee'
])


def score_with_context(
    text: str,
    start: int,
    end: int,
    context_words: List[str],
    base_score: float = 0.85,
    boost: float = 0.12,
    window: int = 60
) -> float:
    """Calculates context-aware confidence score by looking around the entity window."""
    window_start = max(0, start - window)
    window_end = min(len(text), end + window)
    surrounding = text[window_start:window_end].lower()

    for word in context_words:
        if word.lower() in surrounding:
            return min(0.99, base_score + boost)
    return base_score
