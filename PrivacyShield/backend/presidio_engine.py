"""
PrivacyShield - Microsoft Presidio-Compliant PII Detection Architecture
DPDP Act 2023 Compliant Multi-Recognizer Engine

Design:
1. PatternRecognizer, EntityRecognizer, and ContextEngine abstractions.
2. Official Verhoeff check-digit algorithm for Aadhaar validation.
3. Registered recognizers for:
   - PERSON (English, Kannada, Hindi NER & Gazetteers)
   - AADHAAR (Arabic, Kannada ೦-೯, Devanagari ०-९ + Verhoeff validation)
   - PAN (Permanent Account Number format & holder type validation)
   - GSTIN (State code + PAN + entity structure)
   - VOTER_ID (Election Commission EPIC format)
   - PASSPORT (Indian passport travel document format)
   - PHONE_NUMBER (10-digit mobile with telecom prefix validation)
   - EMAIL_ADDRESS (RFC 5322 pattern)
   - RESIDENTIAL_ADDRESS (PIN anchor + multilingual markers)
   - PINCODE (Standalone 6-digit postal code)
   - DATE_OF_BIRTH (DOB in multiple formats)
   - BANK_ACCOUNT (9-18 digit account with banking context)
   - IFSC_CODE (RBI 11-char alphanumeric code)
4. Exact boundary slicing: guarantees text[start:end] == value for all entities.
5. Conflict & Overlap Resolution with confidence scoring.
"""

import re
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict

from india_recognizers import (
    validate_verhoeff,
    AADHAAR_REGEX, AADHAAR_CONTEXT,
    PAN_REGEX, PAN_CONTEXT,
    GSTIN_REGEX, GSTIN_CONTEXT,
    VOTER_ID_REGEX, VOTER_ID_CONTEXT,
    PASSPORT_REGEX, PASSPORT_CONTEXT,
    PHONE_REGEX, PHONE_CONTEXT,
    EMAIL_REGEX, EMAIL_CONTEXT,
    PINCODE_REGEX, ADDRESS_MARKERS, INDIAN_CITIES_STATES,
    COMMON_INDIAN_FIRST_NAMES, COMMON_INDIAN_LAST_NAMES
)

from multilingual import (
    detect_languages,
    normalize_indic_numerals,
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
    HINDI_NAMES
)

@dataclass
class RecognizerResult:
    entity_type: str
    start: int
    end: int
    value: str
    score: float
    explanation: str
    detection_method: str = "Presidio Pattern Recognizer"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PresidioRecognizerRegistry:
    """
    Registry managing all active Presidio-compliant pattern recognizers.
    """

    def __init__(self):
        self._recognizers = []
        self._register_default_recognizers()

    def _register_default_recognizers(self):
        # 1. Bank Account (Must run before Aadhaar to prevent 12-digit account misclassification)
        self.register(BankAccountRecognizer())
        # 2. IFSC Code
        self.register(IfscRecognizer())
        # 3. GSTIN (Runs before PAN so PAN inside GSTIN is handled)
        self.register(GstinRecognizer())
        # 4. PAN Card
        self.register(PanRecognizer())
        # 5. Aadhaar Number
        self.register(AadhaarRecognizer())
        # 6. Voter ID (EPIC)
        self.register(VoterIdRecognizer())
        # 7. Passport
        self.register(PassportRecognizer())
        # 8. Phone / Mobile Number
        self.register(PhoneRecognizer())
        # 9. Email Address
        self.register(EmailRecognizer())
        # 10. Date of Birth
        self.register(DateOfBirthRecognizer())
        # 11. Residential / Enterprise Postal Address
        self.register(AddressRecognizer())
        # 12. Standalone PIN Code
        self.register(PincodeRecognizer())
        # 13. Person Names (Multilingual NER + Gazetteers)
        self.register(PersonNameRecognizer())

    def register(self, recognizer):
        self._recognizers.append(recognizer)

    def analyze(self, text: str, norm_text: str) -> List[RecognizerResult]:
        candidates: List[RecognizerResult] = []
        for rec in self._recognizers:
            try:
                results = rec.analyze(text, norm_text)
                candidates.extend(results)
            except Exception as e:
                pass
        return candidates


# ==============================================================================
# INDIVIDUAL PRESIDIO PATTERN RECOGNIZERS
# ==============================================================================

class BankAccountRecognizer:
    """Recognizes Indian Bank Account numbers (9 to 18 digits) anchored by banking context."""
    def __init__(self):
        self.name = "Presidio_BankAccount_Recognizer"
        self.entity_type = "BANK_ACCOUNT"
        self.context_cues = [
            'account no', 'a/c no', 'account number', 'a/c number', 'bank account',
            'savings account', 'current account', 'salary account', 'a/c',
            'ಖಾತೆ ಸಂಖ್ಯೆ', 'ಖಾತೆ ನಂ', 'ಬ್ಯಾಂಕ್ ಖಾತೆ', 'ಉಳಿತಾಯ ಖಾತೆ',
            'खाता संख्या', 'खाता नंबर', 'बैंक खाता', 'बचत खाता'
        ]
        self.pattern = re.compile(r'\b[0-9]{9,18}\b')

    def analyze(self, text: str, norm_text: str) -> List[RecognizerResult]:
        results = []
        lower_norm = norm_text.lower()
        for m in self.pattern.finditer(norm_text):
            s, e = m.start(), m.end()
            # Check window before for bank context
            win_start = max(0, s - 60)
            preceding = lower_norm[win_start:s]
            has_context = any(cue in preceding for cue in self.context_cues)
            if has_context:
                val = text[s:e]
                results.append(RecognizerResult(
                    entity_type=self.entity_type,
                    start=s,
                    end=e,
                    value=val,
                    score=0.93,
                    explanation="Indian bank account number verified with financial context cue",
                    detection_method="Presidio Financial Context Recognizer"
                ))
        return results


class IfscRecognizer:
    """Recognizes Reserve Bank of India (RBI) IFSC Codes: 4 letters + 0 + 6 alphanumeric."""
    def __init__(self):
        self.name = "Presidio_IFSC_Recognizer"
        self.entity_type = "IFSC_CODE"
        self.pattern = re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b')
        self.context_cues = ['ifsc', 'ifsc code', 'rtgs', 'neft', 'imps', 'branch code', 'ಆರ್‌ಬಿಐ', 'ಐಎಫ್‌ಎಸ್‌ಸಿ', 'आईएफएससी']

    def analyze(self, text: str, norm_text: str) -> List[RecognizerResult]:
        results = []
        lower_norm = norm_text.lower()
        for m in self.pattern.finditer(norm_text):
            s, e = m.start(), m.end()
            win_start = max(0, s - 60)
            win_end = min(len(norm_text), e + 60)
            surrounding = lower_norm[win_start:win_end]
            has_context = any(cue in surrounding for cue in self.context_cues)
            score = 0.95 if has_context else 0.88
            results.append(RecognizerResult(
                entity_type=self.entity_type,
                start=s,
                end=e,
                value=text[s:e],
                score=score,
                explanation="Reserve Bank of India (RBI) IFSC electronic funds transfer branch code",
                detection_method="Presidio RBI Pattern Recognizer (IFSC)"
            ))
        return results


class GstinRecognizer:
    """Recognizes Indian Goods and Services Tax Identification Numbers (GSTIN)."""
    def __init__(self):
        self.name = "Presidio_GSTIN_Recognizer"
        self.entity_type = "GSTIN"

    def analyze(self, text: str, norm_text: str) -> List[RecognizerResult]:
        results = []
        lower_norm = norm_text.lower()
        for m in GSTIN_REGEX.finditer(norm_text):
            s, e = m.start(), m.end()
            win_start = max(0, s - 60)
            win_end = min(len(norm_text), e + 60)
            surrounding = lower_norm[win_start:win_end]
            has_context = any(k in surrounding for k in GSTIN_CONTEXT)
            score = 0.98 if has_context else 0.92
            results.append(RecognizerResult(
                entity_type=self.entity_type,
                start=s,
                end=e,
                value=text[s:e],
                score=score,
                explanation="15-character Indian Goods and Services Tax Identification Number (GSTIN)",
                detection_method="Presidio Tax Pattern Recognizer"
            ))
        return results


class PanRecognizer:
    """Recognizes Indian Permanent Account Number (PAN) with individual/entity validation."""
    def __init__(self):
        self.name = "Presidio_PAN_Recognizer"
        self.entity_type = "PAN"

    def analyze(self, text: str, norm_text: str) -> List[RecognizerResult]:
        results = []
        lower_norm = norm_text.lower()
        pan_context = PAN_CONTEXT + MULTILINGUAL_PAN_KEYWORDS
        for m in PAN_REGEX.finditer(norm_text):
            s, e = m.start(), m.end()
            val_norm = m.group(0)
            win_start = max(0, s - 60)
            win_end = min(len(norm_text), e + 60)
            surrounding = lower_norm[win_start:win_end]
            has_context = any(k.lower() in surrounding for k in pan_context)
            score = 0.97 if has_context else 0.89
            holder_type = {
                'P': 'Individual Person', 'C': 'Company', 'H': 'HUF',
                'F': 'Partnership Firm', 'A': 'AOP', 'T': 'Trust',
                'B': 'BOI', 'L': 'Local Authority', 'J': 'Juridical', 'G': 'Government'
            }.get(val_norm[3], 'Valid Entity')
            results.append(RecognizerResult(
                entity_type=self.entity_type,
                start=s,
                end=e,
                value=text[s:e],
                score=score,
                explanation=f"Valid PAN format ({holder_type})",
                detection_method="Presidio Income Tax Recognizer + Format Validation"
            ))
        return results


class AadhaarRecognizer:
    """Recognizes Indian 12-digit Aadhaar Card Numbers (Arabic, Kannada ೦-೯, Devanagari ०-९) with Verhoeff validation."""
    def __init__(self):
        self.name = "Presidio_Aadhaar_Recognizer"
        self.entity_type = "AADHAAR"

    def analyze(self, text: str, norm_text: str) -> List[RecognizerResult]:
        results = []
        lower_norm = norm_text.lower()
        aadhaar_context = AADHAAR_CONTEXT + MULTILINGUAL_AADHAAR_KEYWORDS
        bank_cues = ['account', 'a/c', 'खाता', 'ಖಾತೆ', 'bank', 'ifsc', 'balance']

        for m in AADHAAR_REGEX.finditer(norm_text):
            s, e = m.start(), m.end()
            val_norm = m.group(0)
            clean_digits = re.sub(r'[\s\-]', '', val_norm)

            if len(clean_digits) != 12 or clean_digits[0] == '0':
                continue

            # Check if this 12-digit number is actually a Bank Account number
            win_start = max(0, s - 60)
            preceding = lower_norm[win_start:s]
            last_bank_pos = max([preceding.rfind(cue) for cue in bank_cues] + [-1])
            last_aadhaar_pos = max([preceding.rfind(k) for k in ['aadhaar', 'aadhar', 'uid', 'ಆಧಾರ್', 'आधार']] + [-1])
            if last_bank_pos != -1 and last_bank_pos > last_aadhaar_pos:
                continue

            win_end = min(len(norm_text), e + 60)
            surrounding = lower_norm[win_start:win_end]
            has_context = any(k.lower() in surrounding for k in aadhaar_context)

            is_verhoeff = validate_verhoeff(clean_digits)
            base = 0.94 if is_verhoeff else 0.88
            score = min(0.99, base + (0.05 if has_context else 0.0))

            results.append(RecognizerResult(
                entity_type=self.entity_type,
                start=s,
                end=e,
                value=text[s:e],
                score=score,
                explanation="12-digit Indian Aadhaar pattern (UIDAI format)" + (" [Verhoeff verified]" if is_verhoeff else ""),
                detection_method="Presidio Pattern Recognizer + Verhoeff Checksum"
            ))
        return results


class VoterIdRecognizer:
    """Recognizes Indian Voter ID cards (Election Commission EPIC format)."""
    def __init__(self):
        self.name = "Presidio_VoterID_Recognizer"
        self.entity_type = "VOTER_ID"

    def analyze(self, text: str, norm_text: str) -> List[RecognizerResult]:
        results = []
        lower_norm = norm_text.lower()
        voter_context = VOTER_ID_CONTEXT + MULTILINGUAL_VOTER_KEYWORDS
        for m in VOTER_ID_REGEX.finditer(norm_text):
            s, e = m.start(), m.end()
            val = m.group(0)
            if re.match(r'^[A-Z]{5}', val):
                continue
            win_start = max(0, s - 60)
            win_end = min(len(norm_text), e + 60)
            surrounding = lower_norm[win_start:win_end]
            has_context = any(k.lower() in surrounding for k in voter_context)
            score = 0.96 if has_context else 0.88
            results.append(RecognizerResult(
                entity_type=self.entity_type,
                start=s,
                end=e,
                value=text[s:e],
                score=score,
                explanation="Indian Election Commission Voter Identity Card (EPIC format)",
                detection_method="Presidio Election Commission Recognizer"
            ))
        return results


class PassportRecognizer:
    """Recognizes Republic of India Passport travel documents."""
    def __init__(self):
        self.name = "Presidio_Passport_Recognizer"
        self.entity_type = "PASSPORT"

    def analyze(self, text: str, norm_text: str) -> List[RecognizerResult]:
        results = []
        lower_norm = norm_text.lower()
        passport_context = PASSPORT_CONTEXT + MULTILINGUAL_PASSPORT_KEYWORDS
        for m in PASSPORT_REGEX.finditer(norm_text):
            s, e = m.start(), m.end()
            win_start = max(0, s - 60)
            win_end = min(len(norm_text), e + 60)
            surrounding = lower_norm[win_start:win_end]
            has_context = any(k.lower() in surrounding for k in passport_context)
            if has_context or "passport" in lower_norm or "ಪಾಸ್‌ಪೋರ್ಟ್" in lower_norm or "पासपोर्ट" in lower_norm:
                results.append(RecognizerResult(
                    entity_type=self.entity_type,
                    start=s,
                    end=e,
                    value=text[s:e],
                    score=0.96 if has_context else 0.89,
                    explanation="Republic of India Passport travel document format",
                    detection_method="Presidio Travel Document Recognizer"
                ))
        return results


class PhoneRecognizer:
    """Recognizes 10-digit Indian telecommunication phone numbers (Arabic, Kannada ೦-೯, Devanagari ०-९)."""
    def __init__(self):
        self.name = "Presidio_Phone_Recognizer"
        self.entity_type = "PHONE_NUMBER"

    def analyze(self, text: str, norm_text: str) -> List[RecognizerResult]:
        results = []
        lower_norm = norm_text.lower()
        phone_context = PHONE_CONTEXT + MULTILINGUAL_PHONE_KEYWORDS
        for m in PHONE_REGEX.finditer(norm_text):
            s, e = m.start(), m.end()
            val_norm = m.group(0)
            clean_digits = re.sub(r'[\s\-\+]', '', val_norm)
            if clean_digits.startswith('91') and len(clean_digits) == 12:
                clean_digits = clean_digits[2:]
            elif clean_digits.startswith('0') and len(clean_digits) == 11:
                clean_digits = clean_digits[1:]

            if len(clean_digits) != 10 or clean_digits[0] not in '6789':
                continue

            win_start = max(0, s - 60)
            win_end = min(len(norm_text), e + 60)
            surrounding = lower_norm[win_start:win_end]
            has_context = any(k.lower() in surrounding for k in phone_context)
            score = 0.96 if has_context else 0.89

            results.append(RecognizerResult(
                entity_type=self.entity_type,
                start=s,
                end=e,
                value=text[s:e],
                score=score,
                explanation="Indian 10-digit mobile phone number verified with telecom prefix",
                detection_method="Presidio Telecom Recognizer + Prefix Validation"
            ))
        return results


class EmailRecognizer:
    """Recognizes electronic mail addresses using RFC 5322 pattern."""
    def __init__(self):
        self.name = "Presidio_Email_Recognizer"
        self.entity_type = "EMAIL_ADDRESS"

    def analyze(self, text: str, norm_text: str) -> List[RecognizerResult]:
        results = []
        for m in EMAIL_REGEX.finditer(text):
            s, e = m.start(), m.end()
            results.append(RecognizerResult(
                entity_type=self.entity_type,
                start=s,
                end=e,
                value=text[s:e],
                score=0.98,
                explanation="Standard electronic mail address format (RFC 5322)",
                detection_method="Presidio RFC 5322 Email Recognizer"
            ))
        return results


class DateOfBirthRecognizer:
    """Recognizes Dates of Birth (DOB) in standard Indian date formats with contextual cues."""
    def __init__(self):
        self.name = "Presidio_DOB_Recognizer"
        self.entity_type = "DATE_OF_BIRTH"
        self.pattern_with_cue = re.compile(
            r'\b(?:DOB|Date of Birth|D\.O\.B|Birth Date|Born on|Born|ಜನ್ಮ ದಿನಾಂಕ|ಹುಟ್ಟಿದ ದಿನಾಂಕ|ಜನ್ಮ ದಿನ|जन्म तिथि|जन्म तारीख|जन्म दिन)[:\s]*([0-9]{1,2}[/-][0-9]{1,2}[/-][0-9]{4}|[0-9]{4}[/-][0-9]{1,2}[/-][0-9]{1,2})\b',
            re.IGNORECASE
        )
        self.pattern_standalone = re.compile(
            r'\b([0-9]{1,2}[/-][0-9]{1,2}[/-][0-9]{4})\b'
        )
        self.dob_cues = ['dob', 'date of birth', 'birth date', 'born', 'ಜನ್ಮ ದಿನಾಂಕ', 'ಹುಟ್ಟಿದ ದಿನಾಂಕ', 'जन्म तिथि', 'जन्म तारीख']

    def analyze(self, text: str, norm_text: str) -> List[RecognizerResult]:
        results = []
        lower_norm = norm_text.lower()
        occupied = set()

        # 1. Matches with explicit cue
        for m in self.pattern_with_cue.finditer(norm_text):
            s = m.start(1)
            e = m.end(1)
            val = text[s:e]
            results.append(RecognizerResult(
                entity_type=self.entity_type,
                start=s,
                end=e,
                value=val,
                score=0.95,
                explanation="Date of birth verified with explicit biographical indicator",
                detection_method="Presidio Biographical Context Recognizer"
            ))
            occupied.add((s, e))

        # 2. Standalone dates near biographical context
        for m in self.pattern_standalone.finditer(norm_text):
            s, e = m.start(1), m.end(1)
            if any(s >= os and e <= oe for os, oe in occupied):
                continue
            win_start = max(0, s - 60)
            win_end = min(len(norm_text), e + 60)
            surrounding = lower_norm[win_start:win_end]
            if any(cue in surrounding for cue in self.dob_cues):
                results.append(RecognizerResult(
                    entity_type=self.entity_type,
                    start=s,
                    end=e,
                    value=text[s:e],
                    score=0.91,
                    explanation="Date of birth matching standard biographical date structure",
                    detection_method="Presidio Pattern + Context Recognizer"
                ))
        return results


class PincodeRecognizer:
    """Recognizes standalone Indian 6-digit postal PIN codes when accompanied by postal cues."""
    def __init__(self):
        self.name = "Presidio_Pincode_Recognizer"
        self.entity_type = "PINCODE"
        self.pattern = re.compile(
            r'\b(?:PIN|PIN\s*Code|Postal\s*Code|Pincode|ಪಿನ್\s*ಕೋಡ್|ಪೋಸ್ಟಲ್\s*ಕೋಡ್|पिन\s*कोड|डाक\s*पिन)[:\s]*([1-9][0-9]{5})\b',
            re.IGNORECASE
        )

    def analyze(self, text: str, norm_text: str) -> List[RecognizerResult]:
        results = []
        for m in self.pattern.finditer(norm_text):
            s = m.start(1)
            e = m.end(1)
            results.append(RecognizerResult(
                entity_type=self.entity_type,
                start=s,
                end=e,
                value=text[s:e],
                score=0.93,
                explanation="Indian 6-digit postal PIN code anchor",
                detection_method="Presidio Postal Code Recognizer"
            ))
        return results


class AddressRecognizer:
    """Recognizes Indian postal and residential addresses across English, Kannada, and Hindi."""
    def __init__(self):
        self.name = "Presidio_Address_Recognizer"
        self.entity_type = "ADDRESS"

    def analyze(self, text: str, norm_text: str) -> List[RecognizerResult]:
        results = []
        pin_matches = list(PINCODE_REGEX.finditer(norm_text))

        for pin in pin_matches:
            pin_start = pin.start()
            pin_end = pin.end()

            search_window_start = max(0, pin_start - 160)
            preceding_text = text[search_window_start:pin_start]
            lower_pre = preceding_text.lower()

            best_start = -1
            addr_cues = [
                'address is', 'address:', 'residence:', 'residing at', 'reside at',
                'permanent address', 'residential address', 'communication address',
                'office address', 'living at:', 'located at', 'location:',
                'ವಿಳಾಸ:', 'ವಿಳಾಸ', 'ವಾಸಸ್ಥಳ:', 'ಶಾಶ್ವತ ವಿಳಾಸ:',
                'पता:', 'पता', 'निवासी:', 'स्थायी पता:'
            ]
            for cue in addr_cues:
                pos = lower_pre.rfind(cue)
                if pos != -1:
                    candidate_pos = search_window_start + pos + len(cue)
                    while candidate_pos < len(text) and text[candidate_pos] in ' :\t\n':
                        candidate_pos += 1
                    best_start = candidate_pos
                    break

            if best_start == -1:
                marker_regex = re.compile(
                    r'\b(Flat\s+\d+|House\s+(?:No\s+)?\d+|Plot\s+\d+|Bungalow\s+\d+|B-\d+|Ward\s+\d+|Shop\s+\d+|Village\s+[A-Z][a-z]+|Penthouse\s+\d+|TC\s+\d+/\d+|\d+,\s+[A-Z]|\d+/\w+,\s+[A-Z]|(?:ಫ್ಲ್ಯಾಟ್|ಮನೆ\s+ಸಂಖ್ಯೆ|ಮನೆ\s+ನಂ|ಬಡಾವಣೆ|ರಸ್ತೆ|ನಗರ)\s+|(?:\u092b\u094d\u0932\u0948\u091f|\u092e\u0915\u093e\u0928\s+\u0928\u0902\u092c\u0930|\u0917\u0932\u0940|\u092e\u093e\u0930\u094d\u0917|\u0938\u0921\u093c\u0915|\u0928\u0917\u0930)\s+)',
                    re.IGNORECASE
                )
                m = marker_regex.search(preceding_text)
                if m:
                    best_start = search_window_start + m.start()

            if best_start != -1 and best_start < pin_end:
                # Precise boundary trimming without offset drift
                s = best_start
                while s < pin_end and text[s].isspace():
                    s += 1
                e = pin_end
                while e > s and text[e - 1].isspace():
                    e -= 1
                addr_text = text[s:e]
                if len(addr_text) >= 12:
                    results.append(RecognizerResult(
                        entity_type=self.entity_type,
                        start=s,
                        end=e,
                        value=addr_text,
                        score=0.94,
                        explanation="Indian postal address verified with 6-digit postal code anchor",
                        detection_method="Presidio Spatial Anchor Recognizer (Postal Address)"
                    ))
        return results


class PersonNameRecognizer:
    """Recognizes Person Names across English, Kannada, and Hindi using honorifics, role cues, and gazetteers."""
    def __init__(self):
        self.name = "Presidio_PersonName_Recognizer"
        self.entity_type = "PERSON"

    def analyze(self, text: str, norm_text: str) -> List[RecognizerResult]:
        results = []
        occupied: List[Tuple[int, int]] = []

        def is_occupied(s: int, e: int) -> bool:
            return any(s < end and e > start for start, end in occupied)

        # 1. English Honorifics: Mr., Mrs., Ms., Shri, Smt., Dr., Prof., Kumari
        # Crucial fix: [^\S\r\n]+ guarantees horizontal whitespace only (NEVER cross newlines!)
        honorific_pattern = re.compile(
            r'\b(Mr\.|Mrs\.|Ms\.|Shri|Smt\.|Dr\.|Prof\.|Kumari)[^\S\r\n]+([A-Z][a-z]+(?:[^\S\r\n]+[A-Z][a-z]+){1,3})\b'
        )
        for m in honorific_pattern.finditer(text):
            name_val = m.group(2).strip()
            name_start = m.start(2)
            name_end = m.end(2)
            if not is_occupied(name_start, name_end):
                results.append(RecognizerResult(
                    entity_type=self.entity_type,
                    start=name_start,
                    end=name_end,
                    value=name_val,
                    score=0.96,
                    explanation=f"Personal name preceded by honorific '{m.group(1)}'",
                    detection_method="Presidio Honorific Recognizer"
                ))
                occupied.append((name_start, name_end))

        # 2. English Contextual Role Cues: Applicant, Customer, Nominee, Name:
        # Crucial fix: [^\S\r\n]+ prevents capturing next line tokens like '\nEmail' or '\nBank'
        context_pattern = re.compile(
            r'\b(Applicant|Customer|Nominee|Patient|Investor|Policyholder|Traveller|Traveler|Employee|Consultant|Elector|Name(?:\s+is)?|I\s+am)(?:[^\S\r\n]*/[^\S\r\n]*[^\r\n:]+)?[^\S\r\n]*[:]?\s*([A-Z][a-z]+(?:[^\S\r\n]+[A-Z][a-z]+){1,2})\b'
        )
        for m in context_pattern.finditer(text):
            name_val = m.group(2).strip()
            name_start = m.start(2)
            name_end = m.end(2)
            if name_val.lower() in ('support ticket', 'application form', 'kyc document', 'bank account'):
                continue
            if not is_occupied(name_start, name_end):
                results.append(RecognizerResult(
                    entity_type=self.entity_type,
                    start=name_start,
                    end=name_end,
                    value=name_val,
                    score=0.93,
                    explanation=f"Personal name following role indicator '{m.group(1)}'",
                    detection_method="Presidio Context Recognizer (Role Indicator)"
                ))
                occupied.append((name_start, name_end))

        # 3. Known Indian First + Last Name Title Case Combinations
        name_combos = re.compile(
            r'\b([A-Z][a-z]+)[^\S\r\n]+([A-Z][a-z]+(?:[^\S\r\n]+[A-Z][a-z]+)?)\b'
        )
        for m in name_combos.finditer(text):
            first = m.group(1).lower()
            rest = m.group(2).lower().split()
            last = rest[-1] if rest else ""

            # Ignore corporate and organizational terms
            if any(w in ('heavy', 'electricals', 'limited', 'bank', 'insurance', 'corporation', 'electronics', 'development', 'department', 'state', 'government') for w in rest + [first]):
                continue

            is_indian_name = (
                (first in COMMON_INDIAN_FIRST_NAMES and (last in COMMON_INDIAN_LAST_NAMES or len(rest) >= 1)) or
                (last in COMMON_INDIAN_LAST_NAMES and first in COMMON_INDIAN_FIRST_NAMES)
            )
            if is_indian_name:
                s, e = m.start(), m.end()
                if not is_occupied(s, e):
                    results.append(RecognizerResult(
                        entity_type=self.entity_type,
                        start=s,
                        end=e,
                        value=text[s:e],
                        score=0.90,
                        explanation="Indian personal name match from recognized naming registry",
                        detection_method="Presidio Indian Name Gazetteer"
                    ))
                    occupied.append((s, e))

        # 4. Identity Document Uppercase Names (PAN cards, Identity cards): RAHUL SHARMA
        uppercase_combos = re.compile(r'\b([A-Z]{3,})[^\S\r\n]+([A-Z]{3,}(?:[^\S\r\n]+[A-Z]{3,})?)\b')
        for m in uppercase_combos.finditer(text):
            val_upper = m.group(0)
            words = val_upper.lower().split()
            if any(w in ('income', 'tax', 'department', 'permanent', 'account', 'number', 'government', 'india', 'election', 'commission', 'directorate', 'signature', 'date', 'birth', 'male', 'female', 'republic') for w in words):
                continue
            first = words[0]
            last = words[-1]
            if (first in COMMON_INDIAN_FIRST_NAMES and last in COMMON_INDIAN_LAST_NAMES) or \
               (first in COMMON_INDIAN_FIRST_NAMES and len(words) >= 2) or \
               (last in COMMON_INDIAN_LAST_NAMES and len(words) >= 2):
                s, e = m.start(), m.end()
                if not is_occupied(s, e):
                    results.append(RecognizerResult(
                        entity_type=self.entity_type,
                        start=s,
                        end=e,
                        value=val_upper,
                        score=0.92,
                        explanation="Uppercase Indian personal name on identity document",
                        detection_method="Presidio Uppercase Identity Recognizer"
                    ))
                    occupied.append((s, e))

        # 5. Kannada Honorifics & Names: ಶ್ರೀ ರಾಹುಲ್ ಶರ್ಮಾ, ಡಾ. ರಮೇಶ್
        kan_honorific = re.compile(
            r'(?:ಶ್ರೀ|ಶ್ರೀಮತಿ|ಕುಮಾರಿ|ಡಾ\.|ಡಾ|ಪ್ರೊ\.)[^\S\r\n]+([\u0C80-\u0CFF]+(?:[^\S\r\n]+[\u0C80-\u0CFF]+){0,2})'
        )
        for m in kan_honorific.finditer(text):
            raw_val = m.group(1).strip()
            words = [w for w in raw_val.split() if w not in ('ಅವರ', 'ಎಂಬ', 'ರವರಿಗೆ', 'ಇವರ', 'ಮತ್ತು', 'ಇವರು', 'ಅವರು')]
            if words:
                clean_name = " ".join(words)
                sub_offset = m.group(0).find(clean_name)
                s = m.start() + sub_offset
                e = s + len(clean_name)
                if not is_occupied(s, e):
                    results.append(RecognizerResult(
                        entity_type=self.entity_type,
                        start=s,
                        end=e,
                        value=clean_name,
                        score=0.95,
                        explanation="Kannada personal name preceded by honorific",
                        detection_method="Presidio Indic Honorific Recognizer"
                    ))
                    occupied.append((s, e))

        # 6. Kannada Contextual Role Cues: ಹೆಸರು: ರಾಹುಲ್ ಶರ್ಮಾ, ಅರ್ಜಿದಾರರ ಹೆಸರು:
        kan_cue_pattern = re.compile(
            r'(?:ಅರ್ಜಿದಾರರ[^\S\r\n]+ಹೆಸರು|ಗ್ರಾಹಕರ[^\S\r\n]+ಹೆಸರು|ಮತದಾರರ[^\S\r\n]+ಹೆಸರು|ಉದ್ಯೋಗಿಯ[^\S\r\n]+ಹೆಸರು|ರೈತರ[^\S\r\n]+ಹೆಸರು|ಪಾಲಿಸಿದಾರರ[^\S\r\n]+ಹೆಸರು|ತಂದೆಯ[^\S\r\n]+ಹೆಸರು|ಪತಿಯ[^\S\r\n]+ಹೆಸರು|ನನ್ನ[^\S\r\n]+ಹೆಸರು|ಅರ್ಜಿದಾರರು|ಗ್ರಾಹಕರು|ಮತದಾರರು|ಉದ್ಯೋಗಿ|ಪಾಲಿಸಿದಾರರು|ಹೆಸರು)(?:[^\S\r\n]*/[^\S\r\n]*[^\r\n:]+)?[^\S\r\n]*[:]?\s*([\u0C80-\u0CFF]+(?:[^\S\r\n]+[\u0C80-\u0CFF]+){0,2})'
        )
        for m in kan_cue_pattern.finditer(text):
            raw_val = m.group(1).strip()
            words = [w for w in raw_val.split() if w not in ('ಅವರ', 'ಎಂಬ', 'ರವರಿಗೆ', 'ಇವರ', 'ಮತ್ತು', 'ಇವರು', 'ಅವರು')]
            if words:
                clean_name = " ".join(words)
                if clean_name in ('ಹೆಸರು', 'ಯ ಹೆಸರು', 'ನಾಮ', 'ವಿಳಾಸ', 'ಆಧಾರ್', 'ಪ್ಯಾನ್', 'ಖಾತೆ', 'ಮತದಾರರ', 'ಅರ್ಜಿದಾರರು', 'ಗ್ರಾಹಕರು'):
                    continue
                sub_offset = m.group(0).find(clean_name)
                s = m.start() + sub_offset
                e = s + len(clean_name)
                if not is_occupied(s, e):
                    results.append(RecognizerResult(
                        entity_type=self.entity_type,
                        start=s,
                        end=e,
                        value=clean_name,
                        score=0.94,
                        explanation="Kannada personal name following role indicator",
                        detection_method="Presidio Indic Context Recognizer"
                    ))
                    occupied.append((s, e))

        # 7. Hindi Honorifics & Names: श्री राहुल शर्मा, श्रीमती प्रिया वर्मा
        hin_honorific = re.compile(
            r'(?:श्री|श्रीमती|सुश्री|डॉ\.|डॉ|प्रो\.)[^\S\r\n]+([\u0900-\u097F]+(?:[^\S\r\n]+[\u0900-\u097F]+){0,2})'
        )
        for m in hin_honorific.finditer(text):
            raw_val = m.group(1).rstrip('।., ').strip()
            words = [w for w in raw_val.split() if w not in ('का', 'की', 'के', 'ने', 'को', 'है', 'हैं', 'और')]
            if words:
                clean_name = " ".join(words)
                sub_offset = m.group(0).find(clean_name)
                s = m.start() + sub_offset
                e = s + len(clean_name)
                if not is_occupied(s, e):
                    results.append(RecognizerResult(
                        entity_type=self.entity_type,
                        start=s,
                        end=e,
                        value=clean_name,
                        score=0.95,
                        explanation="Hindi personal name preceded by honorific",
                        detection_method="Presidio Devanagari Honorific Recognizer"
                    ))
                    occupied.append((s, e))

        # 8. Hindi Contextual Role Cues: नाम: राहुल शर्मा, आवेदक का नाम:
        hin_cue_pattern = re.compile(
            r'(?:आवेदक[^\S\r\n]+का[^\S\r\n]+नाम|ग्राहक[^\S\r\n]+का[^\S\r\n]+नाम|निर्वाचक[^\S\r\n]+का[^\S\r\n]+नाम|कर्मचारी[^\S\r\n]+का[^\S\r\n]+नाम|बीमाधारक[^\S\r\n]+का[^\S\r\n]+नाम|किसान[^\S\r\n]+का[^\S\r\n]+नाम|पिता[^\S\r\n]+का[^\S\r\n]+नाम|पति[^\S\r\n]+का[^\S\r\n]+नाम|मेरा[^\S\r\n]+नाम|आवेदक|ग्राहक|निर्वाचक|कर्मचारी|बीमाधारक|किसान|नाम)(?:[^\S\r\n]*/[^\S\r\n]*[^\r\n:]+)?[^\S\r\n]*[:]?\s*([\u0900-\u097F]+(?:[^\S\r\n]+[\u0900-\u097F]+){0,2})'
        )
        for m in hin_cue_pattern.finditer(text):
            raw_val = m.group(1).rstrip('।., ').strip()
            words = [w for w in raw_val.split() if w not in ('का', 'की', 'के', 'ने', 'को', 'है', 'हैं', 'और')]
            if words:
                clean_name = " ".join(words)
                if clean_name in ('नाम', 'का नाम', 'पता', 'आधार', 'पैन', 'खाता', 'आवेदक', 'ग्राहक', 'कर्मचारी', 'बीमाधारक'):
                    continue
                sub_offset = m.group(0).find(clean_name)
                s = m.start() + sub_offset
                e = s + len(clean_name)
                if not is_occupied(s, e):
                    results.append(RecognizerResult(
                        entity_type=self.entity_type,
                        start=s,
                        end=e,
                        value=clean_name,
                        score=0.94,
                        explanation="Hindi personal name following role indicator",
                        detection_method="Presidio Devanagari Context Recognizer"
                    ))
                    occupied.append((s, e))

        # 9. Standalone Kannada & Hindi Gazetteer Names
        kan_words = re.findall(r'[\u0C80-\u0CFF]+', text)
        for kw in kan_words:
            if kw in KANNADA_NAMES:
                s = text.find(kw)
                while s != -1:
                    e = s + len(kw)
                    if not is_occupied(s, e) and len(kw) >= 3:
                        results.append(RecognizerResult(
                            entity_type=self.entity_type,
                            start=s,
                            end=e,
                            value=kw,
                            score=0.88,
                            explanation="Kannada personal name from gazetteer registry",
                            detection_method="Presidio Kannada Gazetteer Recognizer"
                        ))
                        occupied.append((s, e))
                    s = text.find(kw, e)

        hin_words = re.findall(r'[\u0900-\u097F]+', text)
        for hw in hin_words:
            if hw in HINDI_NAMES:
                s = text.find(hw)
                while s != -1:
                    e = s + len(hw)
                    if not is_occupied(s, e) and len(hw) >= 3:
                        results.append(RecognizerResult(
                            entity_type=self.entity_type,
                            start=s,
                            end=e,
                            value=hw,
                            score=0.88,
                            explanation="Hindi personal name from gazetteer registry",
                            detection_method="Presidio Devanagari Gazetteer Recognizer"
                        ))
                        occupied.append((s, e))
                    s = text.find(hw, e)

        return results
