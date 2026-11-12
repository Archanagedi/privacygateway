"""
PrivacyShield - Local PII Detection Engine
Powered by Microsoft Presidio principles, custom India-specific recognizers,
and local contextual NER heuristics for Indian names and addresses.
All detection executes 100% locally on the host with zero network egress.
"""

import re
import os
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict

from india_recognizers import (
    AADHAAR_REGEX, AADHAAR_CONTEXT, validate_verhoeff,
    PAN_REGEX, PAN_CONTEXT,
    GSTIN_REGEX, GSTIN_CONTEXT,
    VOTER_ID_REGEX, VOTER_ID_CONTEXT,
    PASSPORT_REGEX, PASSPORT_CONTEXT,
    PHONE_REGEX, PHONE_CONTEXT,
    EMAIL_REGEX, EMAIL_CONTEXT,
    PINCODE_REGEX, ADDRESS_MARKERS, INDIAN_CITIES_STATES,
    INDIAN_HONORIFICS, RELATION_CONTEXT,
    COMMON_INDIAN_FIRST_NAMES, COMMON_INDIAN_LAST_NAMES,
    score_with_context,
    DOB_REGEX, DOB_CONTEXT
)
from multilingual import (
    detect_languages,
    normalize_indic_numerals,
    MULTILINGUAL_AADHAAR_KEYWORDS,
    MULTILINGUAL_PAN_KEYWORDS,
    MULTILINGUAL_PHONE_KEYWORDS,
    MULTILINGUAL_HONORIFICS,
    MULTILINGUAL_NAME_CUES,
    MULTILINGUAL_ADDRESS_KEYWORDS,
    KANNADA_NAMES,
    HINDI_NAMES
)
from presidio_engine import PresidioRecognizerRegistry

logger = logging.getLogger("PrivacyShield.Detector")
logger.setLevel(logging.INFO)

@dataclass
class DetectedEntity:
    entity_type: str
    start: int
    end: int
    value: str
    score: float
    explanation: str
    detection_method: str = "Presidio Pattern Recognizer"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PIIDetector:
    """
    Local privacy detection engine tailored for the Digital Personal Data
    Protection (DPDP) Act, 2023. Detects sensitive Indian PII identifiers.
    """

    def __init__(self, sensitivity: float = 0.5):
        self.sensitivity = sensitivity
        self.has_presidio_analyzer = True
        self.registry = PresidioRecognizerRegistry()
        self._init_presidio()

    def _init_presidio(self):
        """Initializes Presidio-compliant detection architecture."""
        logger.info("Presidio architecture & custom India recognizers active.")

    def detect(self, text: str) -> List[DetectedEntity]:
        """
        Runs comprehensive local detection for all sensitive Indian personal
        information entities across Kannada, Hindi, and English.
        Returns non-overlapping, confidence-ranked spans.
        """
        if not text or not text.strip():
            return []

        # 0. Multilingual numeral normalization (maintains 1-to-1 character index mapping)
        norm_text = normalize_indic_numerals(text)

        raw_candidates = self.registry.analyze(text, norm_text)

        candidates: List[DetectedEntity] = []
        for r in raw_candidates:
            candidates.append(DetectedEntity(
                entity_type=r.entity_type,
                start=r.start,
                end=r.end,
                value=r.value,
                score=r.score,
                explanation=r.explanation,
                detection_method=r.detection_method
            ))

        # Resolve overlapping spans, keeping highest scoring / longest entity
        filtered = self._resolve_overlaps(candidates)

        # Filter by threshold sensitivity
        result = [e for e in filtered if e.score >= self.sensitivity]
        result.sort(key=lambda x: x.start)
        return result

    def _detect_addresses(self, text: str, norm_text: Optional[str] = None) -> List[DetectedEntity]:
        """
        Detects Indian enterprise and residential addresses across English,
        Kannada, and Hindi by scanning for address markers, known cities,
        and 6-digit postal PIN codes (Arabic, Kannada, or Devanagari numerals).
        """
        if norm_text is None:
            norm_text = normalize_indic_numerals(text)

        entities: List[DetectedEntity] = []

        # Find postal PIN codes on normalized text
        pin_matches = list(PINCODE_REGEX.finditer(norm_text))

        for pin in pin_matches:
            pin_start = pin.start()
            pin_end = pin.end()

            # Search backwards up to 160 characters for address start markers
            search_window_start = max(0, pin_start - 160)
            preceding_text = text[search_window_start:pin_start]
            lower_pre = preceding_text.lower()

            best_start = -1

            # Check for address keywords across English, Kannada, and Hindi
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
                    # Strip leading whitespace/colons
                    while candidate_pos < len(text) and text[candidate_pos] in ' :\t\n':
                        candidate_pos += 1
                    best_start = candidate_pos
                    break

            # If no explicit cue, check for address markers like Flat, House, Plot, Ward, etc.
            if best_start == -1:
                marker_regex = re.compile(
                    r'\b(Flat\s+\d+|House\s+(?:No\s+)?\d+|Plot\s+\d+|Bungalow\s+\d+|B-\d+|Ward\s+\d+|Shop\s+\d+|Village\s+[A-Z][a-z]+|Penthouse\s+\d+|TC\s+\d+/\d+|\d+,\s+[A-Z]|\d+/\w+,\s+[A-Z]|(?:ಫ್ಲ್ಯಾಟ್|ಮನೆ\s+ಸಂಖ್ಯೆ|ಮನೆ\s+ನಂ|ಬಡಾವಣೆ|ರಸ್ತೆ|ನಗರ)\s+|(?:\u092b\u094d\u0932\u0948\u091f|\u092e\u0915\u093e\u0928\s+\u0928\u0902\u092c\u0930|\u0917\u0932\u0940|\u092e\u093e\u0930\u094d\u0917|\u0938\u0921\u093c\u0915|\u0928\u0917\u0930)\s+)',
                    re.IGNORECASE
                )
                m = marker_regex.search(preceding_text)
                if m:
                    best_start = search_window_start + m.start()

            if best_start != -1 and best_start < pin_end:
                addr_text = text[best_start:pin_end].strip()
                # Ensure address candidate is not too short and contains city/state or PIN
                if len(addr_text) >= 12:
                    score = 0.94
                    entities.append(DetectedEntity(
                        entity_type="ADDRESS",
                        start=best_start,
                        end=pin_end,
                        value=addr_text,
                        score=score,
                        explanation="Indian postal address verified with 6-digit postal code"
                    ))

        return entities

    def _detect_names(self, text: str, existing_entities: List[DetectedEntity]) -> List[DetectedEntity]:
        """
        Extracts personal names across English, Kannada, and Hindi using:
        1. Honorific prefixes (Mr., Shri, Smt., ಡಾ., ಶ್ರೀ, श्रीमती, etc.)
        2. Role & contextual cues (Name:, Applicant:, ಹೆಸರು:, नाम:, etc.)
        3. Identity card uppercase formats
        4. Multilingual name gazetteers (English, Kannada, Hindi)
        """
        names: List[DetectedEntity] = []
        occupied_spans = [(e.start, e.end) for e in existing_entities]

        def is_occupied(s: int, e: int) -> bool:
            return any(s < end and e > start for start, end in occupied_spans)

        # 1. Names preceded by English Honorifics: Dr., Mr., Mrs., Ms., Shri, Smt., etc.
        honorific_pattern = re.compile(
            r'\b(Mr\.|Mrs\.|Ms\.|Shri|Smt\.|Dr\.|Prof\.|Kumari)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b'
        )
        for m in honorific_pattern.finditer(text):
            name_val = m.group(2).strip()
            name_start = m.start(2)
            name_end = m.end(2)

            if not is_occupied(name_start, name_end):
                names.append(DetectedEntity(
                    entity_type="PERSON",
                    start=name_start,
                    end=name_end,
                    value=name_val,
                    score=0.95,
                    explanation=f"Personal name preceded by honorific '{m.group(1)}'"
                ))
                occupied_spans.append((name_start, name_end))

        # 2. English Contextual Names: "Applicant Rahul Sharma", "Customer Priya Nair", "Nominee Geeta Somani", "Name: X"
        context_pattern = re.compile(
            r'\b(Applicant|Customer|Nominee|Patient|Investor|Policyholder|Traveller|Name(?:\s+is)?|I\s+am)\s*[:]?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b'
        )
        for m in context_pattern.finditer(text):
            name_val = m.group(2).strip()
            name_start = m.start(2)
            name_end = m.end(2)

            if name_val.lower() in ('support ticket', 'application form', 'kyc document', 'bank account'):
                continue

            if not is_occupied(name_start, name_end):
                names.append(DetectedEntity(
                    entity_type="PERSON",
                    start=name_start,
                    end=name_end,
                    value=name_val,
                    score=0.92,
                    explanation=f"Personal name following role indicator '{m.group(1)}'"
                ))
                occupied_spans.append((name_start, name_end))

        # 3. Known Indian First + Last Name Combinations in Title Case
        name_combos = re.compile(
            r'\b([A-Z][a-z]+)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b'
        )
        for m in name_combos.finditer(text):
            first = m.group(1).lower()
            rest = m.group(2).lower().split()
            last = rest[-1] if rest else ""

            is_indian_name = (
                (first in COMMON_INDIAN_FIRST_NAMES and (last in COMMON_INDIAN_LAST_NAMES or len(rest) >= 1)) or
                (last in COMMON_INDIAN_LAST_NAMES and first in COMMON_INDIAN_FIRST_NAMES)
            )

            if is_indian_name:
                name_start = m.start()
                name_end = m.end()
                if not is_occupied(name_start, name_end):
                    names.append(DetectedEntity(
                        entity_type="PERSON",
                        start=name_start,
                        end=name_end,
                        value=m.group(0),
                        score=0.90,
                        explanation="Indian personal name match from recognized naming registry"
                    ))
                    occupied_spans.append((name_start, name_end))

        # 4. Identity Document Uppercase Names (PAN cards, Voter ID cards): RAHUL SHARMA
        uppercase_combos = re.compile(r'\b([A-Z]{3,})\s+([A-Z]{3,}(?:\s+[A-Z]{3,})?)\b')
        for m in uppercase_combos.finditer(text):
            val_upper = m.group(0)
            words = val_upper.lower().split()
            # Ignore standard document header terms
            if any(w in ('income', 'tax', 'department', 'permanent', 'account', 'number', 'government', 'india', 'election', 'commission', 'directorate', 'signature', 'date', 'birth', 'male', 'female', 'republic') for w in words):
                continue
            first = words[0]
            last = words[-1]
            if (first in COMMON_INDIAN_FIRST_NAMES and last in COMMON_INDIAN_LAST_NAMES) or \
               (first in COMMON_INDIAN_FIRST_NAMES and len(words) >= 2) or \
               (last in COMMON_INDIAN_LAST_NAMES and len(words) >= 2):
                name_start = m.start()
                name_end = m.end()
                if not is_occupied(name_start, name_end):
                    names.append(DetectedEntity(
                        entity_type="PERSON",
                        start=name_start,
                        end=name_end,
                        value=val_upper,
                        score=0.91,
                        explanation="Uppercase Indian personal name on identity document"
                    ))
                    occupied_spans.append((name_start, name_end))

        # 5. Kannada Honorifics & Names: ಶ್ರೀ ರಾಹುಲ್ ಶರ್ಮಾ, ಡಾ. ರಮೇಶ್, etc.
        kan_honorific = re.compile(
            r'(?:ಶ್ರೀ|ಶ್ರೀಮತಿ|ಕುಮಾರಿ|ಡಾ\.|ಡಾ|ಪ್ರೊ\.)\s+([\u0C80-\u0CFF]+(?:\s+[\u0C80-\u0CFF]+){0,2})'
        )
        for m in kan_honorific.finditer(text):
            raw_val = m.group(1).strip()
            words = [w for w in raw_val.split() if w not in ('ಅವರ', 'ಎಂಬ', 'ರವರಿಗೆ', 'ಇವರ', 'ಮತ್ತು', 'ಇವರು', 'ಅವರು')]
            if words:
                clean_name = " ".join(words)
                s = text.find(clean_name, m.start())
                e = s + len(clean_name)
                if not is_occupied(s, e):
                    names.append(DetectedEntity(
                        entity_type="PERSON",
                        start=s,
                        end=e,
                        value=clean_name,
                        score=0.95,
                        explanation="Kannada personal name preceded by honorific"
                    ))
                    occupied_spans.append((s, e))

        # 6. Kannada Contextual Names: ಹೆಸರು: ರಾಹುಲ್ ಶರ್ಮಾ, ಅರ್ಜಿದಾರರ ಹೆಸರು:, etc.
        kan_cue_pattern = re.compile(
            r'(?:ಹೆಸರು|ಅರ್ಜಿದಾರರ\s+ಹೆಸರು|ಗ್ರಾಹಕರ\s+ಹೆಸರು|ತಂದೆಯ\s+ಹೆಸರು|ಪತಿಯ\s+ಹೆಸರು|ನನ್ನ\s+ಹೆಸರು)\s*[:]?\s+([\u0C80-\u0CFF]+(?:\s+[\u0C80-\u0CFF]+){0,2})'
        )
        for m in kan_cue_pattern.finditer(text):
            raw_val = m.group(1).strip()
            words = [w for w in raw_val.split() if w not in ('ಅವರ', 'ಎಂಬ', 'ರವರಿಗೆ', 'ಇವರ', 'ಮತ್ತು', 'ಇವರು', 'ಅವರು')]
            if words:
                clean_name = " ".join(words)
                s = text.find(clean_name, m.start())
                e = s + len(clean_name)
                if not is_occupied(s, e):
                    names.append(DetectedEntity(
                        entity_type="PERSON",
                        start=s,
                        end=e,
                        value=clean_name,
                        score=0.94,
                        explanation="Kannada personal name following role indicator"
                    ))
                    occupied_spans.append((s, e))

        # 7. Hindi Honorifics & Names: श्री राहुल शर्मा, श्रीमती प्रिया वर्मा, etc.
        hin_honorific = re.compile(
            r'(?:श्री|श्रीमती|सुश्री|डॉ\.|डॉ|प्रो\.)\s+([\u0900-\u097F]+(?:\s+[\u0900-\u097F]+){0,2})'
        )
        for m in hin_honorific.finditer(text):
            raw_val = m.group(1).rstrip('।., ').strip()
            words = [w for w in raw_val.split() if w not in ('का', 'की', 'के', 'ने', 'को', 'है', 'हैं', 'और')]
            if words:
                clean_name = " ".join(words)
                s = text.find(clean_name, m.start())
                e = s + len(clean_name)
                if not is_occupied(s, e):
                    names.append(DetectedEntity(
                        entity_type="PERSON",
                        start=s,
                        end=e,
                        value=clean_name,
                        score=0.95,
                        explanation="Hindi personal name preceded by honorific"
                    ))
                    occupied_spans.append((s, e))

        # 8. Hindi Contextual Names: नाम: राहुल शर्मा, आवेदक का नाम:, etc.
        hin_cue_pattern = re.compile(
            r'(?:नाम|आवेदक\s+का\s+नाम|ग्राहक\s+का\s+नाम|पिता\s+का\s+नाम|पति\s+का\s+नाम|मेरा\s+नाम)\s*[:]?\s+([\u0900-\u097F]+(?:\s+[\u0900-\u097F]+){0,2})'
        )
        for m in hin_cue_pattern.finditer(text):
            raw_val = m.group(1).rstrip('।., ').strip()
            words = [w for w in raw_val.split() if w not in ('का', 'की', 'के', 'ने', 'को', 'है', 'हैं', 'और')]
            if words:
                clean_name = " ".join(words)
                s = text.find(clean_name, m.start())
                e = s + len(clean_name)
                if not is_occupied(s, e):
                    names.append(DetectedEntity(
                        entity_type="PERSON",
                        start=s,
                        end=e,
                        value=clean_name,
                        score=0.94,
                        explanation="Hindi personal name following role indicator"
                    ))
                    occupied_spans.append((s, e))

        # 9. Standalone Kannada & Hindi Gazetteer Names
        kan_words = re.findall(r'[\u0C80-\u0CFF]+', text)
        for kw in kan_words:
            if kw in KANNADA_NAMES:
                s = text.find(kw)
                while s != -1:
                    e = s + len(kw)
                    if not is_occupied(s, e) and len(kw) >= 3:
                        names.append(DetectedEntity(
                            entity_type="PERSON",
                            start=s,
                            end=e,
                            value=kw,
                            score=0.88,
                            explanation="Kannada personal name from gazetteer registry"
                        ))
                        occupied_spans.append((s, e))
                    s = text.find(kw, e)

        hin_words = re.findall(r'[\u0900-\u097F]+', text)
        for hw in hin_words:
            if hw in HINDI_NAMES:
                s = text.find(hw)
                while s != -1:
                    e = s + len(hw)
                    if not is_occupied(s, e) and len(hw) >= 3:
                        names.append(DetectedEntity(
                            entity_type="PERSON",
                            start=s,
                            end=e,
                            value=hw,
                            score=0.88,
                            explanation="Hindi personal name from gazetteer registry"
                        ))
                        occupied_spans.append((s, e))
                    s = text.find(hw, e)

        return names

    def _resolve_overlaps(self, entities: List[DetectedEntity]) -> List[DetectedEntity]:
        """
        Sorts entities and eliminates overlapping spans by preferring:
        1. Higher confidence score
        2. Longer character span
        """
        if not entities:
            return []

        # Sort by start asc, length desc, score desc
        sorted_entities = sorted(
            entities,
            key=lambda e: (e.start, -(e.end - e.start), -e.score)
        )

        resolved: List[DetectedEntity] = []
        for current in sorted_entities:
            conflict = False
            for existing in resolved:
                # Check for overlap: [start, end]
                if max(current.start, existing.start) < min(current.end, existing.end):
                    conflict = True
                    # If current has higher score, replace existing
                    if current.score > existing.score + 0.05:
                        resolved.remove(existing)
                        resolved.append(current)
                    break
            if not conflict:
                resolved.append(current)

        resolved.sort(key=lambda x: x.start)
        return resolved
