"""
PrivacyShield - PII Masking and Consistent Tokenization
Replaces sensitive Indian PII with typed cryptographic or numbered placeholders.
Guarantees consistent tokenization across repeating entity values and strictly
maintains the mapping in transient memory only for the duration of the request.
"""

from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from detector import DetectedEntity

@dataclass
class MaskingResult:
    sanitized_text: str
    placeholder_map: Dict[str, str]  # { "<PERSON_1>": "Rahul Sharma" }
    reverse_map: Dict[str, str]      # { "Rahul Sharma": "<PERSON_1>" }
    masked_entities: List[Dict[str, Any]]
    total_masked: int


class PIIMasker:
    """
    Handles deterministic and consistent tokenization of detected PII entities.
    Example:
      Input: "Rahul Sharma applied. Rahul Sharma has PAN ABCDE1234F."
      Output: "<PERSON_1> applied. <PERSON_1> has PAN <PAN_1>."
    """

    def __init__(self):
        pass

    def mask(self, text: str, entities: List[DetectedEntity]) -> MaskingResult:
        """
        Substitutes detected entities with consistent typed placeholders.
        Preserves repetition consistency and maintains the secret mapping.
        """
        if not entities or not text:
            return MaskingResult(
                sanitized_text=text,
                placeholder_map={},
                reverse_map={},
                masked_entities=[],
                total_masked=0
            )

        # Track numbering per entity type: { "PERSON": 1, "PAN": 1, "AADHAAR": 1, ... }
        type_counters: Dict[str, int] = {}
        # Map raw entity text (normalized) to its allocated placeholder
        val_to_placeholder: Dict[str, str] = {}
        # Map placeholder to original raw value
        placeholder_to_val: Dict[str, str] = {}
        masked_entity_details: List[Dict[str, Any]] = []

        # Sort entities by position ascending
        sorted_entities = sorted(entities, key=lambda e: e.start)

        # Assign consistent placeholders
        for ent in sorted_entities:
            norm_val = ent.value.strip()
            # If already assigned a placeholder for this exact value, reuse it
            if norm_val in val_to_placeholder:
                placeholder = val_to_placeholder[norm_val]
            else:
                current_count = type_counters.get(ent.entity_type, 0) + 1
                type_counters[ent.entity_type] = current_count
                placeholder = f"<{ent.entity_type}_{current_count}>"
                val_to_placeholder[norm_val] = placeholder
                placeholder_to_val[placeholder] = ent.value

            masked_entity_details.append({
                "entity_type": ent.entity_type,
                "original_preview": self._safe_preview(ent.value, ent.entity_type),
                "placeholder": placeholder,
                "score": ent.score,
                "explanation": ent.explanation,
                "detection_method": getattr(ent, "detection_method", "Presidio Pattern Recognizer")
            })

        # Perform replacement from end to start to maintain string index integrity
        # Sort by start descending
        chars = list(text)
        for ent in reversed(sorted_entities):
            norm_val = ent.value.strip()
            placeholder = val_to_placeholder[norm_val]
            chars[ent.start:ent.end] = list(placeholder)

        sanitized_text = "".join(chars)

        return MaskingResult(
            sanitized_text=sanitized_text,
            placeholder_map=placeholder_to_val,
            reverse_map=val_to_placeholder,
            masked_entities=masked_entity_details,
            total_masked=len(sorted_entities)
        )

    def _safe_preview(self, value: str, entity_type: str) -> str:
        """
        Creates a masked display snippet for dashboard previews (e.g. 'R**** S*****', 'XXXX-XXXX-2345')
        so raw PII is never visually displayed in plain text without authorization.
        """
        val = value.strip()
        if entity_type == "AADHAAR":
            clean = val.replace(" ", "").replace("-", "")
            if len(clean) >= 4:
                return f"XXXX-XXXX-{clean[-4:]}"
        elif entity_type == "PAN":
            if len(val) >= 4:
                return f"{val[:2]}XXX{val[-2:]}"
        elif entity_type == "PHONE_NUMBER":
            clean = val.replace(" ", "").replace("-", "").replace("+91", "")
            if len(clean) >= 4:
                return f"+91 XXXXX-{clean[-4:]}"
        elif entity_type == "PERSON":
            parts = val.split()
            masked_parts = [f"{p[0]}{'*' * (len(p)-1)}" if len(p) > 1 else p for p in parts]
            return " ".join(masked_parts)
        
        # General truncation
        if len(val) > 8:
            return f"{val[:3]}...{val[-3:]}"
        return val
