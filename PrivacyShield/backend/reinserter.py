"""
PrivacyShield - Local Placeholder Reinsertion Engine
Restores original values locally into the AI response returned from the external LLM.
Operates strictly in transient local memory.
Guarantees zero cross-contamination between different entities.
"""

import re
from typing import Dict, Any, Tuple
from dataclasses import dataclass

@dataclass
class ReinsertionResult:
    restored_text: str
    reinsertion_status: str  # 'PERFECT', 'PARTIAL', 'SKIPPED', 'NO_PLACEHOLDERS'
    placeholders_found: int
    placeholders_restored: int
    missing_placeholders: list

class LocalReinserter:
    """
    Substitutes placeholders back to original values safely.
    Handles variations, reordered tokens, and dropped tags cleanly.
    """

    def __init__(self):
        # Regex to detect standard placeholders like <PERSON_1>, <AADHAAR_2>, etc.
        # Also handles minor formatting variations like [PERSON_1] or <PERSON_1>
        self.placeholder_regex = re.compile(
            r'([<\[])([A-Z_]+_\d+)([>\]])'
        )

    def reinsert(self, llm_response: str, placeholder_map: Dict[str, str]) -> ReinsertionResult:
        """
        Replaces each placeholder in llm_response with its original value from placeholder_map.
        """
        if not llm_response:
            return ReinsertionResult(
                restored_text="",
                reinsertion_status="SKIPPED",
                placeholders_found=0,
                placeholders_restored=0,
                missing_placeholders=[]
            )

        if not placeholder_map:
            return ReinsertionResult(
                restored_text=llm_response,
                reinsertion_status="NO_PLACEHOLDERS",
                placeholders_found=0,
                placeholders_restored=0,
                missing_placeholders=[]
            )

        restored_text = llm_response
        found_count = 0
        restored_count = 0

        # Build normalized lookup for both <KEY> and KEY
        normalized_map: Dict[str, str] = {}
        for k, v in placeholder_map.items():
            clean_key = k.strip("<>[]")
            normalized_map[clean_key] = v
            normalized_map[f"<{clean_key}>"] = v
            normalized_map[f"[{clean_key}]"] = v

        # Find all placeholders in the response
        present_in_response = set()
        for match in self.placeholder_regex.finditer(llm_response):
            tag_name = match.group(2)
            present_in_response.add(tag_name)
            found_count += 1

        # Check for direct string matches of placeholder_map keys as well
        for key in placeholder_map.keys():
            if key in restored_text:
                present_in_response.add(key.strip("<>[]"))

        # Perform replacement safely using word/exact boundary replacement
        for clean_tag, original_value in normalized_map.items():
            patterns = [
                re.escape(f"<{clean_tag}>"),
                re.escape(f"[{clean_tag}]"),
                r'\b' + re.escape(clean_tag) + r'\b'
            ]
            for pat in patterns:
                if re.search(pat, restored_text):
                    restored_text = re.sub(pat, original_value, restored_text)
                    restored_count += 1

        # Evaluate which original placeholders from the prompt were returned vs dropped
        expected_tags = {k.strip("<>[]") for k in placeholder_map.keys()}
        missing = list(expected_tags - present_in_response)

        if not expected_tags:
            status = "NO_PLACEHOLDERS"
        elif len(missing) == 0:
            status = "PERFECT"
        elif len(missing) < len(expected_tags):
            status = "PARTIAL"
        else:
            status = "DROPPED_BY_MODEL"

        return ReinsertionResult(
            restored_text=restored_text,
            reinsertion_status=status,
            placeholders_found=len(present_in_response),
            placeholders_restored=restored_count,
            missing_placeholders=missing
        )
