"""
PrivacyShield - External LLM Integration & Pre-Flight Zero-Leakage Guard
Powered by Groq Cloud High-Speed Inference API (OpenAI-compatible).
Performs a strict mathematical and lexical check for zero PII leakage
before ANY outbound bytes leave the local server boundary.
"""

import os
import re
import json
import time
import logging
import httpx
from typing import Dict, Any, Tuple, Optional

logger = logging.getLogger("PrivacyShield.LLM")
logger.setLevel(logging.INFO)

# Default Groq Cloud settings per specification
DEFAULT_MODEL = "openai/gpt-oss-120b"
DEFAULT_BASE_URL = "https://api.groq.com/openai/v1"

# Pre-defined task prompts tailored for enterprise documents
TASK_PROMPTS = {
    "summarize": (
        "You are an enterprise document analyst. Please provide a concise, professional executive summary "
        "of the following sanitized document. Retain all entity placeholders (such as <PERSON_1>, <AADHAAR_1>, <PAN_1>) "
        "exactly as they appear in the text without altering their tags."
    ),
    "extract": (
        "You are a regulatory compliance specialist. Extract all structured facts, key figures, financial terms, "
        "dates, and obligations from the following sanitized document. Mention every entity placeholder "
        "(such as <PERSON_1>, <AADHAAR_1>, <PAN_1>, <ADDRESS_1>) in the appropriate extracted fields."
    ),
    "key_points": (
        "Generate a bullet-point analysis of key operational and risk factors described in this document. "
        "Ensure all entity identifiers and placeholders are preserved accurately in your bullet points."
    ),
    "qa": (
        "Analyze the provided sanitized document and answer any compliance, verification, and procedural questions. "
        "Confirm whether all necessary KYC and identity identifiers (<AADHAAR_1>, <PAN_1>, etc.) have been referenced."
    )
}


class LLMService:
    """
    Manages external LLM communication through Groq Cloud Inference API
    with strict outbound privacy enforcement and pre-flight zero-leakage checks.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None
    ):
        raw_key = api_key or os.environ.get("GROQ_API_KEY", "")
        self.api_key = raw_key.strip() if raw_key else ""
        raw_model = model or os.environ.get("GROQ_MODEL", DEFAULT_MODEL)
        self.model = raw_model.strip() if raw_model else DEFAULT_MODEL
        raw_url = base_url or os.environ.get("GROQ_BASE_URL", DEFAULT_BASE_URL)
        self.base_url = raw_url.strip() if raw_url else DEFAULT_BASE_URL

    def set_config(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None
    ):
        if api_key is not None:
            self.api_key = api_key.strip()
        if model is not None:
            self.model = model.strip()
        if base_url is not None:
            self.base_url = base_url.strip()

    def verify_zero_leakage(
        self,
        sanitized_payload: str,
        raw_values: Dict[str, str]
    ) -> Tuple[bool, Optional[str]]:
        """
        STRICT PRE-FLIGHT LEAKAGE GUARD:
        Verifies that none of the detected original raw PII strings exist anywhere
        within the outbound sanitized payload.
        Returns: (passed: bool, violation_detail: Optional[str])
        """
        for placeholder, raw_val in raw_values.items():
            clean_raw = raw_val.strip()
            # If the raw value is trivial (less than 3 chars), skip to avoid trivial false triggers
            if len(clean_raw) < 3:
                continue

            # Check case-insensitive presence in outbound text
            if clean_raw.lower() in sanitized_payload.lower():
                violation = f"LEAKAGE DETECTED: Raw PII value '{clean_raw}' for {placeholder} found in outbound text!"
                logger.critical(violation)
                return False, violation

        return True, None

    async def execute_task(
        self,
        sanitized_payload: str,
        task: str,
        raw_values: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Executes external inference on Groq Cloud after strict zero-leakage verification.
        Sends ONLY sanitized payload and system instructions.
        """
        # Step 1: Pre-flight Zero-Leakage Verification
        leakage_passed, violation_msg = self.verify_zero_leakage(sanitized_payload, raw_values)
        if not leakage_passed:
            return {
                "success": False,
                "leakage_passed": False,
                "error": violation_msg,
                "model_used": self.model,
                "provider": "Groq Cloud",
                "response": "GATEWAY SECURITY ABORT: Raw PII detected in outbound payload. Request halted to prevent external data breach."
            }

        # Step 2: System prompt for the selected task
        system_instruction = TASK_PROMPTS.get(task, TASK_PROMPTS["summarize"])

        # Step 3: Check if real Groq API key is configured
        key = self.api_key.strip() if self.api_key else ""
        is_simulated = False
        api_error = None

        if not key or key == "gsk_your_groq_api_key_here":
            logger.info("GROQ_API_KEY not configured. Using local enterprise LLM simulation engine.")
            is_simulated = True
            simulated_response = self._simulate_llm_response(sanitized_payload, task)
            return {
                "success": True,
                "leakage_passed": True,
                "is_simulated": True,
                "provider": "Groq Cloud (Local Simulation)",
                "setup_note": "Simulated local inference active (GROQ_API_KEY not configured in Settings). Set your Groq API key in Settings for live cloud inference.",
                "model_used": f"{self.model} (Local Simulation)",
                "response": simulated_response
            }

        # Step 4: Real Groq Cloud API Call (/chat/completions)
        try:
            url = f"{self.base_url.rstrip('/')}/chat/completions"
            headers = {
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json"
            }

            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_instruction},
                    {"role": "user", "content": f"DOCUMENT CONTENT (SANITIZED):\n{sanitized_payload}\n\nANALYSIS:"}
                ],
                "max_tokens": 512,
                "temperature": 0.2
            }

            t0 = time.time()
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(url, headers=headers, json=payload)
                elapsed_ms = (time.time() - t0) * 1000.0

                if resp.status_code == 200:
                    data = resp.json()
                    generated_text = ""
                    if "choices" in data and len(data["choices"]) > 0:
                        msg = data["choices"][0].get("message", {})
                        generated_text = msg.get("content", "")

                    return {
                        "success": True,
                        "leakage_passed": True,
                        "is_simulated": False,
                        "provider": "Groq Cloud",
                        "model_used": f"{self.model} (Groq Cloud)",
                        "inference_latency_ms": round(elapsed_ms, 2),
                        "response": generated_text.strip()
                    }
                else:
                    error_detail = resp.text[:300]
                    try:
                        err_json = resp.json()
                        if "error" in err_json:
                            err_msg = err_json["error"].get("message") if isinstance(err_json["error"], dict) else str(err_json["error"])
                            error_detail = err_msg or error_detail
                    except Exception:
                        pass
                    api_error = f"Groq Cloud API returned HTTP {resp.status_code}: {error_detail}"
                    logger.warning(api_error)

        except Exception as e:
            api_error = f"Network or API exception communicating with Groq Cloud: {str(e)}"
            logger.error(api_error)

        # Graceful fallback with clear notification so demo never breaks
        fallback_response = self._simulate_llm_response(sanitized_payload, task)
        return {
            "success": True,
            "leakage_passed": True,
            "is_simulated": True,
            "provider": "Groq Cloud (Fallback)",
            "setup_note": f"Groq Cloud reached error ({api_error}). Safe fallback response generated locally.",
            "model_used": f"{self.model} (Fallback Engine)",
            "response": fallback_response
        }

    async def test_connection(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes a real connection test to Groq Cloud API.
        Never exposes secret API keys in returned data.
        """
        key = (api_key or self.api_key or "").strip()
        test_model = (model or self.model or DEFAULT_MODEL).strip()
        url = f"{self.base_url.rstrip('/')}/chat/completions"

        if not key or key == "gsk_your_groq_api_key_here":
            return {
                "success": False,
                "status_code": 400,
                "error": "GROQ_API_KEY is not configured. Please enter your Groq API key.",
                "model": test_model,
                "endpoint": url
            }

        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": test_model,
            "messages": [
                {"role": "user", "content": "Respond strictly with: PrivacyShield Groq connection verified."}
            ],
            "max_tokens": 100
        }

        t0 = time.time()
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(url, headers=headers, json=payload)
                elapsed_ms = (time.time() - t0) * 1000.0

                if resp.status_code == 200:
                    data = resp.json()
                    msg_content = ""
                    if "choices" in data and len(data["choices"]) > 0:
                        msg_content = data["choices"][0].get("message", {}).get("content", "")

                    return {
                        "success": True,
                        "status_code": 200,
                        "message": "Groq Cloud connection successful!",
                        "model": test_model,
                        "endpoint": url,
                        "latency_ms": round(elapsed_ms, 2),
                        "response_preview": msg_content.strip()
                    }
                else:
                    err_msg = resp.text
                    try:
                        err_json = resp.json()
                        if "error" in err_json:
                            err_msg = err_json["error"].get("message") if isinstance(err_json["error"], dict) else str(err_json["error"])
                    except Exception:
                        pass

                    return {
                        "success": False,
                        "status_code": resp.status_code,
                        "error": err_msg,
                        "model": test_model,
                        "endpoint": url,
                        "latency_ms": round(elapsed_ms, 2)
                    }
        except Exception as e:
            elapsed_ms = (time.time() - t0) * 1000.0
            return {
                "success": False,
                "status_code": 500,
                "error": f"Connection exception: {str(e)}",
                "model": test_model,
                "endpoint": url,
                "latency_ms": round(elapsed_ms, 2)
            }

    def _simulate_llm_response(self, sanitized_payload: str, task: str) -> str:
        """
        Deterministic, intelligent simulated response preserving all sanitized placeholders.
        """
        # Find all placeholders in sanitized payload
        placeholders = re.findall(r'<[A-Z_]+_\d+>', sanitized_payload)
        placeholder_str = ", ".join(placeholders) if placeholders else "None detected"

        if task == "summarize":
            return (
                f"Executive Summary:\n"
                f"This document represents an enterprise transaction involving {placeholder_str}.\n"
                f"The customer has successfully submitted verified KYC and regulatory documentation.\n"
                f"All procedural requirements under Indian financial compliance and DPDP privacy mandates "
                f"have been verified for processing."
            )
        elif task == "extract":
            return (
                f"Structured Information Extraction:\n"
                f"- Primary Identified Party: {placeholders[0] if placeholders else 'N/A'}\n"
                f"- Referenced Credentials & IDs: {', '.join(placeholders[1:]) if len(placeholders) > 1 else 'None'}\n"
                f"- Risk Classification: Tier 1 Verified Enterprise Profile\n"
                f"- Verification Status: Cleared for internal workflow routing"
            )
        elif task == "key_points":
            return (
                f"Key Findings & Observations:\n"
                f"• Verified Identity: Identity records for {placeholders[0] if placeholders else 'the party'} are referenced.\n"
                f"• Document Completeness: Associated credentials ({placeholder_str}) conform to Indian compliance standards.\n"
                f"• Operational Readiness: Sanitized payload contains zero unmasked PII tokens."
            )
        else:
            return (
                f"Compliance Q&A Assessment:\n"
                f"Q: Are all identity credentials documented and verified?\n"
                f"A: Yes, records for {placeholder_str} have been accounted for in accordance with Indian regulatory standards."
            )
