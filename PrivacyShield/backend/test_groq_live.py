"""
Real Groq Cloud Connection Test for PrivacyShield
Sends real API requests to Groq Cloud endpoint: https://api.groq.com/openai/v1/chat/completions
Model: openai/gpt-oss-120b
Never exposes secret API keys.
"""

import os
import sys
import json
import time
import httpx
from dotenv import load_dotenv

# Load env variables securely
env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(env_path, override=True)

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "").strip()
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b").strip()
GROQ_BASE_URL = os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1").strip()

def mask_key(k: str) -> str:
    if not k or len(k) < 8:
        return "[NOT_SET]"
    return f"{k[:7]}...{k[-4:]}"

def test_direct_groq():
    print("==================================================================")
    print(" 1. DIRECT GROQ CLOUD API CONNECTION TEST")
    print("==================================================================")
    print(f"Target Endpoint : {GROQ_BASE_URL}/chat/completions")
    print(f"Configured Model: {GROQ_MODEL}")
    print(f"API Key Status  : Loaded from backend/.env (Key: {mask_key(GROQ_API_KEY)})")

    if not GROQ_API_KEY:
        print("ERROR: GROQ_API_KEY is not set.")
        return

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": "You are the LLM engine for PrivacyShield DPDP Privacy Gateway."},
            {"role": "user", "content": "State your model identification and confirm that PrivacyShield Groq connection is verified in 1-2 sentences."}
        ],
        "max_tokens": 128,
        "temperature": 0.2
    }

    t0 = time.time()
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(f"{GROQ_BASE_URL}/chat/completions", headers=headers, json=payload)
            elapsed_ms = (time.time() - t0) * 1000.0

            print(f"\nHTTP Status Code : {resp.status_code} {resp.reason_phrase}")
            print(f"Network Latency  : {elapsed_ms:.2f} ms")

            # Handle errors
            if resp.status_code == 401:
                print("❌ Authentication Error: Invalid or expired Groq API key.")
                print(f"Provider Details: {resp.text}")
                return
            elif resp.status_code == 429:
                print("❌ Rate Limit Exceeded: Groq rate limit hit.")
                print(f"Provider Details: {resp.text}")
                return
            elif resp.status_code != 200:
                print(f"❌ API Failure (Status {resp.status_code}):")
                print(f"Provider Details: {resp.text}")
                return

            data = resp.json()
            returned_model = data.get("model", "unknown")
            usage = data.get("usage", {})
            choices = data.get("choices", [])
            content = ""
            if choices:
                msg = choices[0].get("message", {})
                content = msg.get("content", "")

            print(f"Returned Model   : {returned_model}")
            print(f"Completion Usage : Prompt: {usage.get('prompt_tokens')}, Completion: {usage.get('completion_tokens')}, Total: {usage.get('total_tokens')}")
            print(f"\n--- ACTUAL GROQ MODEL RESPONSE ---")
            print(content.strip() if content else "[No text content returned]")
            print("----------------------------------")
            print("✓ Live Groq Cloud request executed successfully without mock!")

    except httpx.RequestError as e:
        print(f"❌ Network/Connection Error communicating with Groq: {e}")

def test_gateway_endpoint():
    print("\n==================================================================")
    print(" 2. PRIVACYSHIELD BACKEND /api/test-groq GATEWAY ENDPOINT TEST")
    print("==================================================================")
    url = "http://127.0.0.1:8000/api/test-groq"
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(url, json={})
            print(f"Gateway HTTP Status: {resp.status_code}")
            data = resp.json()
            print("Gateway Test Payload:")
            print(json.dumps(data, indent=2))
    except Exception as e:
        print(f"Could not reach local gateway endpoint: {e}")

def test_error_handling():
    print("\n==================================================================")
    print(" 3. ERROR HANDLING VERIFICATION (AUTH ERROR & RATE LIMIT/FAILURE)")
    print("==================================================================")
    headers = {
        "Authorization": "Bearer gsk_invalid_test_key_for_error_handling",
        "Content-Type": "application/json"
    }
    payload = {
        "model": GROQ_MODEL,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 10
    }
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(f"{GROQ_BASE_URL}/chat/completions", headers=headers, json=payload)
            print(f"Simulated Bad Key Test Status: {resp.status_code} (Expected 401)")
            err_json = resp.json()
            print(f"Error Message Correctly Captured: {err_json.get('error', {}).get('message')}")
    except Exception as e:
        print(f"Error test exception: {e}")

if __name__ == "__main__":
    test_direct_groq()
    test_gateway_endpoint()
    test_error_handling()
