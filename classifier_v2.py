#!/usr/bin/env python3
"""
classifier_v2.py - Multi-Provider LLM Vulnerability Classifier

Improved classifier supporting Google Gemini, GitHub Models, and OpenAI.
Uses official SDKs for better reliability and automatic retry handling.

Adapted to work with VAFinding dataclass from parser.py.
"""

import json
import os
import sys
import time
from typing import Optional
def _extract_json_object(text: str) -> str:
    """Extract first JSON object from text, raising ValueError if none found."""
    stripped = text.strip()
    
    # Try direct parse first
    if stripped.startswith('{') and stripped.endswith('}'):
        try:
            json.loads(stripped)
            return stripped
        except json.JSONDecodeError:
            pass
    
    # Find JSON object boundaries
    start = stripped.find('{')
    if start == -1:
        # Debug: print what we got
        print(f"\n[DEBUG] No JSON found in response. First 200 chars:", file=sys.stderr)
        print(f"[DEBUG] {stripped[:200]}", file=sys.stderr)
        raise ValueError("No JSON object found in response")
    
    # Find matching closing brace
    brace_count = 0
    end = -1
    for i in range(start, len(stripped)):
        if stripped[i] == '{':
            brace_count += 1
        elif stripped[i] == '}':
            brace_count -= 1
            if brace_count == 0:
                end = i
                break
    
    if end == -1:
        print(f"\n[DEBUG] Unclosed JSON object. First 200 chars:", file=sys.stderr)
        print(f"[DEBUG] {stripped[:200]}", file=sys.stderr)
        raise ValueError("No complete JSON object found in response")
    
    candidate = stripped[start:end + 1]
    
    # Validate it's valid JSON
    try:
        json.loads(candidate)
        return candidate
    except json.JSONDecodeError as e:
        print(f"\n[DEBUG] Invalid JSON extracted. Error: {e}", file=sys.stderr)
        print(f"[DEBUG] Extracted: {candidate[:200]}", file=sys.stderr)
        raise ValueError(f"Invalid JSON in response: {e}")



def build_classification_prompt(finding: dict, business_context: Optional[dict] = None) -> str:
    """
    Build a focused classification prompt for any LLM.
    
    Args:
        finding: Dictionary from parser.to_dict_list()
        business_context: Optional business rules and environment context
        
    Returns:
        Prompt string requesting structured JSON response
    """
    cvss_str = f"{finding.get('cvss')}" if finding.get('cvss') is not None else "N/A"
    
    # Build business context section
    context_rules = ""
    if business_context:
        context_rules = "\n\nBUSINESS CONTEXT & RULES:\n"
        if business_context.get('excluded_ports'):
            context_rules += f"- EXCLUDED PORTS: {', '.join(map(str, business_context['excluded_ports']))} (company standard ports, do NOT mark as automation candidates)\n"
        if business_context.get('critical_services'):
            context_rules += f"- CRITICAL SERVICES: {', '.join(business_context['critical_services'])} (prioritize these for automation)\n"
        if business_context.get('environment'):
            context_rules += f"- ENVIRONMENT: {business_context['environment']}\n"
        if business_context.get('custom_notes'):
            context_rules += f"- NOTES: {business_context['custom_notes']}\n"
    
    prompt = f"""You are a security analyst performing vulnerability triage in a controlled lab environment.
You are NOT launching exploits - only classifying vulnerability data for automated testing feasibility.
{context_rules}
Analyze this vulnerability finding:

HOST: {finding.get('host_ip')} ({finding.get('hostname')})
PORT: {finding.get('port')}/{finding.get('protocol')}
SERVICE: {finding.get('service')}
CVSS: {cvss_str}
TITLE: {finding.get('title')}
DESCRIPTION: {finding.get('description', '')[:500]}
EVIDENCE: {finding.get('evidence', '')[:300]}

Respond with ONLY valid JSON (no markdown, no code blocks):

{{
  "severity_bucket": "<Low|Medium|High|Critical>",
  "attack_vector": "<Network|Adjacent|Local|Physical>",
  "vuln_component": "<brief component name>",
  "exploit_notes": "<1-2 sentence explanation>",
  "automation_candidate": <true|false>,
  "llm_confidence": <0.0-1.0>
}}

Rules:
- automation_candidate: true if remotely testable without credentials (RCE, info disclosure, weak crypto)
- automation_candidate: false if needs auth, social engineering, or is policy-only
- vuln_component: specific software/service vulnerable (e.g., "Apache 2.4.49", "OpenSSH 7.4")
"""
    return prompt


def _classify_with_openai_sdk(finding: dict, api_key: str,
                               base_url: str = "https://api.openai.com/v1",
                               model: str = "gpt-4o-mini",
                               business_context: Optional[dict] = None) -> dict:
    """
    Classify using OpenAI SDK (supports OpenAI, GitHub Models, Azure OpenAI).
    
    Args:
        finding: Dictionary from parser
        api_key: API key
        base_url: API endpoint (GitHub: https://models.inference.ai.azure.com)
        model: Model name
        business_context: Optional business rules and environment context
        
    Returns:
        Classification dict with all required fields
    """
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("openai package not installed. Run: pip install openai")
    
    client = OpenAI(api_key=api_key, base_url=base_url)
    prompt = build_classification_prompt(finding, business_context)
    
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a security analyst. Respond with valid JSON only."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.0,  # Deterministic
        max_tokens=1200  # Increased further for verbose local models
    )
    
    raw_content = response.choices[0].message.content
    if not raw_content:
        # Empty response - possibly model timeout or context issue
        print(f"      [WARNING] Empty response from model, retrying with shorter prompt...", file=sys.stderr)
        raise ValueError("Empty response from LLM - will retry")
    response_text = raw_content.strip()
    
    # Remove markdown code blocks if present
    if response_text.startswith('```'):
        lines = response_text.split('\n')
        response_text = '\n'.join(lines[1:-1])
        if response_text.startswith('json'):
            response_text = response_text[4:].strip()
    
    try:
        return json.loads(response_text)
    except json.JSONDecodeError as e:
        print(f"      [DEBUG] JSON parse failed: {e}", file=sys.stderr)
        print(f"      [DEBUG] Response preview: {response_text[:300]}", file=sys.stderr)
        print(f"      [DEBUG] Attempting to extract JSON object...", file=sys.stderr)
        cleaned = _extract_json_object(response_text)
        return json.loads(cleaned)


def _classify_with_gemini(finding: dict, api_key: str,
                          business_context: Optional[dict] = None) -> dict:
    """
    Classify using Google Gemini API.
    
    Args:
        finding: Dictionary from parser
        api_key: Google API key
        business_context: Optional business rules and environment context
        
    Returns:
        Classification dict with all required fields
    """
    try:
        from google import genai  # type: ignore[import]
        from google.genai import types  # type: ignore[import]
    except ImportError:
        raise ImportError("google-genai package not installed. Run: pip install google-genai")
    
    client = genai.Client(api_key=api_key)
    prompt = build_classification_prompt(finding, business_context)
    
    response = client.models.generate_content(
        model='gemini-2.0-flash-exp',
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.0,
            max_output_tokens=400
        )
    )
    
    raw_text = getattr(response, "text", None)
    if not raw_text:
        raise ValueError("Empty response from Gemini")
    response_text = raw_text.strip()
    
    # Remove markdown code blocks if present
    if response_text.startswith('```'):
        lines = response_text.split('\n')
        response_text = '\n'.join(lines[1:-1])
        if response_text.startswith('json'):
            response_text = response_text[4:].strip()
    
    try:
        return json.loads(response_text)
    except json.JSONDecodeError as e:
        print(f"      [DEBUG] Gemini JSON parse failed: {e}", file=sys.stderr)
        print(f"      [DEBUG] Response preview: {response_text[:300]}", file=sys.stderr)
        print(f"      [DEBUG] Attempting to extract JSON object...", file=sys.stderr)
        cleaned = _extract_json_object(response_text)
        return json.loads(cleaned)


def _heuristic_fallback(finding: dict) -> dict:
    """
    Fallback heuristic classification when LLM fails.
    
    Args:
        finding: Dictionary from parser
        
    Returns:
        Basic classification dict
    """
    cvss = finding.get("cvss")
    severity_text = finding.get("severity_text", "").lower()
    
    # Determine severity bucket
    if cvss is not None:
        if cvss >= 9.0 or severity_text == "critical":
            severity_bucket = "Critical"
        elif cvss >= 7.0:
            severity_bucket = "High"
        elif cvss >= 4.0:
            severity_bucket = "Medium"
        elif cvss > 0:
            severity_bucket = "Low"
        else:
            severity_bucket = "None"
    elif severity_text == "critical":
        severity_bucket = "Critical"
    elif severity_text == "high":
        severity_bucket = "High"
    elif severity_text == "medium":
        severity_bucket = "Medium"
    elif severity_text == "low":
        severity_bucket = "Low"
    else:
        severity_bucket = "None"
    
    return {
        "severity_bucket": severity_bucket,
        "attack_vector": "Network",
        "vuln_component": "unknown",
        "exploit_notes": "Heuristic fallback. Manual review required.",
        "automation_candidate": False,
        "llm_confidence": 0.2
    }


def classify_single(finding: dict, provider: str = "auto",
                    api_key: Optional[str] = None,
                    model: Optional[str] = None,
                    business_context: Optional[dict] = None) -> dict:
    """
    Classify a single finding using specified provider.
    
    Args:
        finding: Dictionary from parser.to_dict_list()
        provider: "gemini", "github", "openai", or "auto"
        api_key: API key (if None, reads from environment)
        model: Model name (provider-specific)
        business_context: Optional business rules and environment context
        
    Returns:
        Finding dict enriched with classification fields
    """
    try:
        # Auto-detect provider
        if provider == "auto":
            if os.environ.get('GITHUB_TOKEN'):
                provider = "github"
            elif os.environ.get('GEMINI_API_KEY') or os.environ.get('GOOGLE_API_KEY'):
                provider = "gemini"
            elif os.environ.get('OPENAI_API_KEY'):
                provider = "openai"
            elif os.environ.get('LOCAL_OPENAI_BASE_URL'):
                provider = "local"
            else:
                raise RuntimeError("No API key found in environment")
        
        # Get API key
        if api_key is None:
            if provider == "github":
                api_key = os.environ.get('GITHUB_TOKEN')
                if not api_key:
                    raise RuntimeError("GITHUB_TOKEN not set")
            elif provider == "gemini":
                api_key = os.environ.get('GEMINI_API_KEY') or os.environ.get('GOOGLE_API_KEY')
                if not api_key:
                    raise RuntimeError("GEMINI_API_KEY not set")
            elif provider == "openai":
                api_key = os.environ.get('OPENAI_API_KEY')
                if not api_key:
                    raise RuntimeError("OPENAI_API_KEY not set")
            elif provider == "local":
                api_key = os.environ.get('LOCAL_OPENAI_API_KEY') or "local"
        
        # Classify based on provider
        if provider == "github":
            model = model or "gpt-4o-mini"
            assert api_key is not None
            classification = _classify_with_openai_sdk(
                finding, api_key,
                base_url="https://models.inference.ai.azure.com",
                model=model,
                business_context=business_context
            )
        elif provider == "gemini":
            assert api_key is not None
            classification = _classify_with_gemini(finding, api_key, business_context)
        elif provider == "openai":
            model = model or "gpt-5-nano"
            assert api_key is not None
            classification = _classify_with_openai_sdk(finding, api_key, model=model, business_context=business_context)
        elif provider == "local":
            model = model or "deepseek-r1:14b"
            base_url = os.environ.get('LOCAL_OPENAI_BASE_URL') or "http://localhost:11434/v1"
            assert api_key is not None
            classification = _classify_with_openai_sdk(
                finding,
                api_key,
                base_url=base_url,
                model=model,
                business_context=business_context
            )
        else:
            raise ValueError(f"Unknown provider: {provider}")
        
        # Merge classification into finding
        enriched = finding.copy()
        enriched.update(classification)
        return enriched
        
    except Exception as e:
        error_msg = str(e)
        
        # Check for transient errors that should be retried
        is_transient = any(x in error_msg for x in [
            "503", "UNAVAILABLE", "overloaded", 
            "500", "502", "504",
            "timeout", "Timeout",
            "Empty response from LLM - will retry",
            "Connection", "connection",
            "No complete JSON object found",
            "Invalid JSON in response",
            "Unterminated string"
        ])
        
        if is_transient:
            # Retry with exponential backoff for transient errors
            print(f"      ⚠️  Transient error, retrying with backoff...", file=sys.stderr)
            max_retries = 3
            for retry in range(max_retries):
                wait_time = 2 ** retry  # 1s, 2s, 4s
                print(f"      Retry {retry + 1}/{max_retries} in {wait_time}s...", file=sys.stderr)
                time.sleep(wait_time)
                
                try:
                    # Retry the classification
                    if provider == "github":
                        assert api_key is not None
                        classification = _classify_with_openai_sdk(
                            finding, api_key,
                            base_url="https://models.inference.ai.azure.com",
                            model=model or "gpt-4o-mini",
                            business_context=business_context
                        )
                    elif provider == "gemini":
                        assert api_key is not None
                        classification = _classify_with_gemini(finding, api_key, business_context)
                    elif provider == "openai":
                        assert api_key is not None
                        classification = _classify_with_openai_sdk(
                            finding, api_key, 
                            model=model or "gpt-4o-mini",
                            business_context=business_context
                        )
                    elif provider == "local":
                        assert api_key is not None
                        base_url = os.environ.get('LOCAL_OPENAI_BASE_URL') or "http://localhost:11434/v1"
                        classification = _classify_with_openai_sdk(
                            finding,
                            api_key,
                            base_url=base_url,
                            model=model or "deepseek-r1:14b",
                            business_context=business_context
                        )
                    
                    # Success! Return enriched finding
                    enriched = finding.copy()
                    enriched.update(classification)
                    print(f"      ✅ Retry successful", file=sys.stderr)
                    return enriched
                    
                except Exception as retry_error:
                    if retry == max_retries - 1:
                        # Last retry failed - stop execution
                        print(f"\n[ERROR] All retries exhausted: {str(retry_error)}", file=sys.stderr)
                        print(f"[!] Cannot continue without LLM classification.", file=sys.stderr)
                        sys.exit(1)
                    else:
                        print(f"      Retry failed: {str(retry_error)[:100]}", file=sys.stderr)
                        continue
        
        # Check if rate limited - stop execution
        elif "RateLimitReached" in error_msg or "429" in error_msg:
            print(f"\n[ERROR] Rate limit exceeded!", file=sys.stderr)
            print(f"[ERROR] {error_msg[:200]}", file=sys.stderr)
            print(f"\n[!] Cannot continue without LLM classification.", file=sys.stderr)
            print(f"[!] Please wait for rate limit to reset or switch to a different provider.", file=sys.stderr)
            sys.exit(1)
        else:
            # For other errors, show error and stop
            print(f"\n[ERROR] LLM classification failed: {error_msg}", file=sys.stderr)
            print(f"[!] Cannot continue without LLM classification.", file=sys.stderr)
            sys.exit(1)

        raise RuntimeError("LLM classification failed")


def classify_findings(findings: list[dict], provider: str = "auto",
                     model: Optional[str] = None,
                     business_context: Optional[dict] = None) -> list[dict]:
    """
    Classify a batch of findings with rate limiting.
    
    Args:
        findings: List of dictionaries from parser.to_dict_list()
        provider: "gemini", "github", "openai", or "auto"
        model: Model name (provider-specific)
        business_context: Optional business rules and environment context
        
    Returns:
        List of enriched finding dictionaries
    """
    # Detect actual provider
    actual_provider = provider
    if provider == "auto":
        if os.environ.get('GITHUB_TOKEN'):
            actual_provider = "github"
        elif os.environ.get('GEMINI_API_KEY') or os.environ.get('GOOGLE_API_KEY'):
            actual_provider = "gemini"
        elif os.environ.get('OPENAI_API_KEY'):
            actual_provider = "openai"
        elif os.environ.get('LOCAL_OPENAI_BASE_URL'):
            actual_provider = "local"
        else:
            print("\n" + "=" * 70, file=sys.stderr)
            print("[ERROR] No LLM API key found!", file=sys.stderr)
            print("=" * 70, file=sys.stderr)
            print("This pipeline requires an LLM for intelligent classification.", file=sys.stderr)
            print("Please set one of the following environment variables:\n", file=sys.stderr)
            print("  Gemini (FREE - 1500 requests/day):", file=sys.stderr)
            print("    $env:GEMINI_API_KEY = 'your_key'", file=sys.stderr)
            print("    Get key: https://aistudio.google.com/apikey\n", file=sys.stderr)
            print("  OpenAI (PAID - unlimited):", file=sys.stderr)
            print("    $env:OPENAI_API_KEY = 'sk-your_key'", file=sys.stderr)
            print("    Get key: https://platform.openai.com/api-keys\n", file=sys.stderr)
            print("  GitHub Models (FREE - 150 requests/day):", file=sys.stderr)
            print("    $env:GITHUB_TOKEN = 'ghp_your_token'\n", file=sys.stderr)
            print("  Local (Ollama/LM Studio):", file=sys.stderr)
            print("    $env:LOCAL_OPENAI_BASE_URL = 'http://localhost:11434/v1'", file=sys.stderr)
            print("    Optional: $env:LOCAL_OPENAI_API_KEY = 'local'\n", file=sys.stderr)
            print("=" * 70, file=sys.stderr)
            sys.exit(1)
    
    provider_names = {
        "github": "GitHub Models",
        "gemini": "Google Gemini",
        "openai": "OpenAI",
        "local": "Local (Ollama/LM Studio)"
    }
    
    print(f"[*] Classifying with {provider_names.get(actual_provider, actual_provider)}", 
          file=sys.stderr)
    
    enriched = []
    total = len(findings)
    
    for i, finding in enumerate(findings, 1):
        title = finding.get('title', 'Unknown')[:50]
        print(f"[*] Classifying finding {i}/{total}: {title}...", file=sys.stderr)
        
        classified = classify_single(finding, provider=actual_provider, model=model, 
                                     business_context=business_context)
        enriched.append(classified)
        
        # Rate limiting: wait between requests
        # Gemini free tier: 15 requests/min = 4s between requests to be safe
        # GitHub/OpenAI: More conservative 0.5s delay
        if i < total:
            if actual_provider == "gemini":
                time.sleep(5)  # 5s = 12 requests/min (safely under 15 RPM limit)
            else:
                time.sleep(0.5)  # 0.5s for GitHub/OpenAI
    
    print(f"[+] Classified {len(enriched)} findings", file=sys.stderr)
    return enriched


def main() -> None:
    """Test harness using parser module."""
    print("[*] Testing classifier_v2 module\n")
    
    try:
        import parser
    except ImportError:
        print("[ERROR] Could not import parser.py", file=sys.stderr)
        sys.exit(1)
    
    # Parse sample data
    xml_file = "auvap_nessus_25_findings.xml"
    try:
        findings = parser.parse_nessus_xml(xml_file)
        findings_dicts = parser.to_dict_list(findings)
        print(f"[+] Loaded {len(findings_dicts)} findings\n")
    except Exception as e:
        print(f"[ERROR] Failed to parse XML: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Classify first 3 findings
    sample = findings_dicts[:3]
    enriched = classify_findings(sample)
    
    print("\n[*] Classification results:\n")
    for i, finding in enumerate(enriched, 1):
        print(f"--- Finding {i} ---")
        print(f"Title: {finding['title']}")
        print(f"Severity: {finding.get('severity_bucket', 'N/A')}")
        print(f"Attack Vector: {finding.get('attack_vector', 'N/A')}")
        print(f"Component: {finding.get('vuln_component', 'N/A')}")
        print(f"Automation: {finding.get('automation_candidate', False)}")
        print()


if __name__ == "__main__":
    main()
