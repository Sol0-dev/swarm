"""
SwarmOrchestrator - Routes tasks to specialized AI agents.
Each model in the swarm has a role: orchestrator, hunter, validator, reporter, etc.
Falls back gracefully when fewer models are available.
"""

import json
import time
import requests
from typing import Optional, Dict, List, Any
from rich.console import Console

console = Console()

# Master system prompt embedding shuvonsec methodology
MASTER_SYSTEM = """You are a professional bug bounty hunter and penetration tester operating within SwarmBounty, an AI-powered security research framework.

CORE PRINCIPLES (from shuvonsec methodology):
1. READ FULL SCOPE FIRST — only test what the program explicitly authorizes
2. ONLY REAL BUGS — "Can an attacker do this RIGHT NOW against a real user?" If no → stop
3. KILL WEAK FINDINGS FAST — 30-second check saves hours of wasted reporting
4. VALIDATE BEFORE REPORT — always confirm real impact before writing
5. IMPACT FIRST — start with highest-consequence vulnerabilities
6. 5-MINUTE RULE — no progress after 5 min on a path? pivot
7. CHAIN EVERYTHING — Bug A + Bug B = 3-10x payout

VULNERABILITY CLASSES (20 classes):
Web2: SQLi, XSS (stored/reflected/DOM), SSRF, IDOR, SSTI, Open Redirect, File Upload Bypass,
      CORS Misconfig, CSRF, XXE, Race Conditions, HTTP Request Smuggling, Cache Poisoning,
      OAuth/SSO Bypass, Auth/2FA Bypass, Business Logic, GraphQL injection, Subdomain Takeover,
      Cloud Misconfig (S3/GCP/Azure), Timing Side-Channels

LLM/AI: Prompt Injection, Indirect Injection, Chatbot IDOR, System Prompt Extraction,
        ASCII Smuggling, RCE via Code Tools, Agent Exfil Channels

CHAINING METHODOLOGY:
- IDOR → Auth Bypass → Account Takeover
- SSRF → Cloud Metadata → Credentials → RCE
- XSS → Session Hijack → ATO
- Open Redirect → OAuth Token Theft
- S3 Public → JS Bundle → API Secrets → Full Compromise

BYPASS TABLES:
SSRF bypasses: 127.0.0.1, 0x7f000001, 0177.0.0.1, [::1], localhost, 127.1, spoofed DNS
File upload: double extension (.php.jpg), null byte, content-type bypass, polyglot files
Open redirect: //evil.com, /\\evil.com, %09evil.com, javascript:, data:

ALWAYS:
- Think like an attacker with developer psychology knowledge
- Consider business impact: stolen money, leaked PII, ATO, code execution
- Provide concrete PoC HTTP requests
- Rate findings by CVSS and exploitability
- For web3: check reentrancy, flash loans, access control, signature replay

You must provide actionable, specific, technically precise guidance."""

ROLE_ADDONS = {
    "orchestrator": """
ROLE: ORCHESTRATOR
You coordinate the swarm. Given recon data, you:
1. Prioritize attack surface by exploitability and impact
2. Assign specific vuln classes to investigate
3. Identify the highest-ROI entry points
4. Make go/no-go decisions on findings
5. Track chains and suggest next pivots
Output decisions as JSON when asked.""",

    "hunter": """
ROLE: ACTIVE HUNTER
You generate and adapt attack payloads. Given an endpoint/parameter, you:
1. Generate targeted payloads for the vulnerability class
2. Adapt to context (WAF evasion, encoding tricks)
3. Suggest exact HTTP requests to test
4. Identify edge cases and boundary conditions
5. Think about developer mistakes specific to the tech stack""",

    "validator": """
ROLE: VALIDATOR
You validate findings for real impact. Given a reported bug, you:
1. Apply the 7-question test: can an attacker do this RIGHT NOW?
2. Check for false positive indicators
3. Determine minimum exploitation steps
4. Calculate actual business impact
5. Write a PoC proof sequence
6. Score CVSS 3.1 with justification
Only pass bugs that meet: Real + Reproducible + Impactful""",

    "reporter": """
ROLE: REPORT WRITER
You write professional bug reports for HackerOne, Bugcrowd, Intigriti, Immunefi.
Format: Title | Severity | Summary | Steps | Impact | PoC | Remediation
- Title: "Vuln Type in Component leads to Impact" (max 80 chars)
- Steps: numbered, exact HTTP requests, curl commands
- Impact: concrete user harm (not "could lead to")
- PoC: working curl or Python snippet
- Remediation: specific fix, not generic advice
CVSS scoring with vector string.""",

    "recon": """
ROLE: RECON SPECIALIST
You plan and interpret reconnaissance. You:
1. Select optimal tool chains for the target type
2. Interpret subdomain/URL/tech fingerprint data
3. Identify the most interesting attack surface
4. Find forgotten assets (dev, staging, old APIs)
5. Map the application's trust boundaries
6. Identify third-party services and integrations""",

    "chainer": """
ROLE: CHAIN ANALYST
You find exploit chains. Given a set of bugs, you:
1. Map A→B→C paths to maximize impact
2. Calculate combined CVSS / payout multiplier
3. Find sibling endpoints affected by the same root cause
4. Identify the narrative "attacker journey"
5. Prioritize chains by: ease × impact
Output a ranked chain list."""
}


class LLMClient:
    """Unified client for all LLM providers."""

    def __init__(self, model_config: Dict):
        self.provider = model_config["provider"]
        self.model = model_config["model"]
        self.api_key = model_config["api_key"]
        self.base_url = model_config["base_url"]
        self.role = model_config.get("role", "general")

    def complete(self, messages: List[Dict], system: str = "", max_tokens: int = 4096,
                 temperature: float = 0.3) -> str:
        """Send completion request to appropriate provider API."""
        try:
            if self.provider == "gemini":
                return self._gemini_complete(messages, system, max_tokens, temperature)
            elif self.provider in ("openai", "groq", "deepseek"):
                return self._openai_compat_complete(messages, system, max_tokens, temperature)
            elif self.provider == "anthropic":
                return self._anthropic_complete(messages, system, max_tokens, temperature)
        except Exception as e:
            return f"[ERROR from {self.provider}/{self.model}]: {str(e)}"

    def _openai_compat_complete(self, messages, system, max_tokens, temperature):
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        full_messages = []
        if system:
            full_messages.append({"role": "system", "content": system})
        full_messages.extend(messages)

        payload = {
            "model": self.model,
            "messages": full_messages,
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        r = requests.post(f"{self.base_url}/chat/completions",
                          headers=headers, json=payload, timeout=60)
        r.raise_for_status()
        data = r.json()
        return data["choices"][0]["message"]["content"]

    def _gemini_complete(self, messages, system, max_tokens, temperature):
        # Gemini uses a different API format
        url = f"{self.base_url}/models/{self.model}:generateContent?key={self.api_key}"
        headers = {"Content-Type": "application/json"}

        # Convert messages to Gemini format
        contents = []
        if system:
            contents.append({"role": "user", "parts": [{"text": f"[SYSTEM CONTEXT]: {system}"}]})
            contents.append({"role": "model", "parts": [{"text": "Understood. I'll follow these instructions."}]})

        for msg in messages:
            role = "model" if msg["role"] == "assistant" else "user"
            contents.append({"role": role, "parts": [{"text": msg["content"]}]})

        payload = {
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": temperature
            }
        }
        r = requests.post(url, headers=headers, json=payload, timeout=60)
        r.raise_for_status()
        data = r.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]

    def _anthropic_complete(self, messages, system, max_tokens, temperature):
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system,
            "messages": messages
        }
        r = requests.post(f"{self.base_url}/messages",
                          headers=headers, json=payload, timeout=60)
        r.raise_for_status()
        data = r.json()
        return data["content"][0]["text"]


class SwarmOrchestrator:
    """Manages multiple LLM agents and routes tasks to the right one."""

    def __init__(self, config, ui):
        self.config = config
        self.ui = ui
        self._clients: Dict[str, LLMClient] = {}
        self._init_clients()

    def _init_clients(self):
        for m in self.config.get_available_models():
            client = LLMClient(m)
            self._clients[m["role"]] = client
            # Also index by provider for fallback
            self._clients[f"provider_{m['provider']}"] = client

    def get_active_models(self) -> List[Dict]:
        return self.config.get_available_models()

    def _get_client(self, role: str) -> Optional[LLMClient]:
        """Get client for role, fall back to any available."""
        if role in self._clients:
            return self._clients[role]
        # Fallback to first available
        if self._clients:
            return next(iter(self._clients.values()))
        return None

    def _system_for_role(self, role: str) -> str:
        addon = ROLE_ADDONS.get(role, "")
        return MASTER_SYSTEM + "\n" + addon

    def ask(self, role: str, prompt: str, context: Dict = None,
            json_output: bool = False, max_tokens: int = 4096) -> str:
        """Ask a specific role agent."""
        client = self._get_client(role)
        if not client:
            return "[No AI models configured]"

        system = self._system_for_role(role)
        if json_output:
            system += "\n\nIMPORTANT: Respond ONLY with valid JSON. No markdown, no explanation, no backticks."

        msg_content = prompt
        if context:
            msg_content = f"CONTEXT:\n{json.dumps(context, indent=2)}\n\nTASK:\n{prompt}"

        messages = [{"role": "user", "content": msg_content}]
        return client.complete(messages, system=system, max_tokens=max_tokens)

    def multi_ask(self, prompt: str, roles: List[str] = None,
                  context: Dict = None) -> Dict[str, str]:
        """Ask multiple role agents the same question, return all answers."""
        if roles is None:
            roles = list(set(c.role for c in self._clients.values()
                             if not c.role.startswith("provider_")))

        results = {}
        for role in roles:
            client = self._get_client(role)
            if client:
                console.print(f"  [dim]Asking {role} ({client.provider}/{client.model})...[/dim]")
                results[role] = self.ask(role, prompt, context=context)
        return results

    def chat(self, user_message: str, context: Dict = None,
             history: List[Dict] = None) -> str:
        """General chat - uses orchestrator or first available model."""
        client = self._get_client("orchestrator")
        if not client:
            return "[No models configured]"

        system = self._system_for_role("orchestrator")
        messages = []
        if history:
            messages.extend(history)
        msg_content = user_message
        if context:
            msg_content = f"CONTEXT:\n{json.dumps(context, indent=2)}\n\n{user_message}"
        messages.append({"role": "user", "content": msg_content})
        return client.complete(messages, system=system)

    def orchestrate_hunt(self, target: str, recon_data: Dict,
                         mode: str = "ask") -> Dict:
        """Main orchestration: given recon data, plan the hunt."""
        prompt = f"""
Target: {target}

Recon data:
{json.dumps(recon_data, indent=2)}

Plan the attack:
1. Rank the top 5 attack vectors by: (exploitability × impact)
2. For each vector: exact tool commands and payloads to test
3. Identify chain opportunities
4. Suggest the order of testing

Respond as JSON:
{{
  "priority_vectors": [
    {{
      "rank": 1,
      "vuln_class": "...",
      "target_endpoint": "...",
      "rationale": "...",
      "commands": ["..."],
      "chain_potential": "..."
    }}
  ],
  "quick_wins": ["..."],
  "chain_map": {{...}}
}}
"""
        result = self.ask("orchestrator", prompt, json_output=True)
        try:
            return json.loads(result)
        except Exception:
            return {"raw": result, "priority_vectors": []}

    def find_chains(self, findings: List[Dict]) -> List[Dict]:
        """Given a list of findings, identify exploit chains."""
        prompt = f"""
Findings discovered so far:
{json.dumps(findings, indent=2)}

Analyze for exploit chains:
1. Which bugs can be combined for higher impact?
2. What's the full attack path?
3. Rank chains by combined severity × likelihood

Return JSON:
{{
  "chains": [
    {{
      "chain_name": "...",
      "steps": ["bug_id_1", "bug_id_2"],
      "narrative": "Attacker does X, which enables Y, resulting in Z",
      "combined_severity": "Critical",
      "cvss_increase": "+2.5",
      "payout_multiplier": "3x"
    }}
  ]
}}
"""
        result = self.ask("chainer", prompt, json_output=True)
        try:
            data = json.loads(result)
            return data.get("chains", [])
        except Exception:
            return []

    def analyze_request(self, raw_request: str, source: str = "unknown") -> Dict:
        """Deep analysis of an HTTP request for vulnerabilities."""
        prompt = f"""
Analyze this HTTP request for ALL potential vulnerabilities:

```
{raw_request}
```
Source: {source}

Perform:
1. Parse every parameter, header, path component, cookie
2. Identify injection points and their context
3. For EACH parameter: list possible vuln classes
4. Generate specific test payloads
5. Identify auth tokens, API keys, interesting data
6. Check for business logic issues
7. Suggest chain opportunities

Return JSON:
{{
  "parsed": {{
    "method": "...",
    "path": "...",
    "host": "...",
    "parameters": {{}},
    "headers": {{}},
    "cookies": {{}},
    "body": {{}}
  }},
  "injection_points": [
    {{
      "parameter": "...",
      "location": "query|body|header|cookie|path",
      "context": "...",
      "vuln_classes": ["..."],
      "payloads": ["..."],
      "priority": "high|medium|low"
    }}
  ],
  "interesting_findings": ["..."],
  "auth_analysis": {{...}},
  "chain_opportunities": ["..."],
  "immediate_tests": ["exact curl commands to test"]
}}
"""
        # Use multiple agents for comprehensive analysis
        result_hunter = self.ask("hunter", prompt, json_output=True, max_tokens=6000)
        try:
            return json.loads(result_hunter)
        except Exception:
            return {"raw_analysis": result_hunter}

    def validate_finding(self, finding: Dict, target: str) -> Dict:
        """Validate a finding for real impact."""
        prompt = f"""
Validate this security finding:

Target: {target}
Finding: {json.dumps(finding, indent=2)}

Apply the 7-question validation:
1. Can an attacker do this RIGHT NOW without special conditions?
2. Does it require victim interaction? (if so, is it realistic?)
3. What is the actual harm? (not "could")
4. Is this in scope?
5. Has this been reported before? (common for this target?)
6. What's the CVSS 3.1 score + vector string?
7. Is this a dupe risk?

Return JSON:
{{
  "verdict": "valid|invalid|needs_more_info",
  "confidence": 0-100,
  "impact": "Critical|High|Medium|Low|Informational",
  "cvss_score": 0.0,
  "cvss_vector": "CVSS:3.1/...",
  "real_impact": "...",
  "poc_steps": ["..."],
  "poc_curl": "...",
  "rejection_reason": "null or reason",
  "report_worthy": true/false
}}
"""
        result = self.ask("validator", prompt, json_output=True)
        try:
            return json.loads(result)
        except Exception:
            return {"raw": result, "verdict": "needs_more_info"}

    def write_report(self, finding: Dict, target: str, platform: str = "hackerone") -> str:
        """Write a professional bug bounty report."""
        prompt = f"""
Write a professional {platform} bug report for this validated finding.

Target: {target}
Finding: {json.dumps(finding, indent=2)}

Format:
## Title
[Vuln Type] in [Component] allows [Impact] (max 80 chars)

## Severity
[Critical/High/Medium/Low] — CVSS: X.X ([vector])

## Summary
2-3 sentences: what is it, why it's bad, what an attacker can do

## Steps to Reproduce
1. Numbered exact steps
2. Include exact HTTP requests (curl format)
3. Include expected vs actual behavior

## Proof of Concept
```
Working curl or Python PoC
```

## Impact
Concrete impact on real users. Numbers where possible.
"An unauthenticated attacker can..."

## Remediation
Specific fix, not generic advice.
"""
        return self.ask("reporter", prompt, max_tokens=3000)
