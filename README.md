# ⚡ SwarmBounty

**Multi-LLM AI Swarm Bug Bounty Framework for Kali Linux**

> Autonomous recon → attack planning → vuln hunting → validation → chaining → report writing  
> Built on [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) methodology

---

## Features

- **Multi-LLM Swarm** — Use Gemini, ChatGPT, DeepSeek, Groq (free!), Claude simultaneously
- **Swarm Roles** — Each model specializes: orchestrator, hunter, validator, reporter, chainer
- **`--yolo` mode** — Fully autonomous: AI decides and executes everything
- **`--ask` mode** — Interactive: AI suggests, you approve/modify each step
- **Live Chat** — Paste curl/Burp requests in chat, get instant attack analysis
- **Request Analysis** — Parse raw HTTP, curl commands, Burp Suite exports
- **Session Memory** — Persists across runs; learns from past hunts on same target
- **20 Vuln Classes** — SQLi, XSS, SSRF, IDOR, SSTI, OAuth, GraphQL, LLM injection + more
- **Bug Chaining** — Automatically identifies A→B→C exploit chains (3-10x payout)
- **Report Writing** — HackerOne, Bugcrowd, Intigriti, Immunefi formats + HTML report

---

## Installation (Kali Linux)

```bash
# Clone
git clone https://github.com/yourname/swarmbounty.git
cd swarmbounty

# Install
bash setup.sh

# Or manually:
pip3 install -r requirements.txt --break-system-packages
chmod +x swarmbounty.py
```

---

## API Keys (Free Options Available)

Run `python3 swarmbounty.py --config` to set up keys.

| Provider | Free Tier | Get Key |
|----------|-----------|---------|
| Google Gemini | ✅ Yes | https://aistudio.google.com/app/apikey |
| DeepSeek | ✅ Yes (cheap) | https://platform.deepseek.com/api_keys |
| Groq (Llama/Mixtral) | ✅ Yes | https://console.groq.com/keys |
| OpenAI / ChatGPT | ❌ Paid | https://platform.openai.com/api-keys |
| Anthropic Claude | ❌ Paid | https://console.anthropic.com/ |

**You only need ONE key to start. Add more for swarm mode.**

Or set environment variables:
```bash
export GEMINI_API_KEY="your-key"
export DEEPSEEK_API_KEY="your-key"
export GROQ_API_KEY="your-key"
```

---

## Usage

### Hunt Modes

```bash
# Interactive (ASK) mode - confirm every step
python3 swarmbounty.py --target example.com --ask

# Autonomous (YOLO) mode - AI decides everything
python3 swarmbounty.py --target example.com --yolo

# Quick scan
python3 swarmbounty.py --target example.com --yolo --quick

# Deep scan (multi-agent thorough analysis)
python3 swarmbounty.py --target example.com --yolo --deep

# Focus on specific vuln class
python3 swarmbounty.py --target example.com --vuln ssrf

# With scope file
python3 swarmbounty.py --target example.com --scope scope.txt
```

### Live Chat (Best for Manual Testing)

```bash
python3 swarmbounty.py --chat
```

In chat, you can:
- Ask questions: `"What's the best way to test for IDOR here?"`
- Paste curl commands (auto-detected, buffer + `/analyze`)
- Paste Burp Suite requests line by line, then `/analyze`
- Use `/hunt example.com` to start a hunt
- Use `/chain` to find chains from discovered bugs
- Toggle `/yolo` or `/ask` mode mid-session

**Example chat session:**
```
[ASK]> /hunt api.example.com

[ASK][api.example.com]> POST /api/v2/users/profile HTTP/1.1
[ASK][api.example.com]> Host: api.example.com
[ASK][api.example.com]> Authorization: Bearer eyJhbG...
[ASK][api.example.com]> {"user_id": 12345, "email": "test@test.com"}
[ASK][api.example.com]> /analyze

[ASK][api.example.com]> /chain

[ASK][api.example.com]> /report
```

**Curl command analysis:**
```
[ASK]> curl -X POST https://api.example.com/users/123/delete -H "Cookie: session=abc123" -d '{"confirm": true}'
[ASK]> /analyze
```

### Session Management

```bash
# List all saved sessions
python3 swarmbounty.py --session-list

# Resume a session (picks up where you left off)
python3 swarmbounty.py --pickup example_com_1234567890

# Generate report from session
python3 swarmbounty.py --report example_com_1234567890
```

### Analyze a Burp Request File

```bash
# Save request from Burp → right-click → "Save item" → request.txt
python3 swarmbounty.py --burp request.txt

# Analyze a curl command
python3 swarmbounty.py --curl "curl -X POST https://example.com/login -d 'user=admin&pass=test'"
```

---

## Swarm Architecture

```
┌─────────────────────────────────────────────────────┐
│                  ORCHESTRATOR                        │
│  (strongest model) - Plans attack, routes tasks      │
└──────────┬──────────┬──────────┬──────────┬─────────┘
           │          │          │          │
    ┌──────▼──┐ ┌─────▼──┐ ┌────▼───┐ ┌────▼────┐
    │  RECON  │ │ HUNTER │ │VALIDATR│ │REPORTER │
    │ (maps   │ │(payloads│ │(impact │ │(H1/BC   │
    │ surface)│ │bypass)  │ │ PoC)   │ │ report) │
    └─────────┘ └────────┘ └────────┘ └─────────┘
                               │
                        ┌──────▼──────┐
                        │   CHAINER   │
                        │ (A→B→C bugs │
                        │  multiplier)│
                        └─────────────┘
```

With 3 free API keys (Gemini + DeepSeek + Groq), you get:
- Gemini: Orchestrator (best reasoning)
- DeepSeek: Hunter + Chainer (strong code/logic)
- Groq: Validator (fast, high volume)

---

## Vulnerability Classes Covered

**Web2:**
SQLi, XSS (stored/reflected/DOM), SSRF, IDOR, SSTI, Open Redirect, File Upload Bypass,
CORS Misconfig, CSRF, XXE, Race Conditions, HTTP Request Smuggling, Cache Poisoning,
OAuth/SSO Bypass, Auth/2FA Bypass, Business Logic, GraphQL Injection, Subdomain Takeover,
Cloud Misconfig (S3/GCP/Azure), Timing Side-Channels

**LLM/AI Security:**
Prompt Injection, Indirect Injection, Chatbot IDOR, System Prompt Extraction,
ASCII Smuggling, RCE via Code Tools, Agent Exfil Channels (ASI01-ASI10)

**Web3 (Solidity):**
Reentrancy, Flash Loans, Access Control, Signature Replay, Oracle Manipulation

---

## Bug Chaining (3-10x Payout)

SwarmBounty automatically identifies:

```
IDOR → Auth Bypass → Account Takeover
SSRF → Cloud Metadata → API Keys → RCE
XSS → Session Hijack → ATO
Open Redirect → OAuth Token Theft
S3 Public → JS Bundle → Secrets → Full Compromise
```

---

## Session Memory & Learning

Each session is saved to `~/.swarmbounty/sessions/`.
When you hunt the same target again, the swarm:
- Knows which vuln classes were already found
- Avoids re-testing confirmed paths
- Applies patterns from previous findings
- Suggests unexplored attack surface

Knowledge accumulates in `~/.swarmbounty/knowledge.json`.

---

## Tool Integration (Optional)

SwarmBounty auto-detects and uses these tools if installed:

| Tool | Purpose | Install |
|------|---------|---------|
| subfinder | Subdomain enum | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx | Live host probe | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| nuclei | Template scanner | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| gau | URL discovery | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| sqlmap | SQLi testing | `apt install sqlmap` |
| nmap | Port scanning | `apt install nmap` |
| dalfox | XSS scanner | `go install github.com/hahwul/dalfox/v2@latest` |
| whatweb | Tech fingerprint | `apt install whatweb` |

---

## Reports

Reports are saved to `~/.swarmbounty/reports/`.
Each session generates:
- `SUMMARY.md` — Overview of all findings
- `FIND-001_xss.md` — Individual finding in H1/Bugcrowd format
- `report.html` — Burp-style HTML report (open in browser)

---

## Ethics

> ⚠ **Only use on systems you have explicit written permission to test.**
> This tool is for authorized bug bounty programs and penetration testing engagements only.
> Unauthorized testing is illegal and unethical.

---

*Built on [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) methodology*
