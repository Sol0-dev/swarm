"""
SessionMemory - Persists hunt data between sessions.
The swarm improves over time: each session's findings inform future hunts.
Stored in ~/.swarmbounty/sessions/
"""

import json
import uuid
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict

SESSIONS_DIR = Path.home() / ".swarmbounty" / "sessions"
KNOWLEDGE_FILE = Path.home() / ".swarmbounty" / "knowledge.json"
REPORTS_DIR = Path.home() / ".swarmbounty" / "reports"


class SessionMemory:
    def __init__(self):
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        self._knowledge = self._load_knowledge()

    def new_session(self, target: str) -> Dict:
        """Create a new hunting session."""
        session_id = f"{target.replace('.', '_')}_{int(time.time())}"
        session = {
            "id": session_id,
            "target": target,
            "created": datetime.now().isoformat(),
            "updated": datetime.now().isoformat(),
            "status": "active",
            "recon": {},
            "findings": [],
            "chains": [],
            "validated": [],
            "reports": [],
            "notes": [],
            "tool_output": {},
            "requests_analyzed": [],
            "bugs_found": 0,
            "past_knowledge": self.get_target_knowledge(target)
        }
        self.save_session(session)
        return session

    def save_session(self, session: Dict):
        """Save session to disk."""
        session["updated"] = datetime.now().isoformat()
        session_file = SESSIONS_DIR / f"{session['id']}.json"
        with open(session_file, "w") as f:
            json.dump(session, f, indent=2)

    def load_session(self, session_id: str) -> Optional[Dict]:
        """Load a session by ID."""
        session_file = SESSIONS_DIR / f"{session_id}.json"
        if session_file.exists():
            with open(session_file) as f:
                return json.load(f)
        # Try partial match
        for f in SESSIONS_DIR.glob(f"*{session_id}*.json"):
            with open(f) as fh:
                return json.load(fh)
        return None

    def list_sessions(self) -> List[Dict]:
        """List all sessions with summary info."""
        sessions = []
        for f in sorted(SESSIONS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                with open(f) as fh:
                    s = json.load(fh)
                sessions.append({
                    "id": s["id"],
                    "target": s.get("target", "unknown"),
                    "bugs_found": len(s.get("findings", [])),
                    "date": s.get("created", "")[:10],
                    "status": s.get("status", "unknown")
                })
            except Exception:
                pass
        return sessions

    def add_finding(self, session: Dict, finding: Dict) -> Dict:
        """Add a finding to a session."""
        finding.setdefault("id", f"FIND-{len(session['findings'])+1:03d}")
        finding.setdefault("discovered_at", datetime.now().isoformat())
        finding.setdefault("validated", False)
        session["findings"].append(finding)
        session["bugs_found"] = len(session["findings"])
        self.save_session(session)
        # Update knowledge base
        self._update_knowledge(session["target"], finding)
        return finding

    def add_recon(self, session: Dict, recon_type: str, data: any):
        """Add recon data to session."""
        session["recon"][recon_type] = data
        session["recon"]["last_updated"] = datetime.now().isoformat()
        self.save_session(session)

    def add_tool_output(self, session: Dict, tool: str, output: str):
        """Save raw tool output."""
        session["tool_output"][tool] = {
            "output": output[:50000],  # cap at 50k chars
            "timestamp": datetime.now().isoformat()
        }
        self.save_session(session)

    def add_request(self, session: Dict, request: Dict):
        """Log an analyzed request."""
        request["analyzed_at"] = datetime.now().isoformat()
        session["requests_analyzed"].append(request)
        self.save_session(session)

    def add_note(self, session: Dict, note: str):
        """Add a manual note to the session."""
        session["notes"].append({
            "note": note,
            "timestamp": datetime.now().isoformat()
        })
        self.save_session(session)

    # ─── Knowledge Base (cross-session learning) ─────────────────────────────

    def _load_knowledge(self) -> Dict:
        if KNOWLEDGE_FILE.exists():
            try:
                with open(KNOWLEDGE_FILE) as f:
                    return json.load(f)
            except Exception:
                pass
        return {"targets": {}, "patterns": [], "global_stats": {}}

    def _save_knowledge(self):
        with open(KNOWLEDGE_FILE, "w") as f:
            json.dump(self._knowledge, f, indent=2)

    def _update_knowledge(self, target: str, finding: Dict):
        """Update the knowledge base with a new finding."""
        if target not in self._knowledge["targets"]:
            self._knowledge["targets"][target] = {
                "findings": [], "vuln_classes": {}, "endpoints": []
            }

        t = self._knowledge["targets"][target]
        # Track vuln classes
        vuln = finding.get("vuln_class", "unknown")
        t["vuln_classes"][vuln] = t["vuln_classes"].get(vuln, 0) + 1

        # Store condensed finding
        t["findings"].append({
            "vuln_class": vuln,
            "endpoint": finding.get("endpoint", ""),
            "severity": finding.get("severity", "unknown"),
            "date": finding.get("discovered_at", "")[:10]
        })

        self._save_knowledge()

    def get_target_knowledge(self, target: str) -> Dict:
        """Get accumulated knowledge about a target from past sessions."""
        if target in self._knowledge["targets"]:
            return self._knowledge["targets"][target]
        # Also check for subdomains of the same base domain
        base = ".".join(target.split(".")[-2:])
        related = {}
        for t, data in self._knowledge["targets"].items():
            if t.endswith(base):
                related[t] = data
        return related if related else {}

    def get_global_patterns(self) -> List[str]:
        """Get cross-target patterns discovered."""
        return self._knowledge.get("patterns", [])

    def get_session_context(self, session: Dict) -> Dict:
        """Get condensed session context for AI prompts (avoid token bloat)."""
        return {
            "target": session["target"],
            "findings_summary": [
                {
                    "id": f["id"],
                    "vuln_class": f.get("vuln_class"),
                    "severity": f.get("severity"),
                    "endpoint": f.get("endpoint"),
                    "validated": f.get("validated", False)
                }
                for f in session["findings"][-20:]  # last 20
            ],
            "recon_summary": {
                k: (v[:500] if isinstance(v, str) else
                    (len(v) if isinstance(v, list) else "present"))
                for k, v in session["recon"].items()
                if k != "last_updated"
            },
            "past_knowledge": session.get("past_knowledge", {}),
            "notes": session.get("notes", [])[-5:]
        }
