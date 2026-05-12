"""
Config manager - handles API keys, model routing, swarm role assignment.
Stored in ~/.swarmbounty/config.json (never committed to git).
"""

import json
import os
from pathlib import Path
from typing import Optional, List, Dict


CONFIG_DIR = Path.home() / ".swarmbounty"
CONFIG_FILE = CONFIG_DIR / "config.json"

# Model definitions with free tier info
PROVIDER_MODELS = {
    "gemini": {
        "models": [
            "gemini-2.0-flash",          # free, fast
            "gemini-2.0-flash-thinking",  # free, reasoning
            "gemini-1.5-pro",             # free tier
            "gemini-1.5-flash",           # free, fastest
        ],
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "free": True
    },
    "deepseek": {
        "models": [
            "deepseek-chat",              # cheap/free credits
            "deepseek-reasoner",          # R1 reasoning
            "deepseek-coder",             # code focused
        ],
        "base_url": "https://api.deepseek.com/v1",
        "free": True
    },
    "groq": {
        "models": [
            "llama-3.3-70b-versatile",   # free tier
            "llama-3.1-8b-instant",       # free, very fast
            "mixtral-8x7b-32768",         # free
            "gemma2-9b-it",               # free
        ],
        "base_url": "https://api.groq.com/openai/v1",
        "free": True
    },
    "openai": {
        "models": [
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-4-turbo",
        ],
        "base_url": "https://api.openai.com/v1",
        "free": False
    },
    "anthropic": {
        "models": [
            "claude-sonnet-4-20250514",
            "claude-haiku-4-5-20251001",
            "claude-opus-4-20250514",
        ],
        "base_url": "https://api.anthropic.com/v1",
        "free": False
    }
}

# Swarm role descriptions
SWARM_ROLES = {
    "orchestrator": "Coordinates other agents, decides attack strategy, prioritizes findings",
    "recon":        "Subdomain enum, asset discovery, technology fingerprinting",
    "hunter":       "Active vulnerability hunting, payload generation, exploitation",
    "validator":    "Confirms real impact, validates PoCs, filters false positives",
    "chainer":      "Finds bug chains, computes impact multipliers, ATO paths",
    "reporter":     "Writes HackerOne/Bugcrowd reports, CVSS scoring, PoC formatting",
}


class Config:
    def __init__(self):
        CONFIG_DIR.mkdir(exist_ok=True)
        self._data = self._load()

    def _load(self) -> dict:
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    return json.load(f)
            except Exception:
                pass
        return {"api_keys": {}, "model_roles": {}, "settings": {}}

    def save(self):
        with open(CONFIG_FILE, "w") as f:
            json.dump(self._data, f, indent=2)
        CONFIG_FILE.chmod(0o600)

    def get_api_key(self, provider: str) -> Optional[str]:
        # Check env var first, then config file
        env_map = {
            "gemini": "GEMINI_API_KEY",
            "openai": "OPENAI_API_KEY",
            "deepseek": "DEEPSEEK_API_KEY",
            "groq": "GROQ_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
        }
        env_key = env_map.get(provider)
        if env_key:
            val = os.environ.get(env_key)
            if val:
                return val
        return self._data["api_keys"].get(provider)

    def set_api_key(self, provider: str, key: str):
        self._data["api_keys"][provider] = key

    def get_available_models(self) -> List[Dict]:
        """Return list of all models we have keys for."""
        models = []
        for provider, info in PROVIDER_MODELS.items():
            key = self.get_api_key(provider)
            if key:
                # Use first model by default (or configured)
                configured_model = self._data.get("model_roles", {}).get(provider, {}).get("model")
                model = configured_model or info["models"][0]
                role = self._data.get("model_roles", {}).get(provider, {}).get("role", "general")
                models.append({
                    "provider": provider,
                    "model": model,
                    "api_key": key,
                    "base_url": info["base_url"],
                    "role": role,
                    "all_models": info["models"],
                    "free": info["free"]
                })
        return models

    def auto_assign_roles(self, available: List[Dict]):
        """Automatically assign swarm roles based on model capabilities."""
        roles_to_fill = ["orchestrator", "hunter", "validator", "reporter", "recon", "chainer"]
        # Role priority: prefer stronger models for orchestrator
        role_idx = 0
        for m in available:
            if role_idx < len(roles_to_fill):
                role = roles_to_fill[role_idx]
                if m["provider"] not in self._data["model_roles"]:
                    self._data["model_roles"][m["provider"]] = {}
                self._data["model_roles"][m["provider"]]["role"] = role
                self._data["model_roles"][m["provider"]]["model"] = m["model"]
                role_idx += 1

    def get_setting(self, key: str, default=None):
        return self._data["settings"].get(key, default)

    def set_setting(self, key: str, value):
        self._data["settings"][key] = value
        self.save()

    def get_model_for_role(self, role: str) -> Optional[Dict]:
        """Get the configured model for a specific swarm role."""
        available = self.get_available_models()
        for m in available:
            if m.get("role") == role:
                return m
        # Fallback: return first available
        return available[0] if available else None
