"""
RequestParser - Parses curl commands, Burp Suite requests, raw HTTP.
Extracts injection points and runs multi-agent analysis.
"""

import re
import json
import shlex
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax

console = Console()


class RequestParser:
    def __init__(self, swarm):
        self.swarm = swarm

    def parse(self, raw: str, source: str = "unknown") -> Dict:
        """Auto-detect format and parse."""
        raw = raw.strip()
        if raw.startswith("curl"):
            return self._parse_curl(raw)
        elif re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\s', raw):
            return self._parse_http_raw(raw)
        else:
            # Try to detect pasted Burp format
            if "\r\n" in raw or (re.search(r'^Host:', raw, re.MULTILINE)):
                return self._parse_http_raw(raw)
            return {"raw": raw, "format": "unknown", "source": source}

    def _parse_curl(self, curl_cmd: str) -> Dict:
        """Parse a curl command into structured data."""
        result = {
            "format": "curl",
            "method": "GET",
            "url": "",
            "headers": {},
            "body": "",
            "cookies": {}
        }
        try:
            # Normalize line continuations
            curl_cmd = curl_cmd.replace("\\\n", " ").replace("\\\r\n", " ")
            tokens = shlex.split(curl_cmd)
            i = 1  # skip 'curl'
            while i < len(tokens):
                tok = tokens[i]
                if tok in ("-X", "--request") and i + 1 < len(tokens):
                    result["method"] = tokens[i + 1]
                    i += 2
                elif tok in ("-H", "--header") and i + 1 < len(tokens):
                    hdr = tokens[i + 1]
                    if ":" in hdr:
                        k, v = hdr.split(":", 1)
                        result["headers"][k.strip()] = v.strip()
                        if k.strip().lower() == "cookie":
                            result["cookies"] = self._parse_cookies(v.strip())
                    i += 2
                elif tok in ("-d", "--data", "--data-raw", "--data-binary") and i + 1 < len(tokens):
                    result["body"] = tokens[i + 1]
                    if result["method"] == "GET":
                        result["method"] = "POST"
                    i += 2
                elif tok in ("-b", "--cookie") and i + 1 < len(tokens):
                    result["cookies"].update(self._parse_cookies(tokens[i + 1]))
                    i += 2
                elif not tok.startswith("-"):
                    result["url"] = tok
                    i += 1
                else:
                    i += 1

            # Parse URL components
            if result["url"]:
                parsed = urlparse(result["url"])
                result["host"] = parsed.netloc
                result["path"] = parsed.path
                result["query_params"] = {k: v[0] for k, v in parse_qs(parsed.query).items()}

            # Parse body
            result["body_parsed"] = self._parse_body(
                result.get("body", ""),
                result.get("headers", {}).get("Content-Type", "")
            )
        except Exception as e:
            result["parse_error"] = str(e)
        return result

    def _parse_http_raw(self, raw: str) -> Dict:
        """Parse a raw HTTP request (from Burp Suite or similar)."""
        result = {"format": "http_raw", "headers": {}, "cookies": {}}
        try:
            # Normalize line endings
            raw = raw.replace("\r\n", "\n")
            lines = raw.split("\n")

            # First line: METHOD PATH HTTP/VERSION
            first = lines[0].strip()
            m = re.match(r'^(\w+)\s+(\S+)\s+(HTTP/[\d.]+)?', first)
            if m:
                result["method"] = m.group(1)
                result["path"] = m.group(2)
                result["http_version"] = m.group(3) or "HTTP/1.1"

            # Headers
            i = 1
            while i < len(lines) and lines[i].strip():
                line = lines[i]
                if ":" in line:
                    k, v = line.split(":", 1)
                    result["headers"][k.strip()] = v.strip()
                    if k.strip().lower() == "host":
                        result["host"] = v.strip()
                    elif k.strip().lower() == "cookie":
                        result["cookies"] = self._parse_cookies(v.strip())
                i += 1

            # Body (after blank line)
            result["body"] = "\n".join(lines[i+1:]).strip()
            result["url"] = f"https://{result.get('host', '')}{result.get('path', '')}"

            # Parse query params
            if "?" in result.get("path", ""):
                path, qs = result["path"].split("?", 1)
                result["path"] = path
                result["query_params"] = {k: v[0] for k, v in parse_qs(qs).items()}
            else:
                result["query_params"] = {}

            # Parse body
            result["body_parsed"] = self._parse_body(
                result.get("body", ""),
                result.get("headers", {}).get("Content-Type", "")
            )
        except Exception as e:
            result["parse_error"] = str(e)
        return result

    def _parse_cookies(self, cookie_str: str) -> Dict:
        cookies = {}
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
        return cookies

    def _parse_body(self, body: str, content_type: str) -> Dict:
        if not body:
            return {}
        ct = content_type.lower()
        try:
            if "json" in ct or body.lstrip().startswith("{"):
                return {"type": "json", "data": json.loads(body)}
            elif "x-www-form-urlencoded" in ct:
                return {"type": "form", "data": {k: v[0] for k, v in parse_qs(body).items()}}
            elif "xml" in ct:
                return {"type": "xml", "data": body}
            else:
                return {"type": "raw", "data": body}
        except Exception:
            return {"type": "raw", "data": body}

    def get_injection_points(self, parsed: Dict) -> List[Dict]:
        """Extract all potential injection points from parsed request."""
        points = []

        # Query parameters
        for k, v in parsed.get("query_params", {}).items():
            points.append({
                "name": k, "value": v, "location": "query",
                "context": f"URL query string parameter"
            })

        # Path parameters (numbered segments)
        path = parsed.get("path", "")
        for segment in path.split("/"):
            if segment and (segment.isdigit() or re.match(r'^[0-9a-f-]{8,}$', segment)):
                points.append({
                    "name": "path_segment",
                    "value": segment,
                    "location": "path",
                    "context": f"Path segment - possible IDOR or injection point"
                })

        # Body parameters
        body_parsed = parsed.get("body_parsed", {})
        if body_parsed.get("type") in ("json", "form"):
            data = body_parsed.get("data", {})
            self._extract_nested(data, points, "body", "")

        # Interesting headers
        interesting_headers = [
            "x-forwarded-for", "x-real-ip", "referer", "origin",
            "x-forwarded-host", "x-original-url", "x-rewrite-url",
            "content-type", "x-api-key", "authorization"
        ]
        for k, v in parsed.get("headers", {}).items():
            if k.lower() in interesting_headers:
                points.append({
                    "name": k, "value": v, "location": "header",
                    "context": f"Interesting header"
                })

        # Cookies
        for k, v in parsed.get("cookies", {}).items():
            points.append({
                "name": k, "value": v, "location": "cookie",
                "context": f"Cookie value"
            })

        return points

    def _extract_nested(self, data, points, location, prefix):
        """Recursively extract injection points from nested JSON/form data."""
        if isinstance(data, dict):
            for k, v in data.items():
                key_path = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (str, int, float)):
                    points.append({
                        "name": key_path, "value": str(v),
                        "location": location, "context": f"JSON/form body parameter"
                    })
                elif isinstance(v, (dict, list)):
                    self._extract_nested(v, points, location, key_path)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                self._extract_nested(item, points, location, f"{prefix}[{i}]")

    def analyze_interactive(self, raw: str, source: str = "chat") -> List[Dict]:
        """Full interactive analysis with rich output."""
        console.print(f"\n[cyan]Parsing {source} request...[/cyan]")
        parsed = self.parse(raw, source)
        injection_points = self.get_injection_points(parsed)

        # Display parsed summary
        console.print(Panel(
            f"[bold]{parsed.get('method', '?')}[/bold] {parsed.get('url', parsed.get('path', '?'))}\n"
            f"[dim]Host: {parsed.get('host', '?')} | "
            f"Body: {parsed.get('body_parsed', {}).get('type', 'none')} | "
            f"Cookies: {len(parsed.get('cookies', {}))} | "
            f"Injection points: {len(injection_points)}[/dim]",
            title="[bold cyan]Parsed Request[/bold cyan]",
            style="cyan"
        ))

        if injection_points:
            table = Table(title="Injection Points", style="yellow")
            table.add_column("Parameter", style="bold")
            table.add_column("Location")
            table.add_column("Value (truncated)")
            for p in injection_points:
                val = str(p["value"])[:40] + ("..." if len(str(p["value"])) > 40 else "")
                table.add_row(p["name"], p["location"], val)
            console.print(table)

        # Run swarm analysis
        console.print("\n[cyan]Running swarm analysis...[/cyan]")
        analysis = self.swarm.analyze_request(raw, source)

        # Display findings
        if isinstance(analysis, dict):
            if "injection_points" in analysis:
                console.print("\n[bold yellow]🎯 AI-Identified Attack Vectors:[/bold yellow]")
                for point in analysis.get("injection_points", []):
                    priority = point.get("priority", "medium")
                    color = {"high": "red", "medium": "yellow", "low": "dim"}.get(priority, "white")
                    console.print(
                        f"  [{color}][{priority.upper()}][/{color}] "
                        f"[bold]{point.get('parameter')}[/bold] "
                        f"({point.get('location')}) → {', '.join(point.get('vuln_classes', []))}"
                    )

            if "immediate_tests" in analysis:
                console.print("\n[bold green]⚡ Immediate Tests:[/bold green]")
                for test in analysis.get("immediate_tests", [])[:5]:
                    console.print(Syntax(test, "bash", theme="monokai", word_wrap=True))

            if "interesting_findings" in analysis:
                console.print("\n[bold red]🔍 Notable Findings:[/bold red]")
                for finding in analysis.get("interesting_findings", []):
                    console.print(f"  • {finding}")

            if "chain_opportunities" in analysis:
                console.print("\n[bold magenta]🔗 Chain Opportunities:[/bold magenta]")
                for chain in analysis.get("chain_opportunities", []):
                    console.print(f"  • {chain}")

            if "auth_analysis" in analysis:
                auth = analysis["auth_analysis"]
                if auth:
                    console.print(f"\n[bold]Auth Analysis:[/bold] {json.dumps(auth, indent=2)[:500]}")
        else:
            console.print(Panel(str(analysis)[:2000], title="Analysis", style="dim"))

        # Convert to findings format
        findings = []
        if isinstance(analysis, dict):
            for point in analysis.get("injection_points", []):
                if point.get("priority") == "high":
                    findings.append({
                        "vuln_class": point.get("vuln_classes", ["unknown"])[0],
                        "endpoint": parsed.get("url", ""),
                        "parameter": point.get("parameter"),
                        "severity": "High",
                        "source": "request_analysis",
                        "details": point,
                        "validated": False
                    })

        return findings

    def to_curl(self, parsed: Dict) -> str:
        """Convert a parsed request back to curl command."""
        parts = ["curl"]
        if parsed.get("method") and parsed["method"] != "GET":
            parts.append(f"-X {parsed['method']}")
        for k, v in parsed.get("headers", {}).items():
            if k.lower() != "cookie":
                parts.append(f"-H '{k}: {v}'")
        if parsed.get("cookies"):
            cookie_str = "; ".join(f"{k}={v}" for k, v in parsed["cookies"].items())
            parts.append(f"-b '{cookie_str}'")
        if parsed.get("body"):
            body = parsed["body"].replace("'", "'\\''")
            parts.append(f"--data-raw '{body}'")
        parts.append(f"'{parsed.get('url', '')}'")
        return " \\\n  ".join(parts)
