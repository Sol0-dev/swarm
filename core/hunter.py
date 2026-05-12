"""
BugHunter - Main hunting engine.
Orchestrates recon → vuln hunting → validation → chaining.
Supports --yolo (autonomous) and --ask (interactive) modes.
"""

import os
import json
import subprocess
import shutil
from typing import Optional, List, Dict
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# Tool availability cache
_tool_cache = {}

def tool_available(name: str) -> bool:
    if name not in _tool_cache:
        _tool_cache[name] = shutil.which(name) is not None
    return _tool_cache[name]

def run_tool(cmd: str, timeout: int = 120) -> str:
    """Run a shell command and return output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after {timeout}s]"
    except Exception as e:
        return f"[ERROR: {e}]"


class BugHunter:
    def __init__(self, swarm, session_mem, ui, config):
        self.swarm = swarm
        self.mem = session_mem
        self.ui = ui
        self.config = config
        self.mode = "ask"

    def hunt(self, target: str, mode: str = "ask", scope: List[str] = None,
             vuln_focus: str = None, deep: bool = False, quick: bool = False,
             no_tools: bool = False) -> Dict:
        """Main hunt pipeline."""
        self.mode = mode
        session = self.mem.new_session(target)

        console.print(Panel(
            f"[bold cyan]Starting Hunt[/bold cyan]\n\n"
            f"Target: [yellow]{target}[/yellow]\n"
            f"Mode: [{'red' if mode == 'yolo' else 'green'}]{'YOLO' if mode == 'yolo' else 'ASK'}[/{'red' if mode == 'yolo' else 'green'}]\n"
            f"Session: [dim]{session['id']}[/dim]\n"
            f"Past knowledge: [cyan]{len(session.get('past_knowledge', {}))} items[/cyan]",
            style="cyan"
        ))

        # Show past knowledge
        if session.get("past_knowledge"):
            console.print("[dim]📚 Applying knowledge from past sessions...[/dim]")

        # PHASE 1: Recon
        if self._should_proceed("Phase 1: Recon", "Run subdomain enum, URL crawl, tech fingerprint?"):
            recon_data = self._phase_recon(session, target, quick, no_tools)
        else:
            recon_data = {}

        # PHASE 2: AI Attack Planning
        if self._should_proceed("Phase 2: Attack Planning", "Let swarm analyze recon and plan attack vectors?"):
            plan = self._phase_plan(session, target, recon_data)
        else:
            plan = {"priority_vectors": []}

        # PHASE 3: Vulnerability Hunting
        if self._should_proceed("Phase 3: Vulnerability Hunting", "Start hunting for vulnerabilities?"):
            self._phase_hunt(session, target, plan, vuln_focus, deep, no_tools)

        # PHASE 4: Validation
        if session.get("findings"):
            if self._should_proceed("Phase 4: Validation",
                                    f"Validate {len(session['findings'])} finding(s)?"):
                self._phase_validate(session, target)

        # PHASE 5: Chaining
        if len(session.get("findings", [])) >= 2:
            if self._should_proceed("Phase 5: Chaining",
                                    f"Find exploit chains across {len(session['findings'])} findings?"):
                self._phase_chain(session)

        # Summary
        self._show_summary(session)
        self.mem.save_session(session)
        return session

    def resume(self, session: Dict, mode: str = "ask", deep: bool = False):
        """Resume a previous hunt."""
        self.mode = mode
        target = session["target"]
        console.print(f"\n[cyan]Resuming hunt for {target}[/cyan]")
        console.print(f"  Existing findings: {len(session.get('findings', []))}")

        # Ask swarm what to do next
        ctx = self.mem.get_session_context(session)
        next_steps = self.swarm.ask(
            "orchestrator",
            "Given this session state, what are the best next steps to maximize findings?",
            context=ctx
        )
        console.print(Panel(next_steps, title="[cyan]Swarm Recommendation[/cyan]"))

        if self._should_proceed("Continue Hunt", "Run recommended next steps?"):
            plan = {"priority_vectors": []}
            self._phase_hunt(session, target, plan, None, deep, False)
            if session.get("findings"):
                self._phase_validate(session, target)
            if len(session.get("findings", [])) >= 2:
                self._phase_chain(session)

        self._show_summary(session)
        self.mem.save_session(session)

    # ─── PHASES ──────────────────────────────────────────────────────────────

    def _phase_recon(self, session: Dict, target: str, quick: bool, no_tools: bool) -> Dict:
        """Phase 1: Reconnaissance."""
        console.print("\n[bold cyan]═══ PHASE 1: RECON ═══[/bold cyan]")
        recon = {}

        tools_to_run = []
        if not no_tools:
            if tool_available("subfinder"):
                tools_to_run.append(("subfinder", f"subfinder -d {target} -silent"))
            elif tool_available("amass"):
                tools_to_run.append(("amass", f"amass enum -passive -d {target}"))
            else:
                console.print("[yellow]  ⚠ subfinder/amass not found. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest[/yellow]")

            if tool_available("httpx"):
                tools_to_run.append(("httpx_probe", None))  # depends on subdomains
            if tool_available("waybackurls") or tool_available("gau"):
                gau_tool = "gau" if tool_available("gau") else "waybackurls"
                tools_to_run.append(("urls", f"{gau_tool} {target}"))
            if tool_available("whatweb"):
                tools_to_run.append(("whatweb", f"whatweb --quiet {target}"))
            if tool_available("nmap") and not quick:
                tools_to_run.append(("nmap", f"nmap -sV -T4 --top-ports 100 {target}"))

        for tool_name, cmd in tools_to_run:
            console.print(f"  [dim]Running {tool_name}...[/dim]", end=" ")
            if cmd:
                output = run_tool(cmd)
                recon[tool_name] = output
                self.mem.add_tool_output(session, tool_name, output)
                lines = len(output.split("\n"))
                console.print(f"[green]✓[/green] ({lines} lines)")

                # Run httpx on subdomains if we have them
                if tool_name in ("subfinder", "amass") and tool_available("httpx"):
                    subdomains = [s.strip() for s in output.split("\n") if s.strip()]
                    if subdomains:
                        # Write to temp file
                        tmp = f"/tmp/swarmbounty_subs_{target}.txt"
                        with open(tmp, "w") as f:
                            f.write("\n".join(subdomains[:500]))
                        httpx_out = run_tool(f"httpx -l {tmp} -silent -status-code -title -tech-detect 2>/dev/null", timeout=120)
                        recon["live_hosts"] = httpx_out
                        self.mem.add_tool_output(session, "httpx", httpx_out)
                        console.print(f"  [dim]httpx probing...[/dim] [green]✓[/green]")
            else:
                console.print("[dim]skipped[/dim]")

        # AI recon analysis
        if recon:
            console.print("  [dim]AI analyzing recon data...[/dim]")
            recon_summary = self.swarm.ask(
                "recon",
                f"Analyze this recon data for target {target}. Identify the most interesting attack surface.",
                context={"recon_data": {k: v[:2000] for k, v in recon.items()}}
            )
            recon["ai_analysis"] = recon_summary
            console.print(Panel(recon_summary[:1500], title="[cyan]Recon Analysis[/cyan]"))
        else:
            # AI-only recon (no tools)
            console.print("  [dim]Running AI-based recon analysis...[/dim]")
            recon["ai_analysis"] = self.swarm.ask(
                "recon",
                f"Without tool output, perform theoretical recon analysis for {target}. "
                f"What attack surface is likely present? What would you enumerate first?",
                context={"target": target}
            )
            console.print(Panel(recon["ai_analysis"][:1500], title="[cyan]AI Recon Analysis[/cyan]"))

        self.mem.add_recon(session, "full", recon)
        return recon

    def _phase_plan(self, session: Dict, target: str, recon_data: Dict) -> Dict:
        """Phase 2: AI attack planning."""
        console.print("\n[bold cyan]═══ PHASE 2: ATTACK PLANNING ═══[/bold cyan]")
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as p:
            p.add_task("Swarm analyzing attack surface...")
            plan = self.swarm.orchestrate_hunt(target, recon_data)

        if isinstance(plan, dict) and plan.get("priority_vectors"):
            console.print("\n[bold yellow]🎯 Priority Attack Vectors:[/bold yellow]")
            for v in plan["priority_vectors"][:5]:
                rank = v.get("rank", "?")
                vuln = v.get("vuln_class", "?")
                endpoint = v.get("target_endpoint", "?")
                rationale = v.get("rationale", "")[:100]
                chain = v.get("chain_potential", "")
                console.print(
                    f"  [bold]#{rank}[/bold] [red]{vuln}[/red] @ [yellow]{endpoint}[/yellow]\n"
                    f"       [dim]{rationale}[/dim]"
                    + (f"\n       [magenta]Chain: {chain}[/magenta]" if chain else "")
                )

            if plan.get("quick_wins"):
                console.print("\n[bold green]⚡ Quick Wins:[/bold green]")
                for qw in plan["quick_wins"][:3]:
                    console.print(f"  • {qw}")
        else:
            console.print(Panel(str(plan)[:2000], title="Attack Plan"))

        self.mem.add_recon(session, "attack_plan", plan)
        return plan

    def _phase_hunt(self, session: Dict, target: str, plan: Dict,
                   vuln_focus: str, deep: bool, no_tools: bool):
        """Phase 3: Vulnerability hunting."""
        console.print("\n[bold cyan]═══ PHASE 3: VULNERABILITY HUNTING ═══[/bold cyan]")

        vuln_classes = []
        if vuln_focus:
            vuln_classes = [vuln_focus]
        elif plan.get("priority_vectors"):
            vuln_classes = [v.get("vuln_class", "") for v in plan["priority_vectors"][:5]]
        else:
            vuln_classes = ["xss", "idor", "ssrf", "sqli", "open_redirect"]

        for vuln_class in vuln_classes:
            if not vuln_class:
                continue
            console.print(f"\n  [yellow]Hunting: {vuln_class.upper()}[/yellow]")

            # Get AI hunting strategy
            ctx = self.mem.get_session_context(session)
            ctx["current_vuln"] = vuln_class
            ctx["target"] = target

            strategy = self.swarm.ask(
                "hunter",
                f"""For target {target}, hunting for {vuln_class}:
1. What are the top 3 places to test for this vuln?
2. Give exact payloads and curl commands to test
3. What technology-specific patterns should I look for?
4. What's the quick-win indicator I should look for in responses?

Be specific to the recon data and tech stack we found.""",
                context=ctx
            )

            console.print(Panel(strategy[:2000], title=f"[yellow]{vuln_class.upper()} Strategy[/yellow]"))

            # Run automated scanners if available
            if not no_tools:
                self._run_vuln_scanners(session, target, vuln_class)

            # Interactive: ask user if they found anything
            if self.mode == "ask":
                console.print(f"\n  [dim]Test the above. Did you find anything for {vuln_class}?[/dim]")
                result = input("  Finding? (describe it or 'n' to continue): ").strip()
                if result.lower() not in ("n", "no", ""):
                    finding = {
                        "vuln_class": vuln_class,
                        "endpoint": target,
                        "description": result,
                        "severity": "Unknown",
                        "source": "manual",
                        "raw": result
                    }
                    finding = self.mem.add_finding(session, finding)
                    console.print(f"  [green]✓ Finding {finding['id']} logged[/green]")

    def _run_vuln_scanners(self, session: Dict, target: str, vuln_class: str):
        """Run relevant automated scanners for a vuln class."""
        scanner_map = {
            "xss": [
                ("dalfox", f"dalfox url https://{target} --silence"),
                ("xsstrike", f"python3 -m xsstrike -u https://{target}"),
            ],
            "sqli": [
                ("sqlmap", f"sqlmap -u https://{target} --batch --level=2 --risk=1 --forms 2>/dev/null"),
            ],
            "ssrf": [],  # manual
            "idor": [],  # manual
            "nuclei": [
                ("nuclei", f"nuclei -u https://{target} -severity critical,high -silent 2>/dev/null"),
            ]
        }

        # Always try nuclei if available
        if tool_available("nuclei"):
            console.print(f"    [dim]Running nuclei...[/dim]", end=" ")
            out = run_tool(f"nuclei -u https://{target} -severity critical,high,medium -silent 2>/dev/null", timeout=180)
            if out and "[" in out:  # nuclei findings have brackets
                console.print(f"[red]⚠ nuclei findings[/red]")
                console.print(out[:2000])
                self.mem.add_tool_output(session, "nuclei", out)
                # Parse nuclei findings
                for line in out.split("\n"):
                    if "[critical]" in line.lower() or "[high]" in line.lower():
                        self.mem.add_finding(session, {
                            "vuln_class": "nuclei",
                            "endpoint": target,
                            "description": line.strip(),
                            "severity": "High" if "[high]" in line.lower() else "Critical",
                            "source": "nuclei",
                            "raw": line
                        })
            else:
                console.print("[green]✓ (clean)[/green]")

        # Class-specific scanners
        for scanner_name, cmd in scanner_map.get(vuln_class, []):
            if tool_available(scanner_name.split()[0]):
                console.print(f"    [dim]Running {scanner_name}...[/dim]", end=" ")
                out = run_tool(cmd, timeout=120)
                if out:
                    self.mem.add_tool_output(session, scanner_name, out)
                    console.print("[green]✓[/green]")

    def _phase_validate(self, session: Dict, target: str):
        """Phase 4: Validate findings."""
        console.print("\n[bold cyan]═══ PHASE 4: VALIDATION ═══[/bold cyan]")
        unvalidated = [f for f in session["findings"] if not f.get("validated")]
        console.print(f"  Validating {len(unvalidated)} finding(s)...")

        for finding in unvalidated:
            fid = finding.get("id", "?")
            vuln = finding.get("vuln_class", "?")
            console.print(f"\n  [yellow]Validating {fid}: {vuln}[/yellow]")

            validation = self.swarm.validate_finding(finding, target)

            verdict = validation.get("verdict", "unknown")
            confidence = validation.get("confidence", 0)
            impact = validation.get("impact", "Unknown")
            cvss = validation.get("cvss_score", 0)

            color = {"valid": "green", "invalid": "red", "needs_more_info": "yellow"}.get(verdict, "white")
            console.print(
                f"  [{color}]{verdict.upper()}[/{color}] | "
                f"Confidence: {confidence}% | "
                f"Impact: {impact} | "
                f"CVSS: {cvss}"
            )

            if validation.get("poc_curl"):
                console.print(f"  [dim]PoC curl:[/dim]")
                console.print(f"  [cyan]{validation['poc_curl'][:300]}[/cyan]")

            if validation.get("rejection_reason") and verdict == "invalid":
                console.print(f"  [dim]Reason: {validation['rejection_reason']}[/dim]")

            # Update finding
            finding["validated"] = True
            finding["validation"] = validation
            finding["severity"] = impact
            finding["cvss"] = cvss
            finding["report_worthy"] = validation.get("report_worthy", False)

            if self.mode == "ask" and verdict == "needs_more_info":
                console.print(f"  [yellow]This finding needs more info. Add details? (enter to skip)[/yellow]")
                extra = input("  Details: ").strip()
                if extra:
                    finding["extra_info"] = extra

        self.mem.save_session(session)

    def _phase_chain(self, session: Dict):
        """Phase 5: Chain analysis."""
        console.print("\n[bold cyan]═══ PHASE 5: CHAIN ANALYSIS ═══[/bold cyan]")
        chains = self.swarm.find_chains(session["findings"])
        session["chains"] = chains

        if chains:
            console.print(f"\n[bold magenta]🔗 {len(chains)} Exploit Chain(s) Found:[/bold magenta]")
            for chain in chains:
                console.print(
                    f"\n  [bold]{chain.get('chain_name', 'Chain')}[/bold]\n"
                    f"  Severity: [red]{chain.get('combined_severity', '?')}[/red] | "
                    f"Multiplier: [green]{chain.get('payout_multiplier', '?')}[/green]\n"
                    f"  [dim]{chain.get('narrative', '')}[/dim]"
                )
        else:
            console.print("  [dim]No significant chains identified.[/dim]")

        self.mem.save_session(session)

    # ─── HELPERS ─────────────────────────────────────────────────────────────

    def _should_proceed(self, phase_name: str, question: str) -> bool:
        """In YOLO mode, always proceed. In ASK mode, prompt user."""
        if self.mode == "yolo":
            console.print(f"[dim]  → YOLO: {phase_name}[/dim]")
            return True

        console.print(f"\n[yellow]? {question}[/yellow]")
        console.print("[dim]  [y]es / [n]o / [s]kip / [c]hange suggestion: [/dim]", end="")
        try:
            ans = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        return ans in ("y", "yes", "")

    def validate_finding(self, session: Dict, finding_id: Optional[str] = None):
        """Validate a specific finding or the latest one."""
        findings = session.get("findings", [])
        if not findings:
            console.print("[yellow]No findings to validate.[/yellow]")
            return

        if finding_id:
            target_findings = [f for f in findings if f.get("id") == finding_id]
        else:
            target_findings = [findings[-1]]

        if not target_findings:
            console.print(f"[yellow]Finding {finding_id} not found.[/yellow]")
            return

        self._phase_validate(session, session["target"])

    def _show_summary(self, session: Dict):
        """Display hunt summary."""
        findings = session.get("findings", [])
        chains = session.get("chains", [])
        validated = [f for f in findings if f.get("validated")]
        report_worthy = [f for f in findings if f.get("report_worthy")]

        console.print(Panel(
            f"[bold cyan]Hunt Summary[/bold cyan]\n\n"
            f"Target: [yellow]{session['target']}[/yellow]\n"
            f"Session: [dim]{session['id']}[/dim]\n\n"
            f"Findings: [red]{len(findings)}[/red] total | "
            f"[yellow]{len(validated)}[/yellow] validated | "
            f"[green]{len(report_worthy)}[/green] report-worthy\n"
            f"Chains: [magenta]{len(chains)}[/magenta]\n\n"
            f"[dim]Resume: python3 swarmbounty.py --pickup {session['id']}[/dim]\n"
            f"[dim]Report: python3 swarmbounty.py --report {session['id']}[/dim]",
            style="cyan"
        ))

        if report_worthy:
            console.print("[bold green]Report-worthy findings:[/bold green]")
            for f in report_worthy:
                console.print(
                    f"  [green]✓[/green] [{f.get('severity','?')}] "
                    f"{f.get('vuln_class','?')} - {f.get('endpoint','?')[:60]}"
                )
