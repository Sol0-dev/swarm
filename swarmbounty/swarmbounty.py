#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║          SWARMBOUNTY - AI Swarm Bug Bounty Framework          ║
║    Multi-LLM Orchestration | PoC Chaining | Auto Reporting    ║
║         Based on shuvonsec/claude-bug-bounty methodology      ║
╚═══════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import time
import argparse
import readline
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import print as rprint

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.config import Config
from core.swarm import SwarmOrchestrator
from core.session import SessionMemory
from core.request_parser import RequestParser
from core.hunter import BugHunter
from core.reporter import ReportWriter
from ui.terminal import TerminalUI

console = Console()

BANNER = """[bold red]
  ███████╗██╗    ██╗ █████╗ ██████╗ ███╗   ███╗
  ██╔════╝██║    ██║██╔══██╗██╔══██╗████╗ ████║
  ███████╗██║ █╗ ██║███████║██████╔╝██╔████╔██║
  ╚════██║██║███╗██║██╔══██║██╔══██╗██║╚██╔╝██║
  ███████║╚███╔███╔╝██║  ██║██║  ██║██║ ╚═╝ ██║
  ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝
[/bold red][bold yellow]
  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
[/bold yellow]
[dim]Multi-LLM Bug Bounty Swarm | Built on shuvonsec methodology[/dim]
[dim]⚠  For authorized security testing only. Never test without permission.[/dim]
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="SwarmBounty - AI Swarm Bug Bounty Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  --yolo        Autonomous mode - AI makes all decisions, executes without asking
  --ask         Interactive mode - AI suggests, you approve every step (default)

Examples:
  python3 swarmbounty.py --target example.com --yolo
  python3 swarmbounty.py --target example.com --ask --scope scope.txt
  python3 swarmbounty.py --chat                          # Live chat + request analysis
  python3 swarmbounty.py --pickup session_id             # Resume previous hunt
  python3 swarmbounty.py --report session_id             # Generate report from session
  python3 swarmbounty.py --config                        # Setup API keys
        """
    )

    parser.add_argument("--target", "-t", help="Target domain (e.g. example.com)")
    parser.add_argument("--yolo", action="store_true",
                        help="Autonomous mode - execute all steps without asking")
    parser.add_argument("--ask", action="store_true",
                        help="Interactive mode - confirm every step (default)")
    parser.add_argument("--chat", action="store_true",
                        help="Open live chat with swarm (can paste curl/Burp requests)")
    parser.add_argument("--pickup", metavar="SESSION_ID",
                        help="Resume a previous hunting session")
    parser.add_argument("--report", metavar="SESSION_ID",
                        help="Generate report from existing session")
    parser.add_argument("--scope", help="Scope file (one domain/IP per line)")
    parser.add_argument("--vuln", help="Focus on specific vuln class (xss,sqli,ssrf,idor...)")
    parser.add_argument("--deep", action="store_true",
                        help="Deep mode - thorough multi-agent analysis (slower)")
    parser.add_argument("--quick", action="store_true",
                        help="Quick scan - fast surface-level recon")
    parser.add_argument("--config", action="store_true",
                        help="Configure API keys and settings")
    parser.add_argument("--models", action="store_true",
                        help="Show available/configured AI models")
    parser.add_argument("--session-list", action="store_true",
                        help="List all saved hunting sessions")
    parser.add_argument("--burp", metavar="FILE",
                        help="Parse and analyze a saved Burp request file")
    parser.add_argument("--curl", metavar="CMD",
                        help="Analyze a curl command string")
    parser.add_argument("--no-tools", action="store_true",
                        help="Skip tool execution (AI analysis only)")

    return parser.parse_args()


def run_config_wizard():
    """Interactive API key configuration wizard."""
    cfg = Config()
    console.print(Panel("[bold cyan]SwarmBounty Configuration Wizard[/bold cyan]", style="cyan"))
    console.print("\n[yellow]Configure your AI provider API keys.[/yellow]")
    console.print("[dim]Keys are stored in ~/.swarmbounty/config.json (not committed to git)[/dim]\n")

    providers = {
        "gemini": {
            "name": "Google Gemini",
            "env": "GEMINI_API_KEY",
            "url": "https://aistudio.google.com/app/apikey",
            "free": True
        },
        "openai": {
            "name": "OpenAI / ChatGPT",
            "env": "OPENAI_API_KEY",
            "url": "https://platform.openai.com/api-keys",
            "free": False
        },
        "deepseek": {
            "name": "DeepSeek",
            "env": "DEEPSEEK_API_KEY",
            "url": "https://platform.deepseek.com/api_keys",
            "free": True
        },
        "groq": {
            "name": "Groq (fast Llama/Mixtral - free tier)",
            "env": "GROQ_API_KEY",
            "url": "https://console.groq.com/keys",
            "free": True
        },
        "anthropic": {
            "name": "Anthropic Claude",
            "env": "ANTHROPIC_API_KEY",
            "url": "https://console.anthropic.com/",
            "free": False
        }
    }

    for key, info in providers.items():
        free_tag = " [green](has free tier)[/green]" if info["free"] else ""
        current = cfg.get_api_key(key)
        masked = f"****{current[-4:]}" if current else "[dim]not set[/dim]"
        console.print(f"\n[bold]{info['name']}[/bold]{free_tag}")
        console.print(f"  Get key: {info['url']}")
        console.print(f"  Current: {masked}")
        new_key = input(f"  New key (enter to skip): ").strip()
        if new_key:
            cfg.set_api_key(key, new_key)
            console.print(f"  [green]✓ Saved[/green]")

    # Swarm role assignment
    console.print("\n[bold cyan]Swarm Role Assignment[/bold cyan]")
    console.print("[dim]Assign roles to each model for specialized tasks[/dim]\n")

    available = cfg.get_available_models()
    if len(available) < 2:
        console.print("[yellow]Add at least 2 API keys to enable swarm mode[/yellow]")
    else:
        console.print(f"[green]✓ {len(available)} models available for swarm[/green]")
        cfg.auto_assign_roles(available)

    cfg.save()
    console.print("\n[green bold]✓ Configuration saved to ~/.swarmbounty/config.json[/green bold]")


def show_models():
    """Display configured models and their swarm roles."""
    cfg = Config()
    available = cfg.get_available_models()

    table = Table(title="Configured AI Models", style="cyan")
    table.add_column("Provider", style="bold")
    table.add_column("Model", style="yellow")
    table.add_column("Swarm Role", style="green")
    table.add_column("Status", style="white")

    for m in available:
        table.add_row(
            m["provider"],
            m["model"],
            m.get("role", "general"),
            "[green]✓ Ready[/green]"
        )

    if not available:
        console.print("[red]No models configured. Run: python3 swarmbounty.py --config[/red]")
    else:
        console.print(table)
        console.print(f"\n[green]Swarm size: {len(available)} models[/green]")


def main():
    args = parse_args()

    # Print banner
    console.print(BANNER)

    # Config wizard
    if args.config:
        run_config_wizard()
        return

    # Show models
    if args.models:
        show_models()
        return

    # Initialize core components
    cfg = Config()
    session_mem = SessionMemory()
    ui = TerminalUI(console, yolo_mode=args.yolo)

    # List sessions
    if args.session_list:
        sessions = session_mem.list_sessions()
        if not sessions:
            console.print("[yellow]No saved sessions found.[/yellow]")
        else:
            table = Table(title="Saved Hunting Sessions")
            table.add_column("ID", style="cyan")
            table.add_column("Target", style="yellow")
            table.add_column("Bugs Found", style="red")
            table.add_column("Date", style="dim")
            for s in sessions:
                table.add_row(s["id"], s["target"], str(s["bugs_found"]), s["date"])
            console.print(table)
        return

    # Check we have at least one API key
    available_models = cfg.get_available_models()
    if not available_models:
        console.print(Panel(
            "[red bold]No API keys configured![/red bold]\n\n"
            "Run [cyan]python3 swarmbounty.py --config[/cyan] to add your API keys.\n\n"
            "[dim]Free options: Google Gemini, DeepSeek, Groq[/dim]",
            title="⚠ Setup Required",
            style="red"
        ))
        return

    # Initialize swarm
    swarm = SwarmOrchestrator(cfg, ui)
    hunter = BugHunter(swarm, session_mem, ui, cfg)
    request_parser = RequestParser(swarm)
    reporter = ReportWriter(swarm)

    mode = "yolo" if args.yolo else "ask"
    console.print(f"\n[bold]Mode:[/bold] [{'red' if args.yolo else 'green'}]{'🤖 YOLO (Autonomous)' if args.yolo else '🤝 ASK (Interactive)'}[/{'red' if args.yolo else 'green'}]")
    console.print(f"[bold]Swarm:[/bold] [cyan]{len(available_models)} models active[/cyan]")
    if not args.yolo:
        console.print("[dim]You will be asked to approve/modify each step.[/dim]\n")

    # Report generation from existing session
    if args.report:
        session = session_mem.load_session(args.report)
        if not session:
            console.print(f"[red]Session {args.report} not found.[/red]")
            return
        console.print(f"[cyan]Generating report for session {args.report}...[/cyan]")
        report_path = reporter.generate(session)
        console.print(f"[green]✓ Report saved: {report_path}[/green]")
        return

    # Analyze a Burp request file
    if args.burp:
        console.print(f"[cyan]Parsing Burp request: {args.burp}[/cyan]")
        with open(args.burp) as f:
            raw = f.read()
        request_parser.analyze_interactive(raw, source="burp")
        return

    # Analyze a curl command
    if args.curl:
        request_parser.analyze_interactive(args.curl, source="curl")
        return

    # Resume session
    if args.pickup:
        session = session_mem.load_session(args.pickup)
        if not session:
            console.print(f"[red]Session {args.pickup} not found.[/red]")
            return
        console.print(f"[green]Resuming session: {args.pickup} | Target: {session['target']}[/green]")
        hunter.resume(session, mode=mode, deep=args.deep)
        return

    # Live chat mode
    if args.chat or not args.target:
        launch_chat(hunter, request_parser, swarm, session_mem, reporter, ui, mode)
        return

    # Main hunting mode
    if args.target:
        scope = []
        if args.scope:
            with open(args.scope) as f:
                scope = [l.strip() for l in f if l.strip()]

        hunter.hunt(
            target=args.target,
            mode=mode,
            scope=scope,
            vuln_focus=args.vuln,
            deep=args.deep,
            quick=args.quick,
            no_tools=args.no_tools
        )


def launch_chat(hunter, request_parser, swarm, session_mem, reporter, ui, mode):
    """Launch the live interactive chat interface."""
    console.print(Panel(
        "[bold cyan]SwarmBounty Live Chat[/bold cyan]\n\n"
        "Paste [yellow]curl commands[/yellow], [yellow]Burp requests[/yellow], "
        "or just [yellow]ask questions[/yellow].\n"
        "The swarm will analyze and suggest attack vectors.\n\n"
        "[dim]Commands:[/dim]\n"
        "  [cyan]/hunt <target>[/cyan]     - Start a hunt\n"
        "  [cyan]/analyze[/cyan]          - Analyze pasted request\n"
        "  [cyan]/chain[/cyan]            - Find exploit chains\n"
        "  [cyan]/validate[/cyan]         - Validate a finding\n"
        "  [cyan]/report[/cyan]           - Generate report\n"
        "  [cyan]/session[/cyan]          - Show current session\n"
        "  [cyan]/yolo[/cyan] / [cyan]/ask[/cyan]      - Toggle mode\n"
        "  [cyan]/models[/cyan]           - Show active swarm\n"
        "  [cyan]/help[/cyan]             - Full command list\n"
        "  [cyan]/exit[/cyan]             - Quit\n\n"
        "[dim]Tip: Paste a multi-line Burp request, then type /analyze[/dim]",
        style="cyan"
    ))

    current_session = None
    buffer = []
    current_mode = mode

    # Enable readline history
    histfile = Path.home() / ".swarmbounty" / "chat_history"
    histfile.parent.mkdir(exist_ok=True)
    try:
        readline.read_history_file(str(histfile))
    except FileNotFoundError:
        pass

    while True:
        try:
            # Prompt changes based on mode
            mode_indicator = "[YOLO]" if current_mode == "yolo" else "[ASK]"
            target_indicator = f"[{current_session['target']}]" if current_session else ""
            prompt = f"\n{mode_indicator}{target_indicator}> "

            user_input = input(prompt).strip()
            if not user_input:
                continue

            readline.write_history_file(str(histfile))

            # Check for commands
            if user_input.startswith("/"):
                parts = user_input.split(None, 1)
                cmd = parts[0].lower()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd == "/exit" or cmd == "/quit":
                    if current_session:
                        session_mem.save_session(current_session)
                        console.print(f"[green]Session saved: {current_session['id']}[/green]")
                    console.print("[dim]Goodbye. Stay ethical.[/dim]")
                    break

                elif cmd == "/hunt":
                    if not arg:
                        console.print("[yellow]Usage: /hunt <target>[/yellow]")
                    else:
                        current_session = hunter.hunt(
                            target=arg, mode=current_mode,
                            scope=[], vuln_focus=None, deep=False, quick=False
                        )

                elif cmd == "/analyze":
                    if buffer:
                        raw_request = "\n".join(buffer)
                        buffer = []
                        console.print(f"[cyan]Analyzing buffered request ({len(raw_request)} bytes)...[/cyan]")
                        findings = request_parser.analyze_interactive(raw_request, source="chat")
                        if current_session and findings:
                            current_session.setdefault("findings", []).extend(findings)
                    else:
                        console.print("[yellow]Buffer is empty. Paste a request first, then /analyze[/yellow]")

                elif cmd == "/chain":
                    if current_session and current_session.get("findings"):
                        console.print("[cyan]Running chaining analysis...[/cyan]")
                        chains = swarm.find_chains(current_session["findings"])
                        ui.display_chains(chains)
                    else:
                        console.print("[yellow]No findings to chain. Run /hunt or /analyze first.[/yellow]")

                elif cmd == "/validate":
                    finding_id = arg or None
                    if current_session:
                        hunter.validate_finding(current_session, finding_id)
                    else:
                        console.print("[yellow]No active session. Start a hunt first.[/yellow]")

                elif cmd == "/report":
                    if current_session:
                        console.print("[cyan]Generating report...[/cyan]")
                        path = reporter.generate(current_session)
                        console.print(f"[green]✓ Report: {path}[/green]")
                    else:
                        console.print("[yellow]No active session.[/yellow]")

                elif cmd == "/session":
                    if current_session:
                        ui.display_session_summary(current_session)
                    else:
                        console.print("[yellow]No active session.[/yellow]")

                elif cmd == "/yolo":
                    current_mode = "yolo"
                    hunter.mode = "yolo"
                    console.print("[red]Switched to YOLO mode - autonomous execution[/red]")

                elif cmd == "/ask":
                    current_mode = "ask"
                    hunter.mode = "ask"
                    console.print("[green]Switched to ASK mode - confirm every step[/green]")

                elif cmd == "/models":
                    show_models_inline(swarm)

                elif cmd == "/clear":
                    buffer = []
                    console.print("[dim]Buffer cleared.[/dim]")

                elif cmd == "/buffer":
                    console.print(f"[dim]Buffer ({len(buffer)} lines):[/dim]")
                    for i, line in enumerate(buffer[:10]):
                        console.print(f"  {i+1}: {line}")
                    if len(buffer) > 10:
                        console.print(f"  ... and {len(buffer)-10} more lines")

                elif cmd == "/help":
                    show_help()

                else:
                    console.print(f"[yellow]Unknown command: {cmd}. Type /help for commands.[/yellow]")

            else:
                # If input looks like a request (curl, HTTP verb, etc.), buffer it
                if is_request_like(user_input):
                    buffer.append(user_input)
                    console.print(f"[dim]Buffered line {len(buffer)}. Paste more or type /analyze[/dim]")
                else:
                    # Treat as natural language query to the swarm
                    console.print("\n[dim]Swarm thinking...[/dim]")
                    context = {}
                    if current_session:
                        context["session"] = {
                            "target": current_session.get("target"),
                            "findings": current_session.get("findings", [])[-5:],
                            "recon": current_session.get("recon", {})
                        }
                    response = swarm.chat(user_input, context=context)
                    console.print(Panel(response, title="[bold cyan]Swarm Response[/bold cyan]", style="dim"))

        except KeyboardInterrupt:
            console.print("\n[yellow]Ctrl+C - type /exit to quit[/yellow]")
        except EOFError:
            break


def is_request_like(text):
    """Detect if input looks like an HTTP request or curl command."""
    triggers = [
        "curl ", "GET ", "POST ", "PUT ", "DELETE ", "PATCH ",
        "HTTP/", "Host:", "Authorization:", "Content-Type:",
        "User-Agent:", "Cookie:", "--header", "-H ", "-d ", "--data"
    ]
    return any(text.startswith(t) or t in text[:50] for t in triggers)


def show_models_inline(swarm):
    """Show active swarm models."""
    models = swarm.get_active_models()
    for m in models:
        role_color = {"orchestrator": "red", "hunter": "yellow",
                      "validator": "green", "reporter": "cyan"}.get(m.get("role"), "white")
        console.print(f"  [{role_color}]{m.get('role', 'general').upper()}[/{role_color}] "
                      f"{m['provider']} / {m['model']}")


def show_help():
    """Print full help."""
    console.print(Panel("""
[bold cyan]HUNT COMMANDS[/bold cyan]
  /hunt <target>         Start a new hunting session
  /pickup <session_id>   Resume previous session
  /session               Show current session findings

[bold cyan]ANALYSIS COMMANDS[/bold cyan]
  /analyze               Analyze buffered request
  /chain                 Find exploit chains from findings
  /validate [id]         Validate a specific finding
  /buffer                Show buffered request lines
  /clear                 Clear request buffer

[bold cyan]REQUEST INPUT[/bold cyan]
  Just paste a curl command or HTTP request line-by-line,
  then type /analyze when done.

  Example:
    POST /api/users/123 HTTP/1.1
    Host: example.com
    Authorization: Bearer eyJ...
    {"email": "test@test.com"}
    /analyze

[bold cyan]OUTPUT COMMANDS[/bold cyan]
  /report                Generate H1/Bugcrowd report
  /models                Show active AI swarm

[bold cyan]MODE COMMANDS[/bold cyan]
  /yolo                  Switch to autonomous mode
  /ask                   Switch to interactive mode
  /exit                  Quit (saves session)
""", title="[bold]SwarmBounty Help[/bold]", style="dim"))


if __name__ == "__main__":
    main()
