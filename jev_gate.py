from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sys
from dataclasses import asdict, dataclass
from enum import Enum

from dotenv import load_dotenv
from typesafe_sdk import Choice, Noul, Score, TypeSafeClient

DEFAULT_TIMEOUT_SECONDS = 8.0

# Categories Jev can return that should never be silently rescued by a
# so-so numeric risk score. If Jev thinks it's destructive, the local
# policy treats that as the final word regardless of the risk number.
HARD_BLOCK_CATEGORIES = {"destructive_or_dangerous"}
ESCALATE_CATEGORIES = {"privileged"}


class Action(str, Enum):
    ALLOW = "ALLOW"
    CONFIRM = "CONFIRM"
    BLOCK = "BLOCK"


# Exit codes are the real interface. Anything wrapping this tool (a shell
# hook, an agent's pre-exec check) should branch on these, not on stdout.
EXIT_ALLOW = 0
EXIT_BLOCK = 1
EXIT_USAGE_ERROR = 2
EXIT_API_ERROR = 3
EXIT_NOT_CONFIRMED = 4


@dataclass
class Verdict:
    command: str
    category: str
    risk: float
    reversible: float
    needs_confirmation: float
    confidence: float


class JevGateError(RuntimeError):
    """Raised when Jev can't be reached or hands back something unusable.

    Every call site treats this as fail-closed: no verdict means no ALLOW.
    """


def analyze_command(
    client: TypeSafeClient,
    command: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> Verdict:
    """Ask Jev to classify a shell command across several dimensions.

    Runs the request on a worker thread so a stalled connection can't hang
    the gate indefinitely — a security check that never returns is just as
    bad as one that says yes to everything.
    """

    def _call():
        return client.system_one(
            state=command,
            questions={
                "category": Choice(
                    instructions="What kind of shell command is this?",
                    criteria={
                        "read_only": "Inspects files, processes, environment, or system state without intentionally changing it",
                        "file_change": "Creates, deletes, moves, renames, or edits files/directories",
                        "package_or_system_change": "Installs, removes, upgrades, configures, or otherwise changes software/system state",
                        "network": "Makes network requests, changes network configuration, or interacts with remote systems",
                        "process_or_execution": "Starts, stops, kills, or executes programs/processes",
                        "privileged": "Uses or requests elevated privileges such as sudo/Administrator/root",
                        "destructive_or_dangerous": "Can cause major data loss, credential exposure, service disruption, or other serious harm",
                        "other": "Does not fit the categories above",
                    },
                ),
                "risk": Score(
                    instructions="How risky is this command if executed exactly as written?",
                    criteria=[
                        "Essentially harmless or informational",
                        "Minor impact and usually reversible",
                        "Moderate impact; could cause problems if misunderstood",
                        "High impact; can significantly alter data or system state",
                        "Extremely dangerous; likely to cause major damage, loss, or compromise if misused",
                    ],
                ),
                "reversible": Noul(
                    instructions="Can the command's effects be straightforwardly undone without backup restoration or specialist recovery?",
                ),
                "needs_confirmation": Noul(
                    instructions="Should a local security policy require explicit human confirmation before this command is allowed to run?",
                ),
            },
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_call)
        try:
            response = future.result(timeout=timeout)
        except concurrent.futures.TimeoutError as exc:
            raise JevGateError(f"Jev did not respond within {timeout:.0f}s") from exc
        except Exception as exc:
            raise JevGateError(f"Jev request failed: {exc}") from exc

    try:
        answers = response.answers
        risk_answer = answers["risk"]

        confidence_values = [
            float(getattr(answer, "confidence"))
            for answer in answers.values()
            if isinstance(getattr(answer, "confidence", None), (int, float))
        ]

        return Verdict(
            command=command,
            category=answers["category"].choice,
            risk=float(risk_answer.score),
            reversible=float(answers["reversible"].noul),
            needs_confirmation=float(answers["needs_confirmation"].noul),
            confidence=(sum(confidence_values) / len(confidence_values)) if confidence_values else 0.0,
        )
    except (KeyError, AttributeError, TypeError, ValueError) as exc:
        raise JevGateError(f"Unexpected response shape from Jev: {exc}") from exc


def policy(verdict: Verdict) -> tuple[Action, str]:
    """Apply deterministic local policy on top of Jev's fuzzy judgment.

    Order matters:
      1. Category overrides run first — a command Jev already flagged as
         destructive shouldn't get rescued by a middling risk number.
      2. Low-confidence judgments get escalated instead of trusted at face
         value; an unsure "probably fine" isn't the same as a confident one.
      3. Numeric thresholds handle everything else.
    """
    if verdict.category in HARD_BLOCK_CATEGORIES:
        return Action.BLOCK, f"Category '{verdict.category}': always requires human review."

    if verdict.risk >= 3.5 or verdict.needs_confirmation >= 0.75:
        return Action.BLOCK, "High-impact command: requires explicit human review."

    if verdict.confidence and verdict.confidence < 0.5 and verdict.risk >= 1.0:
        return (
            Action.CONFIRM,
            f"Low-confidence judgment ({verdict.confidence:.0%}) on a non-trivial command.",
        )

    if verdict.category in ESCALATE_CATEGORIES:
        return Action.CONFIRM, f"Category '{verdict.category}': confirm before running privileged commands."

    if verdict.risk >= 2.0 or verdict.needs_confirmation >= 0.40:
        return Action.CONFIRM, "Potentially impactful command: confirm before running."

    return Action.ALLOW, "Low-risk command under the local policy."


def gate(
    client: TypeSafeClient,
    command: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> tuple[Verdict, Action, str]:
    """The one entry point other code should call: classify, then decide."""
    verdict = analyze_command(client, command, timeout=timeout)
    action, reason = policy(verdict)
    return verdict, action, reason


def _print_human(verdict: Verdict, action: Action, reason: str) -> None:
    print("\n=== JEV GATE ===")
    print(f"Command:             {verdict.command}")
    print(f"Category:            {verdict.category}")
    print(f"Risk score:          {verdict.risk:.2f} / 4")
    print(f"Reversible (P):      {verdict.reversible:.1%}")
    print(f"Needs confirmation:  {verdict.needs_confirmation:.1%}")
    print(f"Avg. confidence:     {verdict.confidence:.1%}")
    print(f"Decision:            {action.value}")
    print(f"Reason:              {reason}")
    print("=================\n")


def _print_json(verdict: Verdict, action: Action, reason: str) -> None:
    payload = asdict(verdict)
    payload["decision"] = action.value
    payload["reason"] = reason
    print(json.dumps(payload, indent=2))


def main(argv: list[str] | None = None) -> int:
    load_dotenv()

    parser = argparse.ArgumentParser(description="Use Jev to classify a shell command before execution.")
    parser.add_argument("command", nargs="*", help="Command to analyze")
    parser.add_argument("--json", action="store_true", help="Machine-readable output for scripting/agent use")
    parser.add_argument("--yes", action="store_true", help="Auto-accept CONFIRM decisions (non-interactive use)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS, help="Seconds to wait for Jev")
    args = parser.parse_args(argv)

    if not os.getenv("TYPESAFE_API_KEY"):
        print("Missing TYPESAFE_API_KEY. Put it in .env or your environment.", file=sys.stderr)
        return EXIT_USAGE_ERROR

    command = " ".join(args.command).strip()
    if not command and not args.json:
        command = input("command> ").strip()

    if not command:
        print("No command supplied.", file=sys.stderr)
        return EXIT_USAGE_ERROR

    client = TypeSafeClient()
    try:
        verdict, action, reason = gate(client, command, timeout=args.timeout)
    except JevGateError as exc:
        # Fail closed: if we can't get a judgment, we don't allow the command.
        print(str(exc), file=sys.stderr)
        return EXIT_API_ERROR

    if args.json:
        _print_json(verdict, action, reason)
    else:
        _print_human(verdict, action, reason)

    if action is Action.ALLOW:
        return EXIT_ALLOW
    if action is Action.BLOCK:
        return EXIT_BLOCK

    # CONFIRM: only proceeds with --yes or an explicit interactive "y".
    if args.yes:
        return EXIT_ALLOW
    if not args.json and sys.stdin.isatty():
        reply = input("Proceed? [y/N] ").strip().lower()
        if reply == "y":
            return EXIT_ALLOW
    return EXIT_NOT_CONFIRMED


if __name__ == "__main__":
    raise SystemExit(main())
