from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass

from dotenv import load_dotenv
from typesafe_sdk import Choice, Noul, Score, TypeSafeClient


@dataclass
class Verdict:
    category: str
    risk: float
    reversible: float
    needs_confirmation: float
    confidence: float


def analyze_command(client: TypeSafeClient, command: str) -> Verdict:
    """Ask Jev to classify a shell command across several dimensions."""
    response = client.system_one(
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

    answers = response.answers
    risk_answer = answers["risk"]
    confidence_values = []
    for answer in answers.values():
        confidence = getattr(answer, "confidence", None)
        if isinstance(confidence, (int, float)):
            confidence_values.append(float(confidence))

    return Verdict(
        category=answers["category"].choice,
        risk=float(risk_answer.score),
        reversible=float(answers["reversible"].noul),
        needs_confirmation=float(answers["needs_confirmation"].noul),
        confidence=(sum(confidence_values) / len(confidence_values)) if confidence_values else 0.0,
    )


def policy(verdict: Verdict) -> tuple[str, str]:
    """Apply deterministic local policy after Jev makes the fuzzy judgment."""
    risk = verdict.risk
    confirmation = verdict.needs_confirmation

    if risk >= 3.5 or confirmation >= 0.75:
        return "BLOCK", "High-impact command: require explicit human review."
    if risk >= 2.0 or confirmation >= 0.40:
        return "CONFIRM", "Potentially impactful command: ask for confirmation first."
    return "ALLOW", "Low-risk command under the local policy."


def main() -> int:
    load_dotenv()

    if not os.getenv("TYPESAFE_API_KEY"):
        print("Missing TYPESAFE_API_KEY. Put it in .env or your environment.", file=sys.stderr)
        return 2

    parser = argparse.ArgumentParser(description="Use Jev to classify a shell command before execution.")
    parser.add_argument("command", nargs="*", help="Command to analyze")
    args = parser.parse_args()

    command = " ".join(args.command).strip()
    if not command:
        command = input("command> ").strip()

    if not command:
        print("No command supplied.", file=sys.stderr)
        return 2

    client = TypeSafeClient()
    try:
        verdict = analyze_command(client, command)
    except Exception as exc:
        print(f"Jev request failed: {exc}", file=sys.stderr)
        return 1

    action, reason = policy(verdict)

    print("\n=== JEV GATE ===")
    print(f"Command:             {command}")
    print(f"Category:            {verdict.category}")
    print(f"Risk score:          {verdict.risk:.2f} / 4")
    print(f"Reversible (P):      {verdict.reversible:.1%}")
    print(f"Needs confirmation:  {verdict.needs_confirmation:.1%}")
    print(f"Avg. confidence:     {verdict.confidence:.1%}")
    print(f"Decision:            {action}")
    print(f"Reason:              {reason}")
    print("=================\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
