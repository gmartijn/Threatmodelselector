#!/usr/bin/env python3
"""
Threat Model Selector
Asks up to 6 questions and recommends a threat modeling methodology (or combination).

Usage:
  Interactive (default):
    python threat_model_selector.py

  Non-interactive (all answers as flags, values: yes/no):
    python threat_model_selector.py \
      --q1 yes --q2 no --q3 yes --q4 no --q5 yes --q6 no

  JSON output:
    python threat_model_selector.py --json

Notes:
- You can answer with: y/n/yes/no/true/false (case-insensitive).
- If a question doesn't apply, answer 'no' to move to the next one.
"""

import argparse
import json
import sys
from typing import Dict, List, Tuple

Question = Tuple[str, str, str]  # (id, text, rationale)

QUESTIONS: List[Question] = [
    ("q1", "Are you focusing mainly on system design & technical threats (DFDs/components)?",
     "If yes, STRIDE maps cleanly to data-flow diagrams and design reviews."),
    ("q2", "Is privacy and personal data compliance a main concern (e.g., GDPR)?",
     "If yes, LINDDUN is tailored to privacy-by-design and regulatory alignment."),
    ("q3", "Do you need to connect threats to business risk and attacker simulations?",
     "If yes, PASTA emphasizes business impact and realistic attack scenarios."),
    ("q4", "Is the scope organization-wide (people, processes, critical assets)?",
     "If yes, OCTAVE supports org-wide risk posture; FAIR adds financial quantification."),
    ("q5", "Do you want to focus on attacker behavior, TTPs, or attack paths?",
     "If yes, combine Attack Trees + MITRE ATT&CK + CAPEC for behavior/path coverage."),
    ("q6", "Do you need to scale across Agile/DevOps teams or run creative workshops?",
     "If yes, VAST supports scalable modeling; Security Cards boost ideation.")
]

RECOMMENDATIONS: Dict[str, Dict[str, str]] = {
    "q1": {"yes": "STRIDE", "no": "next"},
    "q2": {"yes": "LINDDUN", "no": "next"},
    "q3": {"yes": "PASTA", "no": "next"},
    "q4": {"yes": "OCTAVE or FAIR", "no": "next"},
    "q5": {"yes": "Attack Trees + MITRE ATT&CK + CAPEC", "no": "next"},
    "q6": {"yes": "VAST or Security Cards", "no": "Reconsider scope / combine methods"}
}

DETAILS: Dict[str, str] = {
    "STRIDE": "Use for system/DFD-centric design reviews to enumerate Spoofing, Tampering, Repudiation, Info Disclosure, DoS, EoP.",
    "LINDDUN": "Privacy threat modeling focused on Linkability, Identifiability, Non-repudiation, Detectability, Disclosure, Unawareness, Non-compliance.",
    "PASTA": "Seven-stage, risk-driven method aligning attacker scenarios with business impact.",
    "OCTAVE or FAIR": "OCTAVE for org-wide risk posture; FAIR for financial quantification of risk magnitude.",
    "Attack Trees + MITRE ATT&CK + CAPEC": "Attack Trees map paths to goals; ATT&CK provides real-world TTPs; CAPEC catalogs attack patterns.",
    "VAST or Security Cards": "VAST scales across Agile/DevOps; Security Cards facilitate creative brainstorming with adversary/motive prompts.",
    "Reconsider scope / combine methods": "If none matched strongly, reassess objectives or explicitly combine methods (e.g., STRIDE + LINDDUN; PASTA + ATT&CK)."
}

def normalize_answer(s: str) -> str:
    s = s.strip().lower()
    if s in {"y", "yes", "true", "t", "1"}:
        return "yes"
    if s in {"n", "no", "false", "f", "0"}:
        return "no"
    return ""

def ask_interactive(qid: str, text: str) -> str:
    while True:
        ans = input(f"{text} [y/n]: ").strip()
        norm = normalize_answer(ans)
        if norm:
            return norm
        print("Please answer 'y' or 'n'.")

def decide(answers: Dict[str, str]) -> Dict[str, object]:
    """
    Return a decision dict containing selected recommendations and rationale.
    Follows the linear 6-question flow; collects combinations when multiple 'yes' apply.
    """
    chosen: List[str] = []
    rationale: List[str] = []

    for (qid, text, why) in QUESTIONS:
        ans = answers.get(qid)
        if ans is None:
            # should not happen
            ans = "no"
        if ans == "yes":
            rec = RECOMMENDATIONS[qid]["yes"]
            if rec not in chosen:
                chosen.append(rec)
                rationale.append(f"{qid.upper()}: {why}")
        else:
            # 'no' moves to next unless it's Q6 where we finalize
            if qid == "q6":
                rec = RECOMMENDATIONS[qid]["no"]
                if rec not in chosen:
                    chosen.append(rec)
                    rationale.append(f"{qid.upper()}: None of the earlier focus areas fit strongly.")
            continue

    # If nothing selected (e.g., all 'no' until q6==no), ensure we still return the fallback
    if not chosen:
        chosen = [RECOMMENDATIONS["q6"]["no"]]
        rationale.append("No strong fit identified in Q1–Q6; suggest reassessing scope or combining methods.")

    details = [DETAILS.get(c, "") for c in chosen]
    return {
        "answers": answers,
        "recommendations": chosen,
        "details": details,
        "rationale": rationale
    }

def main():
    parser = argparse.ArgumentParser(description="Threat Model Selector")
    for qid, text, _ in QUESTIONS:
        parser.add_argument(f"--{qid}", choices=["yes", "no"], help=text + " (yes/no)")
    parser.add_argument("--json", action="store_true", help="Output result as JSON")
    args = parser.parse_args()

    answers: Dict[str, str] = {}

    # Gather answers (CLI flags override interactive prompts)
    for qid, text, _ in QUESTIONS:
        val = getattr(args, qid)
        if val in {"yes", "no"}:
            answers[qid] = val
        else:
            # interactive
            answers[qid] = ask_interactive(qid, text)

    result = decide(answers)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    # Pretty print
    print("\n=== Recommended Threat Modeling Approach ===")
    for rec, detail in zip(result["recommendations"], result["details"]):
        print(f"- {rec}: {detail}")
    print("\nRationale:")
    for r in result["rationale"]:
        print(f"* {r}")
    print("\nAnswers:")
    for qid, ans in result["answers"].items():
        print(f"  {qid.upper()}: {ans}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
