#!/usr/bin/env python3
"""
Threat Model Selector (Two-Level + Condensed Recommendation)
Asks up to 12 questions:
- Level 1 (Q1–Q6): Core method fit
- Level 2 (Q7–Q12): Refinements for context/constraints/outcomes
Outputs:
- Full recommendation list with details and rationale
- Condensed summary and "Top pick" (preference) based on input-driven scoring

Usage:
  Interactive (default when stdin is a TTY and --no-prompt is not set):
    python threat_model_selector.py

  Non-interactive (lenient yes/no values):
    python threat_model_selector.py \
      --q1 yes --q2 no --q3 yes --q4 no --q5 yes --q6 no \
      --q7 yes --q8 no --q9 yes --q10 yes --q11 yes --q12 no

  JSON output:
    python threat_model_selector.py --json

  Skip prompts (useful in CI; unanswered default to "no"):
    python threat_model_selector.py --no-prompt

Notes:
- CLI answers accept: y/n/yes/no/true/false/1/0 (case-insensitive).
- Level 1 picks the main modeling approaches; Level 2 adds focused refinements.
- "Top pick" is chosen from Level 1 selections (or fallback), with Level 2 providing tie-break boosts.
"""

import argparse
import json
import sys
from typing import Dict, List, Tuple, Any

Question = Tuple[str, str, str]  # (id, text, rationale)

# -------------------------
# Level 1: Core method fit
# -------------------------
QUESTIONS_L1: List[Question] = [
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

RECOMMENDATIONS_L1: Dict[str, Dict[str, str]] = {
    "q1": {"yes": "STRIDE", "no": "next"},
    "q2": {"yes": "LINDDUN", "no": "next"},
    "q3": {"yes": "PASTA", "no": "next"},
    "q4": {"yes": "OCTAVE or FAIR", "no": "next"},
    "q5": {"yes": "Attack Trees + MITRE ATT&CK + CAPEC", "no": "next"},
    "q6": {"yes": "VAST or Security Cards", "no": "Reconsider scope / combine methods"}
}

PRIMARY_METHODS = [
    "STRIDE",
    "LINDDUN",
    "PASTA",
    "OCTAVE or FAIR",
    "Attack Trees + MITRE ATT&CK + CAPEC",
    "VAST or Security Cards",
    "Reconsider scope / combine methods",  # fallback
]

# ---------------------------------------
# Level 2: Refinements (context/outcomes)
# ---------------------------------------
QUESTIONS_L2: List[Question] = [
    ("q7", "Do you need to produce regulator/auditor-ready artifacts or map to specific compliance frameworks?",
     "If yes, add compliance-oriented outputs and crosswalks to your model."),
    ("q8", "Is the system safety-critical (e.g., medical, automotive, industrial control)?",
     "If yes, include safety-informed security analysis (e.g., STPA-Sec)."),
    ("q9", "Do you want the model to integrate with CI/CD or be automatable for cloud/microservices?",
     "If yes, favor approaches and tooling that work well in DevSecOps pipelines."),
    ("q10", "Do you require quantitative risk outputs for budgeting/board decisions?",
     "If yes, include FAIR-style quantitative analysis."),
    ("q11", "Will you map findings against real-world adversary TTPs (threat intelligence)?",
     "If yes, ensure ATT&CK/CAPEC alignment and attack simulation."),
    ("q12", "Is supply chain or third-party risk (dependencies/SBOM) in scope?",
     "If yes, include supply-chain-focused modeling and SBOM-driven analysis.")
]

REFINEMENTS: Dict[str, List[str]] = {
    "q7": ["Compliance Crosswalks / Auditor Artifacts"],
    "q8": ["STPA-Sec (Safety-Informed Security)"],
    "q9": ["CI/CD-Integrated Threat Modeling (e.g., VAST, tool-supported STRIDE)"],
    "q10": ["FAIR (Quantitative Add-on)"],
    "q11": ["MITRE ATT&CK + CAPEC Integration"],
    "q12": ["Supply-Chain Modeling (SBOM-centric)"]
}

DETAILS: Dict[str, str] = {
    # Level 1 details
    "STRIDE": "Use for system/DFD-centric design reviews to enumerate Spoofing, Tampering, Repudiation, Info Disclosure, DoS, EoP.",
    "LINDDUN": "Privacy threat modeling focused on Linkability, Identifiability, Non-repudiation, Detectability, Disclosure, Unawareness, Non-compliance.",
    "PASTA": "Seven-stage, risk-driven method aligning attacker scenarios with business impact.",
    "OCTAVE or FAIR": "OCTAVE for org-wide risk posture; FAIR for financial quantification of risk magnitude.",
    "Attack Trees + MITRE ATT&CK + CAPEC": "Attack Trees map paths to goals; ATT&CK provides real-world TTPs; CAPEC catalogs attack patterns.",
    "VAST or Security Cards": "VAST scales across Agile/DevOps; Security Cards facilitate creative brainstorming with adversary/motive prompts.",
    "Reconsider scope / combine methods": "If none matched strongly, reassess objectives or explicitly combine methods (e.g., STRIDE + LINDDUN; PASTA + ATT&CK).",
    # Level 2 details
    "Compliance Crosswalks / Auditor Artifacts": "Produce traceable outputs mapped to control catalogs/regulations; generate evidence-ready artifacts.",
    "STPA-Sec (Safety-Informed Security)": "Integrate system safety analysis with security hazards to address harm to humans/physical systems.",
    "CI/CD-Integrated Threat Modeling (e.g., VAST, tool-supported STRIDE)": "Automate checks in pipelines; keep models living with architecture-as-code/microservices.",
    "FAIR (Quantitative Add-on)": "Augment with loss magnitude/frequency estimates to support budgeting and risk acceptance.",
    "MITRE ATT&CK + CAPEC Integration": "Map threats and mitigations to adversary TTPs and attack patterns; improve realism and detection alignment.",
    "Supply-Chain Modeling (SBOM-centric)": "Model dependency risk, update cadence, provenance, and exposure through SBOM-driven analysis."
}

# -------------------------
# Input handling utilities
# -------------------------
def normalize_answer(s: str) -> str:
    s = s.strip().lower()
    if s in {"y", "yes", "true", "t", "1"}:
        return "yes"
    if s in {"n", "no", "false", "f", "0"}:
        return "no"
    return ""


def ask_interactive(text: str) -> str:
    while True:
        ans = input(f"{text} [y/n]: ").strip()
        norm = normalize_answer(ans)
        if norm:
            return norm
        print("Please answer 'y' or 'n'.")


def _cli_choice(s: str) -> str:
    n = normalize_answer(s)
    if n in {"yes", "no"}:
        return n
    raise argparse.ArgumentTypeError("Must be yes/no (also accepts y/n/true/false/1/0)")

# -------------------------
# Decision engine (L1 + L2)
# -------------------------
def decide(answers: Dict[str, str]) -> Dict[str, Any]:
    """
    Returns:
      answers, recommendations, details, rationale,
      preference_scores (dict), top_pick (str), also_consider (list)
    Fallback is added ONLY if no L1 'yes' answers were given.
    """
    chosen: List[str] = []
    rationale: List[str] = []

    # Level 1: core fit
    for (qid, _text, why) in QUESTIONS_L1:
        ans = answers.get(qid, "no")
        if ans == "yes":
            rec = RECOMMENDATIONS_L1[qid]["yes"]
            if rec not in chosen:
                chosen.append(rec)
                rationale.append(f"{qid.upper()}: {why}")

    # Fallback if no L1 selected at all
    if not chosen:
        fallback = RECOMMENDATIONS_L1["q6"]["no"]
        chosen.append(fallback)
        rationale.append("No strong fit identified in Q1–Q6; suggest reassessing scope or combining methods.")

    # Level 2: refinements (add-on emphases)
    refinements_selected: List[str] = []
    for (qid, _text, why) in QUESTIONS_L2:
        ans = answers.get(qid, "no")
        if ans == "yes":
            for rec in REFINEMENTS.get(qid, []):
                if rec not in refinements_selected:
                    refinements_selected.append(rec)
            rationale.append(f"{qid.upper()}: {why}")

    # Merge full list (L1 first, then refinements)
    recommendations = chosen + [r for r in refinements_selected if r not in chosen]
    details = [DETAILS.get(c, "") for c in recommendations]

    # Compute preference scores to select a top pick among Level 1 selections
    scores = _compute_preference_scores(answers, chosen)

    # Determine top pick: highest score; stable tie-break by L1 question order
    top_pick = _select_top_pick(scores, chosen)

    # Also consider: other L1 picks (excluding top) in score order
    also_consider = [m for m in _sorted_by_score(scores) if m != top_pick]

    return {
        "answers": answers,
        "recommendations": recommendations,
        "details": details,
        "rationale": rationale,
        "preference_scores": scores,
        "top_pick": top_pick,
        "also_consider": also_consider
    }

# -------------------------
# Preference scoring
# -------------------------
def _compute_preference_scores(answers: Dict[str, str], l1_selected: List[str]) -> Dict[str, int]:
    """
    Score only Level-1 (primary) methods. Base points for each 'yes' pick,
    plus small bonuses from Level-2 answers as tie-breakers.
    """
    # Base score for being selected at all
    BASE = 3
    BONUS = 1

    scores: Dict[str, int] = {m: 0 for m in l1_selected}

    # Assign base scores from L1 picks
    for (qid, _text, _why) in QUESTIONS_L1:
        if answers.get(qid) == "yes":
            m = RECOMMENDATIONS_L1[qid]["yes"]
            if m in scores:
                scores[m] += BASE

    # Tie-breaker boosts from L2 (heuristics)
    if "STRIDE" in scores:
        if answers.get("q9") == "yes":  # CI/CD + cloud
            scores["STRIDE"] += BONUS
        if answers.get("q7") == "yes":  # compliance docs sometimes needed in STRIDE reviews
            scores["STRIDE"] += 0  # leave neutral unless you want to influence

    if "LINDDUN" in scores:
        if answers.get("q7") == "yes":  # compliance / privacy by design
            scores["LINDDUN"] += BONUS

    if "PASTA" in scores:
        if answers.get("q11") == "yes":  # TTP / intel mapping
            scores["PASTA"] += BONUS
        if answers.get("q10") == "yes":  # quantitative appetite
            scores["PASTA"] += BONUS  # risk-driven method often pairs well with quant

    if "OCTAVE or FAIR" in scores:
        if answers.get("q10") == "yes":  # quantitative for board/budget
            scores["OCTAVE or FAIR"] += BONUS
        if answers.get("q7") == "yes":  # compliance artifacts
            scores["OCTAVE or FAIR"] += BONUS

    if "Attack Trees + MITRE ATT&CK + CAPEC" in scores:
        if answers.get("q11") == "yes":  # TTP integration
            scores["Attack Trees + MITRE ATT&CK + CAPEC"] += BONUS

    if "VAST or Security Cards" in scores:
        if answers.get("q9") == "yes":  # CI/CD / scale
            scores["VAST or Security Cards"] += BONUS

    # Fallback stays with its base only if it's the only one
    return {k: int(v) for k, v in scores.items()}


def _sorted_by_score(scores: Dict[str, int]) -> List[str]:
    # Stable sort by (-score, PRIMARY_METHODS index) for deterministic ordering
    return sorted(scores.keys(),
                  key=lambda m: (-scores[m], PRIMARY_METHODS.index(m)))


def _select_top_pick(scores: Dict[str, int], l1_selected: List[str]) -> str:
    if not scores:
        # When only fallback exists or no L1 picks, return fallback (if present), else ""
        return "Reconsider scope / combine methods" if "Reconsider scope / combine methods" in l1_selected else (l1_selected[0] if l1_selected else "")
    return _sorted_by_score(scores)[0]

# -------------------------
# CLI
# -------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Threat Model Selector (Two-Level + Condensed Recommendation)")
    # Level 1 flags
    for qid, text, _ in QUESTIONS_L1:
        parser.add_argument(f"--{qid}", type=_cli_choice, help=text + " (yes/no)")
    # Level 2 flags
    for qid, text, _ in QUESTIONS_L2:
        parser.add_argument(f"--{qid}", type=_cli_choice, help=text + " (yes/no)")

    parser.add_argument("--json", action="store_true", help="Output result as JSON")
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Do not prompt; default unanswered questions to 'no' (useful in CI)"
    )

    args = parser.parse_args()

    answers: Dict[str, str] = {}
    interactive_ok = sys.stdin.isatty() and not args.no_prompt

    # Gather answers (CLI flags override interactive prompts)
    # Level 1 first
    for qid, text, _ in QUESTIONS_L1:
        val = getattr(args, qid)
        if val in {"yes", "no"}:
            answers[qid] = val
        else:
            answers[qid] = ask_interactive(text) if interactive_ok else "no"

    # Level 2 next
    for qid, text, _ in QUESTIONS_L2:
        val = getattr(args, qid)
        if val in {"yes", "no"}:
            answers[qid] = val
        else:
            answers[qid] = ask_interactive(text) if interactive_ok else "no"

    result = decide(answers)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    # Brief refinements line (if any)
    refinements = [r for r in result["recommendations"] if r not in PRIMARY_METHODS]
    if refinements:
        print("Refinements: " + ", ".join(refinements))

    # Preference scores (for transparency)
    if result["preference_scores"]:
        pairs = [f"{m}={result['preference_scores'][m]}" for m in _sorted_by_score(result["preference_scores"])]
        print("Scores: " + ", ".join(pairs))

    # ---------- Full output ----------
    print("\n=== Full Recommendation ===")
    for rec, detail in zip(result["recommendations"], result["details"]):
        print(f"- {rec}: {detail}")

    print("\nRationale:")
    for r in result["rationale"]:
        print(f"* {r}")

    print("\nAnswers:")
    # Preserve order: L1 then L2
    for qid, _text, _why in QUESTIONS_L1 + QUESTIONS_L2:
        print(f"  {qid.upper()}: {result['answers'][qid]}")

    # ---------- Condensed summary ----------
    print("\n=== Condensed Recommendation ===")
    print(f"Top pick: {result['top_pick'] or 'N/A'}")

    if result["also_consider"]:
        print("Also consider: " + ", ".join(result["also_consider"]))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
