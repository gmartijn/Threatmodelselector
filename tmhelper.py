#!/usr/bin/env python3
"""
Threat Model Selector (Two-Level + Level-3 Refiners + Output/UX Upgrades)

Adds Level 3 method-specific refiners and nicer output controls.

Asks up to 12 questions for L1/L2 and optional L3 blocks gated by L1 picks.
Outputs:
- Full recommendation list with details and rationale
- Condensed summary and "Top pick" based on input-driven scoring
- JSON/Markdown/Text formats with a stable schema version

Usage:
  Interactive (default when stdin is a TTY and --no-prompt is not set):
    python threat_model_selector.py

  Non-interactive (lenient yes/no values):
    python threat_model_selector.py \
      --q1 yes --q2 no --q3 yes --q4 no --q5 yes --q6 no \
      --q7 yes --q8 no --q9 yes --q10 yes --q11 yes --q12 no

  JSON output:
    python threat_model_selector.py --format json

  Markdown output (great for wikis/PRs):
    python threat_model_selector.py --format markdown

  Skip prompts (useful in CI; unanswered default to "no"):
    python threat_model_selector.py --no-prompt

  Only condensed:
    python threat_model_selector.py --only-condensed

  Provide answers from file (JSON or YAML):
    python threat_model_selector.py --answers answers.json

Notes:
- CLI answers accept: y/n/yes/no/true/false/1/0 (case-insensitive).
- Level 1 picks the main modeling approaches; Level 2 adds focused refinements.
- Level 3 refines ambiguous Level-1 bundles (e.g., OCTAVE vs FAIR; VAST vs Security Cards).
- "Top pick" is chosen from Level 1 selections; Level 2 provides tie-break boosts; Level 3 resolves names.
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
    "Supply-Chain Modeling (SBOM-centric)": "Model dependency risk, update cadence, provenance, and exposure through SBOM-driven analysis.",
    # Resolved L3 specifics
    "FAIR": "Financially quantitative risk analysis using loss magnitude/frequency modeling.",
    "OCTAVE": "Organization-centric, qualitative risk posture and process-focused analysis.",
    "VAST": "Scalable threat modeling aligned to Agile/DevOps with automation potential.",
    "Security Cards": "Workshop method to spark creative attacker-motive-driven ideation.",
    "STRIDE-per-DFD": "Apply STRIDE to data flows/processes/stores across trust boundaries for systematic design coverage.",
    "STRIDE-per-Element": "Apply STRIDE to each component/service when DFDs are impractical or the system is service-oriented.",
    "PASTA (full)": "Follow all seven stages with end-to-end traceability from business objectives to test cases and mitigations.",
    "PASTA (light)": "Lightweight, scenario-driven adaptation of PASTA for time-boxed projects while preserving attacker realism.",
    "LINDDUN (DPIA-oriented)": "Use LINDDUN to drive a DPIA-style artifact with explicit mapping to regulatory obligations.",
    "LINDDUN (engineering-oriented)": "Focus LINDDUN outputs on design decisions (minimization, unlinkability, consent patterns) over paperwork.",
    "ATT&CK-led mapping": "Drive analysis from adversary TTPs to detections/controls; great for blue teams and purple teaming.",
    "Attack-Tree-led": "Start from attacker goals and decompose paths for design and abuse-case reviews; great for architects.",
    "CAPEC-led cataloging": "Organize by attack pattern classes to create reusable requirements/test catalogs across products."
}

# -------------------------
# Level 3: Method-specific refiners
# -------------------------
# Only asked if the corresponding Level-1 method is selected.
# Keys must match Level-1 method labels.
L3_BLOCKS: Dict[str, List[Question]] = {
    "OCTAVE or FAIR": [
        ("l3_octavefair_quant", "Do you need defensible financial quantification for board/budget decisions?",
         "If yes, prefer FAIR for quantitative risk modeling."),
        ("l3_octavefair_orgwide", "Is org-wide process/culture and qualitative posture your main focus?",
         "If yes, prefer OCTAVE for organization-centric risk posture."),
    ],
    "VAST or Security Cards": [
        ("l3_vastcards_scale", "Do you need to scale modeling across many Agile/DevOps teams or integrate with pipelines?",
         "If yes, VAST fits scalable, automatable workflows."),
        ("l3_vastcards_ideation", "Do you want creative, workshop-style ideation to explore attacker motives?",
         "If yes, Security Cards boost group ideation."),
    ],
    "STRIDE": [
        ("l3_stride_dfd", "Will you model data flows with DFDs (trust boundaries, stores, processes)?",
         "If yes, prefer STRIDE-per-DFD for systematic coverage."),
        ("l3_stride_element", "Is your architecture better captured as components/services without DFDs?",
         "If yes, prefer STRIDE-per-Element for inventory-driven analysis."),
    ],
    "PASTA": [
        ("l3_pasta_full", "Do you need full 7-stage traceability from business objectives to test cases?",
         "If yes, prefer PASTA (full)."),
        ("l3_pasta_light", "Do you want a lighter, scenario-driven variant due to time constraints?",
         "If yes, prefer PASTA (light)."),
    ],
    "LINDDUN": [
        ("l3_linddun_dpia", "Is your primary outcome a DPIA/compliance artifact (e.g., GDPR Article 35)?",
         "If yes, emphasize LINDDUN (DPIA-oriented)."),
        ("l3_linddun_engineering", "Do you focus on privacy engineering decisions (data minimization, unlinkability) over paperwork?",
         "If yes, emphasize LINDDUN (engineering-oriented)."),
    ],
    "Attack Trees + MITRE ATT&CK + CAPEC": [
        ("l3_amc_detection", "Are the main consumers detection/blue teams wanting TTP coverage and detections?",
         "If yes, prefer ATT&CK-led mapping."),
        ("l3_amc_design", "Are the main consumers architecture/design teams needing scenario trees for abuse cases?",
         "If yes, prefer Attack-Tree-led."),
        ("l3_amc_catalog", "Do you need structured pattern coverage for classes of attacks (for requirements/testing catalogs)?",
         "If yes, prefer CAPEC-led cataloging."),
    ],
}

# Map ambiguous Level-1 labels to display-specific picks based on L3 answers.
def resolve_l3(method: str, answers: Dict[str, str]) -> str:
    if method == "OCTAVE or FAIR":
        q_quant = answers.get("l3_octavefair_quant") == "yes"
        q_org = answers.get("l3_octavefair_orgwide") == "yes"
        if q_quant and not q_org:
            return "FAIR"
        if q_org and not q_quant:
            return "OCTAVE"
        if q_quant and q_org:
            return "FAIR"  # prefer FAIR when both are true
        return method
    if method == "VAST or Security Cards":
        q_scale = answers.get("l3_vastcards_scale") == "yes"
        q_ideate = answers.get("l3_vastcards_ideation") == "yes"
        if q_scale and not q_ideate:
            return "VAST"
        if q_ideate and not q_scale:
            return "Security Cards"
        if q_scale and q_ideate:
            return "VAST"  # prefer VAST for operational scale
        return method
    if method == "STRIDE":
        q_dfd = answers.get("l3_stride_dfd") == "yes"
        q_elem = answers.get("l3_stride_element") == "yes"
        if q_dfd and not q_elem:
            return "STRIDE-per-DFD"
        if q_elem and not q_dfd:
            return "STRIDE-per-Element"
        if q_dfd and q_elem:
            return "STRIDE-per-DFD"  # default to DFD if both
        return method
    if method == "PASTA":
        q_full = answers.get("l3_pasta_full") == "yes"
        q_light = answers.get("l3_pasta_light") == "yes"
        if q_full and not q_light:
            return "PASTA (full)"
        if q_light and not q_full:
            return "PASTA (light)"
        if q_full and q_light:
            return "PASTA (full)"  # prefer full when both
        return method
    if method == "LINDDUN":
        q_dpia = answers.get("l3_linddun_dpia") == "yes"
        q_eng = answers.get("l3_linddun_engineering") == "yes"
        if q_dpia and not q_eng:
            return "LINDDUN (DPIA-oriented)"
        if q_eng and not q_dpia:
            return "LINDDUN (engineering-oriented)"
        if q_dpia and q_eng:
            return "LINDDUN (DPIA-oriented)"  # bias to compliance when both
        return method
    if method == "Attack Trees + MITRE ATT&CK + CAPEC":
        q_det = answers.get("l3_amc_detection") == "yes"
        q_des = answers.get("l3_amc_design") == "yes"
        q_cat = answers.get("l3_amc_catalog") == "yes"
        # Priority: detection > design > catalog (can tweak)
        if q_det and not (q_des or q_cat):
            return "ATT&CK-led mapping"
        if q_des and not (q_det or q_cat):
            return "Attack-Tree-led"
        if q_cat and not (q_det or q_des):
            return "CAPEC-led cataloging"
        # Mixed: prefer ATT&CK-led if detection is among goals
        if q_det:
            return "ATT&CK-led mapping"
        if q_des:
            return "Attack-Tree-led"
        if q_cat:
            return "CAPEC-led cataloging"
        return method
    return method

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

    # Compute preference scores to select a top pick among Level 1 selections
    scores = _compute_preference_scores(answers, chosen)

    # Determine top pick: highest score; stable tie-break by L1 question order
    top_pick = _select_top_pick(scores, chosen)

    # Also consider: other L1 picks (excluding top) in score order
    also_consider = [m for m in _sorted_by_score(scores) if m != top_pick]

    # Initial details based on pre-resolution names
    details = [DETAILS.get(c, "") for c in recommendations]

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
        if answers.get("q7") == "yes":
            scores["STRIDE"] += 0  # neutral but kept for readability

    if "LINDDUN" in scores:
        if answers.get("q7") == "yes":
            scores["LINDDUN"] += BONUS

    if "PASTA" in scores:
        if answers.get("q11") == "yes":
            scores["PASTA"] += BONUS
        if answers.get("q10") == "yes":
            scores["PASTA"] += BONUS

    if "OCTAVE or FAIR" in scores:
        if answers.get("q10") == "yes":
            scores["OCTAVE or FAIR"] += BONUS
        if answers.get("q7") == "yes":
            scores["OCTAVE or FAIR"] += BONUS

    if "Attack Trees + MITRE ATT&CK + CAPEC" in scores:
        if answers.get("q11") == "yes":
            scores["Attack Trees + MITRE ATT&CK + CAPEC"] += BONUS

    if "VAST or Security Cards" in scores:
        if answers.get("q9") == "yes":
            scores["VAST or Security Cards"] += BONUS

    return {k: int(v) for k, v in scores.items()}


def _sorted_by_score(scores: Dict[str, int]) -> List[str]:
    # Stable sort by (-score, PRIMARY_METHODS index) for deterministic ordering
    return sorted(scores.keys(),
                  key=lambda m: (-scores[m], PRIMARY_METHODS.index(m)))


def _select_top_pick(scores: Dict[str, int], l1_selected: List[str]) -> str:
    if not scores:
        return "Reconsider scope / combine methods" if "Reconsider scope / combine methods" in l1_selected else (l1_selected[0] if l1_selected else "")
    return _sorted_by_score(scores)[0]

# -------------------------
# CLI
# -------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Threat Model Selector (Two-Level + Condensed Recommendation + L3 Refiners)")
    # Level 1 flags
    for qid, text, _ in QUESTIONS_L1:
        parser.add_argument(f"--{qid}", type=_cli_choice, help=text + " (yes/no)")
    # Level 2 flags
    for qid, text, _ in QUESTIONS_L2:
        parser.add_argument(f"--{qid}", type=_cli_choice, help=text + " (yes/no)")

    # Level 3 flags (namespaced by explicit IDs; shown/used only if relevant)
    for method, block in L3_BLOCKS.items():
        for qid, text, _ in block:
            parser.add_argument(f"--{qid}", type=_cli_choice, help=f"[{method}] {text} (yes/no)")

    parser.add_argument(
        "--format",
        choices=["text", "markdown", "json"],
        default="text",
        help="Output format (text, markdown, json)."
    )
    parser.add_argument(
        "--only-condensed",
        action="store_true",
        help="Only print the condensed recommendation (top pick + also consider)."
    )
    parser.add_argument(
        "--answers",
        type=str,
        help="Path to JSON or YAML file containing q1..q12 and optional L3 answers."
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Do not prompt; default unanswered questions to 'no' (useful in CI)"
    )

    args = parser.parse_args()

    answers: Dict[str, str] = {}
    interactive_ok = sys.stdin.isatty() and not args.no_prompt

    # Load answers file (if provided)
    if args.answers:
        from pathlib import Path as _Path
        p = _Path(args.answers)
        if not p.exists():
            print(f"Error: answers file not found: {p}", file=sys.stderr)
            sys.exit(2)
        text = p.read_text(encoding="utf-8")
        data: Dict[str, Any]
        try:
            data = json.loads(text)
        except Exception:
            try:
                import yaml as _yaml  # type: ignore
                data = _yaml.safe_load(text)  # type: ignore
            except Exception:
                print("Error: failed to parse answers file as JSON or YAML.", file=sys.stderr)
                sys.exit(2)
        if not isinstance(data, dict):
            print("Error: answers file must contain an object with q1..q12 keys.", file=sys.stderr)
            sys.exit(2)
        for qid, _t, _w in QUESTIONS_L1 + QUESTIONS_L2:
            v = data.get(qid)
            if isinstance(v, str):
                nv = normalize_answer(v)
                if nv in {"yes", "no"}:
                    answers[qid] = nv
        # Optional L3 keys from file
        for method, block in L3_BLOCKS.items():
            for qid, _t, _w in block:
                v = data.get(qid)
                if isinstance(v, str):
                    nv = normalize_answer(v)
                    if nv in {"yes", "no"}:
                        answers[qid] = nv

    # Level 1 first
    for qid, text, _ in QUESTIONS_L1:
        val = getattr(args, qid)
        if val in {"yes", "no"}:
            answers[qid] = val
        else:
            answers[qid] = ask_interactive(text) if interactive_ok else answers.get(qid, "no")

    # Level 2 next
    for qid, text, _ in QUESTIONS_L2:
        val = getattr(args, qid)
        if val in {"yes", "no"}:
            answers[qid] = val
        else:
            answers[qid] = ask_interactive(text) if interactive_ok else answers.get(qid, "no")

    # Level 3: only prompt for methods selected in Level 1
    provisional_l1 = []
    for (qid, _text, _why) in QUESTIONS_L1:
        if answers.get(qid) == "yes":
            rec = RECOMMENDATIONS_L1[qid]["yes"]
            if rec not in provisional_l1:
                provisional_l1.append(rec)

    for method in provisional_l1:
        block = L3_BLOCKS.get(method, [])
        for qid, text, _ in block:
            val = getattr(args, qid, None)
            if val in {"yes", "no"}:
                answers[qid] = val
            else:
                answers[qid] = ask_interactive(f"[{method}] {text}") if interactive_ok else answers.get(qid, "no")

    result = decide(answers)

    # Post-process: resolve ambiguous L1 labels for display (recommendations/top pick/also_consider)
    def _resolved_name(name: str) -> str:
        return resolve_l3(name, result["answers"])

    result["recommendations"] = [_resolved_name(r) for r in result["recommendations"]]
    result["top_pick"] = _resolved_name(result["top_pick"])
    result["also_consider"] = [_resolved_name(a) for a in result["also_consider"]]

    # Recompute details after L3 resolution to keep JSON consistent
    result["details"] = [DETAILS.get(r, "") for r in result["recommendations"]]

    # Add a schema version
    result_out = dict(result)
    result_out["schema_version"] = "1.0"

    # ---------- Output helpers ----------
    def _print_text(res: Dict[str, Any]) -> None:
        if args.only_condensed:
            print("=== Condensed Recommendation ===")
            tp = res["top_pick"] or "N/A"
            print(f"Top pick: {tp}")
            if res["also_consider"]:
                print("Also consider: " + ", ".join(res["also_consider"]))
            if tp == "Reconsider scope / combine methods" and not [k for k, v in res["preference_scores"].items() if v > 0]:
                print("(No strong Level-1 fit; consider refining scope or combining methods.)")
            return

        refinements = [r for r in res["recommendations"] if r not in PRIMARY_METHODS]
        if refinements:
            print("Refinements: " + ", ".join(refinements))

        if res["preference_scores"]:
            pairs = [f"{m}={res['preference_scores'][m]}" for m in _sorted_by_score(res["preference_scores"]) ]
            print("Scores: " + ", ".join(pairs))

        print("\n=== Full Recommendation ===")
        for rec, detail in zip(res["recommendations"], res["details"]):
            print(f"- {rec}: {detail}")

        print("\nRationale:")
        for r in res["rationale"]:
            print(f"* {r}")

        print("\nAnswers:")
        for qid, _text, _why in QUESTIONS_L1 + QUESTIONS_L2:
            print(f"  {qid.upper()}: {res['answers'][qid]}")
        # Show L3 answers that were asked or provided
        asked_l3 = [qid for block in L3_BLOCKS.values() for (qid, _t, _w) in block]
        any_l3 = any(qid in res["answers"] for qid in asked_l3)
        if any_l3:
            print("  -- L3 refiners --")
            for method, block in L3_BLOCKS.items():
                for qid, text, _w in block:
                    if qid in res["answers"]:
                        print(f"  {qid}: {res['answers'][qid]}")

        print("\n=== Condensed Recommendation ===")
        print(f"Top pick: {res['top_pick'] or 'N/A'}")
        if res["also_consider"]:
            print("Also consider: " + ", ".join(res["also_consider"]))
        if res["top_pick"] == "Reconsider scope / combine methods" and not [k for k, v in res["preference_scores"].items() if v > 0]:
            print("(No strong Level-1 fit; consider refining scope or combining methods.)")

    def _print_markdown(res: Dict[str, Any]) -> None:
        print("# Threat Model Selector Results\n")
        print("## Condensed Recommendation")
        print(f"- **Top pick:** {res['top_pick'] or 'N/A'}")
        if res["also_consider"]:
            print(f"- **Also consider:** {', '.join(res['also_consider'])}")
        if res["top_pick"] == "Reconsider scope / combine methods" and not [k for k, v in res["preference_scores"].items() if v > 0]:
            print("  - _No strong Level-1 fit; consider refining scope or combining methods._")
        if res["preference_scores"]:
            ordered = _sorted_by_score(res["preference_scores"]) 
            line = ", ".join([f"{m}={res['preference_scores'][m]}" for m in ordered])
            print(f"\n**Scores:** {line}\n")
        print("## Full Recommendation")
        for rec, detail in zip(res["recommendations"], res["details"]):
            print(f"- **{rec}** — {detail}")
        print("\n## Rationale")
        for r in res["rationale"]:
            print(f"- {r}")
        print("\n## Answers")
        for qid, text, _why in QUESTIONS_L1 + QUESTIONS_L2:
            print(f"- **{qid.upper()}** ({text}): {res['answers'][qid]}")
        asked_l3 = [qid for block in L3_BLOCKS.values() for (qid, _t, _w) in block]
        any_l3 = any(qid in res["answers"] for qid in asked_l3)
        if any_l3:
            print("\n## Level-3 Refiners")
            for method, block in L3_BLOCKS.items():
                for qid, text, _w in block:
                    if qid in res["answers"]:
                        print(f"- **{qid}** ({text}): {res['answers'][qid]}")

    if args.format == "json":
        print(json.dumps(result_out, indent=2))
        return
    elif args.format == "markdown":
        _print_markdown(result_out)
    else:
        _print_text(result_out)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
