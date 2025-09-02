# Threat Model Selector 3000™ 🛡️✨

> *"Because choosing the wrong threat model is only slightly less embarrassing than forgetting your SBOM at a supply‑chain party."* 📦🥳

---

## What is this? 🤔

A single Python CLI that interviews you (politely-ish) about your system, risk appetite, and constraints, then recommends **threat modeling methods** that fit — now with **Level‑3 refiners** that pick the *specific* variant when bundles are suggested (e.g., **OCTAVE _or_ FAIR** → **FAIR**).

It asks up to **12 core/refinement questions** (Level 1 + Level 2) and, when relevant, **method‑specific Level‑3 questions**. Answers are **yes/no** (also `y/n/true/false/1/0`).

It’s like Tinder, but for security frameworks. 💘🔐

---

## What’s new ✨

- **Level‑3 method refiners** (only asked when relevant):
  - **OCTAVE or FAIR** → resolves to **FAIR** or **OCTAVE**
  - **VAST or Security Cards** → resolves to **VAST** or **Security Cards**
  - **STRIDE** → **STRIDE‑per‑DFD** or **STRIDE‑per‑Element**
  - **PASTA** → **PASTA (full)** or **PASTA (light)**
  - **Attack Trees + MITRE ATT&CK + CAPEC** → **ATT&CK‑led**, **Attack‑Tree‑led**, or **CAPEC‑led**
  - **LINDDUN** → **LINDDUN (DPIA‑oriented)** or **LINDDUN (engineering‑oriented)**
- **Nicer output controls**:
  - `--format text|markdown|json`
  - `--only-condensed` (just Top pick + Also consider)
  - `--answers FILE` (JSON or YAML; handy for CI and reproducibility)
  - Still supports `--no-prompt` for non‑interactive runs
- **Stable JSON** includes `schema_version: "1.0"`

---

## How it works ⚙️

1. **Level 1** (Q1–Q6): chooses main approaches (STRIDE, LINDDUN, PASTA, OCTAVE/FAIR, ATT&CK/Attack Trees/CAPEC, VAST/Security Cards; fallback suggests mixing/reshaping scope).
2. **Level 2** (Q7–Q12): adds context refinements (compliance, safety, CI/CD, quant, TTPs, supply chain).
3. **Level 3**: only for the methods you picked in Level 1; resolves bundles or variants (e.g., STRIDE flavor, VAST vs Cards).
4. **Scoring**: Level‑1 answers set the base; Level‑2 adds small tie‑break bonuses. Level‑3 doesn’t change scores — it **renames** the chosen methods to the specific pick.

---

## Installation 📥

```bash
git clone https://github.com/<you>/<repo>.git
cd <repo>
# It’s just Python 3.
```

> If your file is named differently, adjust commands below. In this README we assume: `threat_model_selector.py`.

---

## Usage 🖱️

### Interactive
```bash
python threat_model_selector.py
```

### Non‑interactive (flags)
```bash
python threat_model_selector.py   --q1 yes --q2 no --q3 yes --q4 yes --q5 no --q6 yes   --q7 yes --q9 yes --q10 yes --q11 yes --q12 no   --l3_octavefair_quant yes --l3_vastcards_scale yes
```

### Only the TL;DR
```bash
python threat_model_selector.py --only-condensed
```

### Output formats
```bash
# Markdown (great for PRs/wikis)
python threat_model_selector.py --format markdown

# JSON (machine‑readable)
python threat_model_selector.py --format json
```

### Bring your own answers (JSON/YAML)
```bash
python threat_model_selector.py --answers answers.json --format json
```
**answers.json**
```json
{
  "q1": "yes", "q3": "yes", "q4": "yes", "q6": "yes",
  "q9": "yes", "q10": "yes", "q11": "yes",
  "l3_octavefair_quant": "yes",         
  "l3_vastcards_scale": "yes",          
  "l3_stride_dfd": "yes",               
  "l3_pasta_light": "yes"               
}
```

### Skip prompts (default unanswered to "no")
```bash
python threat_model_selector.py --no-prompt
```

---

## Level‑3 cheat sheet 🧠

- **OCTAVE or FAIR**
  - `l3_octavefair_quant`: need financial quant? → **FAIR**
  - `l3_octavefair_orgwide`: org‑wide qualitative posture? → **OCTAVE**
- **VAST or Security Cards**
  - `l3_vastcards_scale`: many teams / pipelines? → **VAST**
  - `l3_vastcards_ideation`: creative workshop ideation? → **Security Cards**
- **STRIDE**
  - `l3_stride_dfd`: modeling DFDs/trust boundaries? → **STRIDE‑per‑DFD**
  - `l3_stride_element`: service/component inventory? → **STRIDE‑per‑Element**
- **PASTA**
  - `l3_pasta_full`: full 7‑stage traceability? → **PASTA (full)**
  - `l3_pasta_light`: time‑boxed scenario variant? → **PASTA (light)**
- **Attack Trees + MITRE ATT&CK + CAPEC**
  - `l3_amc_detection`: detection/blue‑team first? → **ATT&CK‑led mapping**
  - `l3_amc_design`: architects/abuse‑case focus? → **Attack‑Tree‑led**
  - `l3_amc_catalog`: reusable pattern catalogs? → **CAPEC‑led cataloging**
- **LINDDUN**
  - `l3_linddun_dpia`: need DPIA/compliance artifact? → **LINDDUN (DPIA‑oriented)**
  - `l3_linddun_engineering`: privacy engineering decisions? → **LINDDUN (engineering‑oriented)**

---

## Example output 📊

### Text (with Level‑3 resolution)
```
Refinements: CI/CD-Integrated Threat Modeling (e.g., VAST, tool-supported STRIDE), MITRE ATT&CK + CAPEC Integration
Scores: PASTA=5, STRIDE=4, OCTAVE or FAIR=4, VAST or Security Cards=4

=== Full Recommendation ===
- STRIDE-per-DFD: Apply STRIDE to data flows/processes/stores across trust boundaries for systematic design coverage.
- PASTA (light): Lightweight, scenario-driven adaptation of PASTA for time-boxed projects while preserving attacker realism.
- FAIR: Financially quantitative risk analysis using loss magnitude/frequency modeling.
- VAST: Scalable threat modeling aligned to Agile/DevOps with automation potential.
- CI/CD-Integrated Threat Modeling (e.g., VAST, tool-supported STRIDE): Automate checks in pipelines; keep models living with architecture-as-code/microservices.
- MITRE ATT&CK + CAPEC Integration: Map threats and mitigations to adversary TTPs and attack patterns; improve realism and detection alignment.

Rationale:
* Q1: If yes, STRIDE maps cleanly to data-flow diagrams and design reviews.
* Q3: If yes, PASTA emphasizes business impact and realistic attack scenarios.
* Q4: If yes, OCTAVE supports org-wide risk posture; FAIR adds financial quantification.
* Q6: If yes, VAST supports scalable modeling; Security Cards boost ideation.
* Q9: If yes, favor approaches and tooling that work well in DevSecOps pipelines.
* Q11: If yes, ensure ATT&CK/CAPEC alignment and attack simulation.

Answers:
  Q1: yes
  Q2: no
  Q3: yes
  Q4: yes
  Q5: no
  Q6: yes
  Q7: no
  Q8: no
  Q9: yes
  Q10: yes
  Q11: yes
  Q12: no
  -- L3 refiners --
  l3_stride_dfd: yes
  l3_pasta_light: yes
  l3_octavefair_quant: yes
  l3_vastcards_scale: yes

=== Condensed Recommendation ===
Top pick: PASTA (light)
Also consider: STRIDE-per-DFD, FAIR, VAST
```

### Markdown
```markdown
# Threat Model Selector Results

## Condensed Recommendation
- **Top pick:** FAIR
- **Also consider:** STRIDE-per-Element, PASTA (full)

**Scores:** FAIR=5, STRIDE=4, PASTA=4

## Full Recommendation
- **FAIR** — Financially quantitative risk analysis using loss magnitude/frequency modeling.
- **STRIDE-per-Element** — Apply STRIDE to each component/service when DFDs are impractical or the system is service-oriented.
- **PASTA (full)** — Follow all seven stages with end-to-end traceability from business objectives to test cases and mitigations.
```

### JSON (schema snippet)
```json
{
  "schema_version": "1.0",
  "top_pick": "VAST",
  "also_consider": ["FAIR", "STRIDE-per-DFD"],
  "preference_scores": {"VAST or Security Cards": 4, "OCTAVE or FAIR": 4, "STRIDE": 4},
  "recommendations": [
    "VAST",
    "FAIR",
    "STRIDE-per-DFD",
    "CI/CD-Integrated Threat Modeling (e.g., VAST, tool-supported STRIDE)"
  ]
}
```

> Note: `preference_scores` are keyed by the **original Level‑1 labels** for transparency; human‑friendly names are resolved in `top_pick`, `also_consider`, and `recommendations`.

---

## FAQ ❓💡

**What if I answer everything with “no”?**  
You’ve unlocked *Procrastinate‑Driven Development™*. The tool suggests revisiting scope or combining methods until something fits.

**What’s the “condensed recommendation”?**  
The TL;DR: a **Top pick**, an **also consider** list, and any refinements to sprinkle on top. 🌶️

**Can I add my own frameworks or change weights?**  
Yes. Extend `DETAILS`, `L3_BLOCKS`, and `resolve_l3()` as you like. (Framework weighting is on the roadmap; PRs welcome.)

**Why so many jokes?**  
Because security is serious 🔐, but docs don’t have to be. 😂

---

## License 📜🚀

Released under the **Infinite Improbability License**. 🌌  
Do whatever you like — if it goes wrong, blame the Vogons. 👽📚
