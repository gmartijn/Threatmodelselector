# Threat Model Selector 3000™ 🛡️✨

> *"Because picking the wrong threat model is only slightly less embarrassing than forgetting your SBOM at a supply‑chain party."* 📦🥳  
> Bonus: now with Level‑3 questions so you can win arguments faster and with charts. 📈

---

## What is this? 🤔

`tmhelper.py` is a tiny Python CLI that interviews you (politely‑ish) about your system, risk appetite, and constraints, then recommends **threat modeling methods** that fit.  
It asks **Level‑1** (core fit) and **Level‑2** (refinements) questions — and, when relevant, **Level‑3** questions that resolve bundles into a *specific* choice (e.g., **OCTAVE or FAIR** → **FAIR**).

It’s like Tinder, but for security frameworks. 💘🔐  
Except the dates are compliance audits, and the ghosting is… your logging pipeline. 👻📜

---

## What’s new ✨

- **Level‑3 method refiners** (asked *only* when relevant):
  - **OCTAVE or FAIR** → **FAIR** or **OCTAVE** (spreadsheets vs workshops)
  - **VAST or Security Cards** → **VAST** or **Security Cards** (scale vs vibes)
  - **STRIDE** → **STRIDE‑per‑DFD** or **STRIDE‑per‑Element** (boxes vs inventories)
  - **PASTA** → **PASTA (full)** or **PASTA (light)** (tasting menu vs express lunch)
  - **Attack Trees + MITRE ATT&CK + CAPEC** → **ATT&CK‑led**, **Attack‑Tree‑led**, or **CAPEC‑led**
  - **LINDDUN** → **LINDDUN (DPIA‑oriented)** or **LINDDUN (engineering‑oriented)**
- **Output/UX upgrades**:
  - `--format text|markdown|json` (pick your poison)
  - `--only-condensed` (the TL;DR your PM will actually read)
  - `--answers FILE` (JSON/YAML — because answering the same questions 47 times is a prank, not a process)
  - `--no-prompt` (great for CI and introverts)
- **Stable JSON** includes `schema_version: "1.0"` (future‑you says thanks)

---

## How it works ⚙️

1. **Level 1 (Q1–Q6):** choose main approaches — STRIDE, LINDDUN, PASTA, OCTAVE/FAIR, Attack Trees + ATT&CK + CAPEC, VAST/Security Cards.  
   *If nothing fits, the tool suggests refining scope or combining methods (aka the buffet option).* 🍽️
2. **Level 2 (Q7–Q12):** add context refinements — compliance, safety, CI/CD, quant, TTPs, supply chain.  
   *Optional toppings. Like jalapeños, but for auditors.* 🌶️
3. **Level 3 (method‑specific):** only for Level‑1 picks; resolves bundles/variants (e.g., VAST vs Security Cards).  
   *Now we pick the exact sauce.* 🍝
4. **Scoring:** Level‑1 answers set the base; Level‑2 adds small tie‑break bonuses. Level‑3 doesn’t change scores — it **renames** picks to the specific variant.  
   *No secret ELO. Just honest math.*

---

## Installation 📥

```bash
git clone https://github.com/gmartijn/Threatmodelselector.git
cd Threatmodelselector
python tmhelper.py --help
```
> If `python` opens a text editor on your machine… we have questions. And a lot of empathy.

---

## Usage 🖱️

### Interactive
```bash
python tmhelper.py
```

### Non‑interactive (flags)
```bash
python tmhelper.py   --q1 yes --q2 no --q3 yes --q4 yes --q5 no --q6 yes   --q7 yes --q9 yes --q10 yes --q11 yes --q12 no   --l3_octavefair_quant yes --l3_vastcards_scale yes
```
*For bash completion, just hit ↑ until destiny appears.*

### Only the TL;DR
```bash
python tmhelper.py --only-condensed
```
*Great for steering committees and attention spans.*

### Output formats
```bash
# Markdown (great for PRs/wikis)
python tmhelper.py --format markdown

# JSON (machine‑readable)
python tmhelper.py --format json
```
*Text is the default, because tradition.*

### Bring your own answers (JSON/YAML)
```bash
python tmhelper.py --answers answers.json --format json
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
*Now your CI can have opinions, too.*

### Skip prompts (defaults any unanswered to "no")
```bash
python tmhelper.py --no-prompt
```
*For when your pipeline moves faster than your architecture review.*

---

## Level‑3 cheat sheet 🧠

- **OCTAVE or FAIR**
  - `l3_octavefair_quant`: need financial quant? → **FAIR** (bring charts)
  - `l3_octavefair_orgwide`: org‑wide qualitative posture? → **OCTAVE** (bring workshops)
- **VAST or Security Cards**
  - `l3_vastcards_scale`: many teams / pipelines? → **VAST** (DevSecOps catnip)
  - `l3_vastcards_ideation`: creative workshop ideation? → **Security Cards** (post‑its sold separately)
- **STRIDE**
  - `l3_stride_dfd`: modeling DFDs/trust boundaries? → **STRIDE‑per‑DFD** (draw boxes, save lives)
  - `l3_stride_element`: service/component inventory? → **STRIDE‑per‑Element** (Kubernetes clusters *not* included)
- **PASTA**
  - `l3_pasta_full`: full 7‑stage traceability? → **PASTA (full)** (fine dining)
  - `l3_pasta_light`: time‑boxed scenario variant? → **PASTA (light)** (fast casual)
- **Attack Trees + MITRE ATT&CK + CAPEC**
  - `l3_amc_detection`: detection/blue‑team first? → **ATT&CK‑led mapping** (SOC‑approved)
  - `l3_amc_design`: architects/abuse‑case focus? → **Attack‑Tree‑led** (whiteboard optional)
  - `l3_amc_catalog`: reusable pattern catalogs? → **CAPEC‑led cataloging** (collect them all™)
- **LINDDUN**
  - `l3_linddun_dpia`: need DPIA/compliance artifact? → **LINDDUN (DPIA‑oriented)** (legal loves this one weird trick)
  - `l3_linddun_engineering`: privacy engineering decisions? → **LINDDUN (engineering‑oriented)** (less paperwork, more patterns)

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
> `preference_scores` use the original Level‑1 labels for transparency. This is not a bug; it’s an *audit trail*. 🕵️‍♀️

---

## Troubleshooting 🧯

- **“python: command not found”** → try `python3`. If *that* fails, we respect your life choices and suggest a package manager.
- **“unknown argument --json”** → the new flag is `--format json`.
- **“why is my top pick the fallback?”** → you answered “no” to all L1 questions. Bold move. Try combining methods or revisiting scope.

---

## FAQ ❓💡

**What if I answer everything with “no”?**  
You’ve unlocked *Procrastinate‑Driven Development™*. The tool suggests revisiting scope or combining methods until something fits. Also: hydrate.

**What’s the “condensed recommendation”?**  
The TL;DR: a **Top pick**, an **also consider** list, and refinements to sprinkle on top. 🌶️ Perfect for slides you present at 16:55 on a Friday.

**Can I add my own frameworks or change weights?**  
Yes. Extend `DETAILS`, `L3_BLOCKS`, and `resolve_l3()`. Weighting knobs are on the roadmap — right next to “make coffee.” ☕️ PRs welcome.

**Does this replace human threat modeling?**  
No. It replaces **arguments** about which method to start with. Humans still required for diagrams, context, and snacks.

---

## License 📜🚀

Released under the **Infinite Improbability License**. 🌌  
Do whatever you like — if it goes wrong, blame the Vogons. 👽📚  
If it goes *right*, please pretend it was very difficult.
