# Threat Model Selector 3000™ 🛡️✨

> *"Because choosing the wrong threat model is only slightly less\
> embarrassing than forgetting your SBOM at a supply-chain party."* 📦🥳

------------------------------------------------------------------------

## What is this? 🤔

This is a Python script that asks you up to **12 questions** --- six
core ones and six bonus ones --- about your system, your risks, and your
deepest compliance nightmares:

-   "Are you focusing mainly on system design & technical threats?"
    🖥️🔧\
-   "Is privacy and personal data compliance a main concern?" 🔒🧑‍⚖️\
-   "Do you ever shout 'PASTA!' and then realize you were just hungry?"
    🍝😱\
-   "Do you need regulator-ready artifacts?" 📑🧐\
-   "Is your system safety-critical (like planes, cars, or your
    toaster)?" ✈️🚗🍞\
-   "Do you want to drag threat modeling into your CI/CD pipeline?" 🤖🔄

Based on your answers (restricted to **yes** or **no** because nuance is
for philosophers 🧘‍♂️), the script recommends one or more **threat
modeling methodologies**.

It's like Tinder, but for security frameworks. 💘🔐

------------------------------------------------------------------------

## How it works ⚙️

1.  You run the script. ▶️\
2.  It interrogates you like a sarcastic security auditor. 🕵️‍♀️😏\
3.  You reply with `yes` or `no` (or their rebellious cousins
    `y/n/true/false/1/0`).\
4.  Out comes your destiny:
    -   **STRIDE** if you love tidy diagrams and enumerating threats.
        📝\
    -   **LINDDUN** if GDPR haunts your dreams. 👻📜\
    -   **PASTA** if you enjoy attacker scenarios *and* carbs. 🍝👨‍🍳\
    -   **OCTAVE/FAIR** if you think in spreadsheets and dollar signs.
        📈💰\
    -   **Attack Trees** if you plot evil flows on napkins. 🌳🖊️\
    -   **VAST** if you want to scale security workshops across Agile
        chaos. 🌀🐇\
    -   **Fallback combo platter** if nothing fits: *"just mix and
        hope"*. 🤷‍♂️✨\
5.  Bonus answers refine the output: want quantification? supply chain
    coverage? CI/CD integration? We've got add-ons for that. 🎁

------------------------------------------------------------------------

## Features ✨

-   **Interactive mode** (like a choose-your-own-adventure book, but
    scarier).\
-   **Non-interactive flags** (for introverts and robots 🤖).\
-   **JSON output** (because destiny should be machine-parsable 📦).\
-   **Condensed recommendation** with a **Top Pick** and scoring
    breakdown 🏆.\
-   **Preference scoring model** documented in
    [calculation.md](calculation.md). 🧮

------------------------------------------------------------------------

## Installation 📥

``` bash
git clone https://github.com/gmartijn/Threatmodelselector.git
cd Threatmodelselector
pip install absolutely-nothing
```

You already have Python. 🐍\
If not, your problems are bigger than this script. 🤨

------------------------------------------------------------------------

## Usage 🖱️

**Interactive:**

``` bash
python tmhelper.py
```

**Non-interactive** (for robots 🤖, CI/CD 🛠️, and people who hate small
talk 🙈):

``` bash
python tmhelper.py --q1 yes --q2 no --q3 yes --q4 no --q5 no --q6 yes --q9 yes
```

**JSON output:**

``` bash
python tmhelper.py --json
```

**Skip prompts (default unanswered to 'no'):**

``` bash
python tmhelper.py --no-prompt
```

------------------------------------------------------------------------

## Example Output 📊

Here's what you might see if you run the script interactively and answer
`q1=yes`, `q9=yes`, `q10=yes`:

``` text
=== Full Recommendation ===
- STRIDE: Use for system/DFD-centric design reviews to enumerate Spoofing, Tampering, Repudiation, Info Disclosure, DoS, EoP.
- CI/CD-Integrated Threat Modeling (e.g., VAST, tool-supported STRIDE): Automate checks in pipelines; keep models living with architecture-as-code/microservices.

Rationale:
* Q1: If yes, STRIDE maps cleanly to data-flow diagrams and design reviews.
* Q9: If yes, favor approaches and tooling that work well in DevSecOps pipelines.
* Q10: If yes, include FAIR-style quantitative analysis.

Answers:
  Q1: yes
  Q2: no
  Q3: no
  Q4: no
  Q5: no
  Q6: no
  Q7: no
  Q8: no
  Q9: yes
  Q10: yes
  Q11: no
  Q12: no

=== Condensed Recommendation ===
Top pick: STRIDE
Also consider: none
Refinements: CI/CD-Integrated Threat Modeling (e.g., VAST, tool-supported STRIDE)
Scores: STRIDE=4
```

------------------------------------------------------------------------

## Frequently Asked Questions ❓💡

**Q: What if I answer all questions with "no"?**\
A: Congratulations 🎉. You've just invented *Procrastinate-Driven
Development™*. 🛋️⏳

**Q: What's this "condensed recommendation"?**\
A: It's the TL;DR of threat modeling. You get a **Top Pick** (most
preferred method), an *"also consider"* list, and refinements.
Basically: "Just do this one, but maybe spice it up with these extras."
🌶️

**Q: Can I add my own exotic frameworks?**\
A: Yes 🙌. Especially if it has a ridiculous acronym like **CATS**
(*Cyber Adversary Tree Simulation*). 🐱🌳

**Q: Why does this README sound unhinged?**\
A: Because security is serious 🔐, but documentation doesn't have to be
😂.

------------------------------------------------------------------------

## License 📜🚀

This software is released under the **Infinite Improbability License**.
🌌\
Basically: do whatever you like, but if it goes wrong, blame the Vogons.
👽📚
