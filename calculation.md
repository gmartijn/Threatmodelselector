# Threat Model Preference Scoring -- Example Report

## Inputs

-   **Q1 = yes** → *System design focus*\
-   **Q9 = yes** → *CI/CD automation*\
-   **Q10 = yes** → *Quantitative risk appetite*\
-   All other questions = no

------------------------------------------------------------------------

## Step 1. Base Scores

Each **Level-1 "yes"** adds a base score of:

\[ B = 3 \]

-   Q1 = yes → STRIDE = 3

\[ `\text{Score(STRIDE)}`{=tex} = 3 \]

------------------------------------------------------------------------

## Step 2. Refinement Bonuses

Each **Level-2 "yes"** adds a bonus of:

\[ `\beta `{=tex}= 1 \]

-   Q9 = yes → STRIDE +1\
-   Q10 = yes → (would boost PASTA or OCTAVE/FAIR if selected, but they
    are not)

\[ `\text{Score(STRIDE)}`{=tex} = 3 + 1 = 4 \]

------------------------------------------------------------------------

## Step 3. Fallback Rule

Not needed, since STRIDE is selected.

------------------------------------------------------------------------

## Step 4. Top Pick Selection

\[ `\text{Top Pick}`{=tex} = `\arg`{=tex}`\max`{=tex}\_{M}
`\text{Score}`{=tex}(M) \]

-   STRIDE = 4\
-   Others = 0

\[ `\text{Top Pick}`{=tex} = `\text{STRIDE}`{=tex} \]

------------------------------------------------------------------------

## Step 5. Also Consider

\[ `\text{Also Consider}`{=tex} = `\varnothing`{=tex} \]

------------------------------------------------------------------------

## Step 6. Final Recommendation

**Detailed Methods:** - **STRIDE**: Use for system/DFD-centric design
reviews to enumerate Spoofing, Tampering, Repudiation, Info Disclosure,
DoS, EoP.\
- **Refinement -- CI/CD-Integrated Threat Modeling**: Automate checks in
pipelines; keep models living with architecture-as-code/microservices.

**Condensed Recommendation:** - **Top Pick:** STRIDE (score = 4)\
- **Also Consider:** *none*\
- **Refinements:** CI/CD-Integrated Threat Modeling

------------------------------------------------------------------------

✅ With these inputs, the tool strongly favors **STRIDE**, enhanced with
**CI/CD integration** to fit DevSecOps workflows.
