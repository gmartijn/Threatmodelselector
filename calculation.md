# Threat Model Preference Scoring -- Calculation Model

This document explains the scoring process used to determine the **Top
Pick** among threat modeling methods, along with supporting
recommendations.

------------------------------------------------------------------------

## 1. Base Score Assignment

Each **Level-1 "yes" answer** contributes a **base score**:

$$
Score(M) = Score(M) + B
$$

Where:\
- $M$ = method recommended by the question\
- $B = 3$ (base score for each "yes")

------------------------------------------------------------------------

## 2. Refinement Bonus (Level-2 Questions)

Some Level-2 "yes" answers **boost specific methods**.\
Each bonus is worth:

$$
Score(M) = Score(M) + \beta
$$

Where:\
- $\beta = 1$ (bonus per relevant refinement)

### Bonus mapping:

-   **Q7 (Compliance)** → +1 to *LINDDUN*, +1 to *OCTAVE or FAIR*\
-   **Q8 (Safety-critical)** → *adds STPA-Sec* (refinement, no score
    impact to L1)\
-   **Q9 (CI/CD automation)** → +1 to *STRIDE*, +1 to *VAST or Security
    Cards*\
-   **Q10 (Quantitative risk)** → +1 to *PASTA*, +1 to *OCTAVE or FAIR*\
-   **Q11 (TTP mapping)** → +1 to *PASTA*, +1 to *Attack Trees + MITRE
    ATT&CK + CAPEC*\
-   **Q12 (Supply chain)** → *adds Supply-Chain Modeling* (refinement,
    no score impact to L1)

------------------------------------------------------------------------

## 3. Fallback Rule

If **no Level-1 questions** are answered "yes":

$$
Recommendation = \{ Reconsider\ scope\ /\ combine\ methods \}
$$

This ensures the tool never returns an empty recommendation set.

------------------------------------------------------------------------

## 4. Top Pick Selection

The **Top Pick** is chosen as:

$$
TopPick = \arg\max_{M \in L1} Score(M)
$$

Where ties are broken by **first occurrence in question order** (Q1 →
Q6).

------------------------------------------------------------------------

## 5. Also Consider

All other methods with positive scores are listed in **descending
order**:

$$
AlsoConsider = \{ M \in L1 \setminus \{TopPick\} \;|\; Score(M) > 0 \}
$$

------------------------------------------------------------------------

## 6. Output Structure

Final results include: - **Top Pick**: The method with the highest
score.\
- **Also Consider**: Other methods with nonzero scores.\
- **Refinements**: Extra methods/considerations from Level-2 answers.\
- **Preference Scores**: Score values for transparency.
