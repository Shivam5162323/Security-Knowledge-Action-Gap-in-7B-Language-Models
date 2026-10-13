# Analysis plan

**Status (2026-10-09).** This plan was not deposited in a registry or in a
timestamped public commit before the data were collected. The manuscript therefore
does not describe the analysis as pre-specified or pre-registered, and words such as
"pre-specified", "confirmatory" and "fixed before" in sections 1–8 record what the
document was meant to be, not something a reader can verify. Sections 1–8 are left
as they were written; section 9 lists what was done differently and section 10 what
was added after the final analysis.

The run manifest stores hashes of the stimuli, the rules and the sampling settings
(`python -m skgap fingerprint`), and the pipeline refuses to continue a run whose
design has changed.

## 1. Questions

- **RQ1** What do ≤7B models know about each weakness class?
- **RQ2** How often do they introduce it when asked for working code with no security cue?
- **RQ3** Is the second predicted by the first, and how much vulnerable code remains where knowledge is demonstrably present?
- **RQ4** Do a generic reminder and retrieved security notes change the outcome, beyond what security wording alone does, and at what cost to working code?

## 2. Design

11 models (7 of 2–4B parameters, 4 of ~7B; Q4_K_M) × 56 tasks (8 in each of
7 CWE classes) × 6 conditions × 5 samples. Sample 0 is greedy; samples 1–4 use
temperature 0.8, top-p 0.9, seeds 1–4. Knowledge probes use greedy decoding.
Reasoning is switched off for every model that offers it. Models, tasks, conditions
and constants are in `skgap/config.py` and `skgap/stimuli/`.

Model selection rule, fixed before any model was queried: the current release of
each widely pulled family in the Ollama library that ships a size labelled 7b or
smaller (library checked 2026-10-09).

No human rates anything. Primary measures are executable tests and fixed rules. A
language model, Claude Opus 5.5 (`claude-opus-5-5`), is used as a blind scorer for
two secondary purposes only (section 5).

## 3. Measures

| Symbol | Definition |
|---|---|
| vulnerable | The attack-test verdict if the task's attack test separated the task's two reference solutions in the run environment and returned a verdict for this answer; otherwise the Semgrep verdict. No code: not vulnerable, not functional. |
| functional | The answer passes the task's functional test. |
| secure-pass | functional and not vulnerable. |
| IR | Share of vulnerable answers (introduction rate). |
| K_mcq | Multiple-choice accuracy per (model, class), chance-corrected: (acc − 0.25) / 0.75. |
| K_det | Recognition per (model, class): TPR on insecure references + TNR on secure references − 1. |
| **K** | mean(K_mcq, K_det). Primary knowledge score. |
| **recognises** | Per (model, task): the insecure reference is called vulnerable and the secure one safe. |
| repair | Per (model, task): the model's rewrite of the insecure reference is functional and not vulnerable. Procedural; not part of K. |
| K_explain, K_explain_scorer | Free-text explanation per (model, class), scored by a fixed concept rubric and, blind, by the scorer model on a 0–2 scale rescaled to 0–1. Secondary; not part of K. |

Units. Generations are nested in (model, task) cells; cells are crossed by model
and by task; tasks are nested in classes. No analysis treats generations, or
cells, as independent observations without accounting for this.

## 4. Hypotheses and tests

All tests two-sided at α = 0.05 unless stated. Bootstrap: 2,000 replicates,
resampling models and tasks independently (two-way cluster bootstrap), percentile
intervals. Permutation tests: 5,000 permutations or exact.

**H1 — residual gap.** In (model, task) cells where the model *recognises* the
weakness, the baseline introduction rate G exceeds δ = 0.05.
Test: one-sided; supported if the lower limit of the 90% bootstrap interval for G
exceeds δ. Reported alongside: G in cells that do not recognise; G in cells that
recognise *and* repair; G in (model, class) cells with K ≥ τ = 0.5.

**H2 — coupling.** Higher knowledge goes with a lower baseline introduction rate.
Two confirmatory tests, Holm-adjusted over the pair:

- H2a, class level: slope of IR on K over model × class cells with model and class fixed effects.
- H2b, task level: slope of IR on *recognises* over model × task cells with model-by-class and task fixed effects, i.e. comparing tasks within one model's handling of one class.

Inference: Freedman–Lane permutation of reduced-model residuals, on the t
statistic. The fixed effects remove the confound of a raw correlation
(classes that are both easy to explain and rarely introduced; models that are
generally stronger). Also reported, as description: Spearman's ρ over all cells
and over model means; ρ within each class; slopes for K_mcq, K_det and the two
explanation scores separately; a mixed-effects logistic regression
`vulnerable ~ K + (1|model) + (1|class) + (1|task)` on the generations, fitted in
Python (variational) and to be confirmed with lme4 (`glmm.R`).

H1 and H2 are not alternatives. A negative slope with G well above δ means
knowledge transfers in part and is not sufficient.

**Threshold sensitivity.** The comparison of high- and low-knowledge cells is
repeated for τ across the 10th–90th percentile of K (Table T11). τ = 0.5 is the
only pre-specified value; the sweep is descriptive.

**H3 — reminder.** (a) IR is lower under `reminder` than under `baseline`.
(b) Activation: the reduction is larger in cells that *recognise* the weakness
(slope of the per-cell difference on *recognises*, fixed effects as in H2b).
A reminder carries no information about the fix, so (b) is what "knowledge present
but not used" predicts.

**H4 — retrieval.** `rag_dense` and `rag_hybrid` lower IR and raise secure-pass
relative to (a) `baseline`, (b) `reminder`, (c) `ctx_irrelevant`. Contrast (c)
separates relevant content from security wording. `rag_oracle − baseline` is
reported as an upper bound.

**H5 — hybrid vs dense.** `rag_hybrid − rag_dense`.

For H3a, H4 and H5: the estimate is the mean over (model, task) cells of the
difference in rates, with a two-way bootstrap interval. The p-value is an exact
sign-flip test on the 11 per-model mean differences (the model is the unit),
Holm-adjusted across the nine contrasts within each outcome. Primary outcome:
vulnerable. Secure-pass and functional are reported for every contrast, so a
reduction bought with non-working code is visible.

## 5. Robustness (all pre-specified)

Key results are repeated with: Semgrep verdicts only; attack verdicts only; the
greedy sample only; sampled answers only; functional answers only; placeholder
credentials ("your_password") not counted as vulnerable (Table T18). Agreement
between the two detectors is in Table T3. Tier (≤4B vs ~7B) differences are tested
by exact permutation over models (Table T17); with 7 and 4 models there are 330
arrangements, so the smallest two-sided p-value is about 0.006.

Scorer audit. A random sample of 140 generated answers, ten per class and automatic
verdict, is judged by the scorer model for the task's weakness class. The scorer
sees the task and the code only; the rubric is `INSTRUCTIONS` in `skgap/audit.py`
and its hash is stored with the ratings. Reported: precision, recall and Cohen's
kappa of the automatic verdict against the scorer, overall and per class (Table
T20). The sample is stratified by automatic verdict, so precision is unbiased and
recall is not a population estimate. The automatic verdict stays the outcome
whatever the audit shows; disagreements are reported, not corrected.

## 6. Exclusions and missing data

No answer is excluded. Replies without code count as not vulnerable and not
functional and are counted in Table T1. Failed requests are retried up to three
times per session; any that remain missing are reported per model, and cell means
use the samples that exist. A model that cannot be run at all is dropped and the
drop reported. If a task's attack test does not validate in the run environment,
its answers use the Semgrep verdict (Table T2).

## 7. Sensitivity of the design

Computed with `python -m skgap power` and the simulation code in `skgap/stats.py`
before data collection.

*Correlations* (Fisher z, two-sided α = 0.05). With 10 pairs, |ρ| = 0.63 has 50%
power and 80% power needs |ρ| ≥ 0.79. With 20 pairs, 80% needs |ρ| ≥ 0.59. With
the 77 model × class cells of this design, 80% needs |ρ| ≥ 0.31, if cells were
independent, which they are not; hence the tests in section 4.

*H2a* (simulation: logistic model with random model, class, task and cell
effects with SDs 0.6, 0.8, 0.7, 0.4; baseline rate 0.35). False-positive rate
0.045. Power 0.57 for an odds ratio of 0.82 per SD of K, 0.96 for 0.70, ≈1 for 0.61.

*Condition contrasts* (sign-flip over 11 models at α = 0.01, approximating the
Holm threshold; simulation). Power for a true risk difference of 0.05 is 0.68 when
models differ little in their response (SD 0.04) and 0.19 when they differ a lot
(SD 0.08); for 0.08 it is 0.98 and 0.51; for 0.10 it is 1.00 and 0.75.

Consequences: the design can detect moderate coupling and condition effects of
eight to ten percentage points; it cannot rule out small ones. Non-significant
contrasts are reported with their intervals and not described as "no effect".

## 8. What would change the conclusions

- G near zero in recognising cells: there is no gap; knowledge suffices where present.
- No slope in H2a and H2b with G large: knowledge and behaviour are dissociated.
- Negative slope with G large: partial transfer (the pattern the earlier data hinted at).
- `rag_dense ≈ ctx_irrelevant`: any RAG benefit is priming by security wording.
- `rag_dense ≈ reminder`: retrieval adds nothing over a one-line instruction.
- Lower IR with lower functional rate and flat secure-pass: the intervention trades vulnerabilities for broken code.

## 9. Deviations

Written on 2026-10-09, after data collection and before the scorer audit and the
final analysis. Sections 1–8 are left as they were.

**Two models dropped; the design is 9 models, not 11.** The selection rule gave 11
models. Two are not in the study, under the rule in section 6:

- Gemma 4 E2B (`gemma4:e2b-it-q4_K_M`). Its model runner stopped producing output
  after about 280 generations, in two separate sessions on different machines, with
  no error in the server log. It could not be completed.
- DeepSeek-R1 7B (`deepseek-r1:7b-qwen-distill-q4_K_M`). Its run completed, but
  reasoning could not be switched off: the reasoning was returned in a separate
  field and used the whole output budget. All 203 multiple-choice, recognition and
  explanation answers and 678 of 1,680 generations were empty, and 1,285
  generations hit the 640-token limit. This was found from response lengths and
  empty-answer counts, before any analysis. Scoring it would have recorded a model
  with zero knowledge and few vulnerabilities, both produced by the token limit.

Neither model entered any analysis before or after the decision. The study has 6
models of 2–4B and 3 of ~7B, none from Google or DeepSeek, and no model was tested
with reasoning on.

**Sessions.** The nine models were generated in three Kaggle sessions (T4 x2 each)
from the same code bundle; prompts, retrieval results, detector validation and the
evaluator version are identical across them. Mistral 7B was generated in two of the
sessions; the copy used is from the session that completed first, and 150 of 336
of its temperature-0 answers were identical between the two, so greedy decoding
was not bit-reproducible under parallel batching.

What the smaller design changes in sections 4, 5 and 7:

- Sign-flip tests use 9 per-model differences. The smallest two-sided p-value is
  2/512 = 0.004.
- Tier comparison: 6 and 3 models give 84 arrangements, so the smallest two-sided
  p-value is 0.024.
- Correlations: 63 model × class cells; 80% power needs |ρ| ≥ 0.35 if cells were
  independent.
- H2a, same simulation with 9 models: false-positive rate 0.04; power 0.50 for an
  odds ratio of 0.82 per SD of K, 0.90 for 0.70, 0.99 for 0.61. In the metric of the
  test itself, the slope of the introduction rate on K, these effect sizes are falls of
  3.6, 6.1 and 8.7 percentage points per SD of K (the mean slope of the simulated data
  sets, printed by `python -m skgap power`), or slopes of −0.21, −0.36 and −0.50 per
  unit of K at the observed SD of 0.17. The manuscript states power in this metric.
- Condition contrasts, same simulation with 9 models (model SD 0.04 and 0.08): power
  0.44 and 0.10 for a true risk difference of 0.05, 0.89 and 0.31 for 0.08, 0.98 and
  0.52 for 0.10.

The design now detects condition effects of about ten percentage points reliably
only when models respond alike; the statement that small effects cannot be ruled
out applies with more force.

## 10. Additions after the final analysis

Written on 2026-10-09, after the final analysis.

**Mixed-effects model.** The model named in section 4,
`vulnerable ~ K + (1|model) + (1|class) + (1|task)`, treats the programs of a
model × class cell as independent given those three effects, although K has one
value per cell. Fitted exactly with lme4 it gives an odds ratio of 1.47 per SD of K
(Wald 95% interval 1.21 to 1.79), close to the variational fit in `report.md`, and
that interval is too narrow. The manuscript reports the model with two further
random intercepts, for the model × class and the model × task cells: odds ratio
1.24 (0.71 to 2.19), p = 0.45; for *recognises* 1.04 (0.48 to 2.22). Script and
output: `runs/<name>/analysis/glmm_exact.R`, `glmm_exact_output.txt`,
`tables/T21_mixed_model.csv`.

**Further descriptive tables** (`tools/manuscript/paper_extra.py`): the four
combinations of working and vulnerable by condition (T22), the change in all three
outcomes by model (T23), and the effect of retrieval split by whether a note of the
task's own class was retrieved (T24). The last is confounded with class.

**Scorer.** After the scorer model had rated the audit sample and the explanations,
the authors checked its ratings informally. This was not a second rating: no
agreement statistic was computed and no rating was changed.

Added on 2026-10-12; no result of sections 4 to 6 changed.

**Kappa of the audit.** The audit sample holds ten programs with each automatic
verdict per class, so its kappa (0.80) is that of a balanced sample and not of the
whole set of programs, in which 31% carry a vulnerable verdict. Weighting each of
the 14 strata by its size among the 15,117 programs with code gives an estimated
agreement of 0.93 and kappa of 0.84 (stratified bootstrap 95% interval 0.76 to
0.92). Computed by `tools/manuscript/paper_extra.py`.

**Irrelevant notes.** They are drawn from the 1,525 notes whose CWE identifier is
none of the 27 that make up the seven classes and their close relatives
(`family` in `skgap/stimuli/base.py`). Broad parent classes were not excluded:
CWE-20 and CWE-74 supplied 4 of the 168 notes drawn, and 3 of the 168 belong to an
ancestor or descendant of the task's own class in the CWE hierarchy (version 4.20,
Research Concepts view). Counted by the same script.

**Retrieval settings.** The NVD period, 1 January to 29 April 2024, is one query
window of the greatest length the NVD interface serves (120 days). The query is the
task text alone. The fusion weights (0.6 dense, 0.4 BM25), the constant 60, the
encoder and the number of notes were not tuned; the BM25 weight, the constant, the
encoder and the number of notes are those of the first version of the study.

**Figures.** The manuscript uses `figP_gap` and `figP_scatter`, which are fig3 and
fig4 without the title inside the figure. The axis of fig4 now reads “Knowledge K”
(K includes recognition), every panel carries its x-axis numbers, and the pipeline
figure no longer says that the whole knowledge battery is scored automatically:
the explanations also receive a score from the scorer model.

Added on 2026-10-13, after a further review; no result of sections 4 to 6 changed.

**Why programs did not pass the functional test.** Every non-functional program is
assigned to one reason from the error the evaluation stored (`failure_reason` in
`tools/manuscript/paper_extra.py`, Table T25): cut off at the output limit, does not
parse or compile, failed import, exception on ordinary input, wrong result, and a
group that lies in the test environment and not in the program. That group has 231
programs, 230 of them in the CWE-798 tasks: the stubs for the client libraries did
not resolve the import of a submodule under Python 3.13, the program waited for a
password to be typed, or it converted the placeholder value of an environment
variable to a number. The programs were not evaluated again and every outcome in
sections 4 to 6 still counts them as not functional. Table T26 repeats the contrasts
of the reminder and of dense retrieval without the truncated programs and without
this group. The classification and the exclusion were chosen after the results were
known.

**Human raters.** `python -m skgap sheets --human` writes a rating page per rater
for the sample the scorer judged, under the same rules (`skgap/audit_human.py`).
A rater may give all unrated items one rating in a single step and then change
single items; the ratings file marks those left unchanged. Agreement between the
raters, with the automatic verdict and with the scorer is reported as Table T27 once
the ratings exist. Like the scorer's, these ratings do not alter any outcome.

Added on 2026-10-14. A correction: three results of sections 4 to 6 change in the
third decimal, and no conclusion changes.

**Aliased fixed effects.** `stats.fe_slope` removed the fixed effects with a QR
factorisation of the dummy variables and dropped the columns whose diagonal entry
was zero. Where effects are aliased, as model-by-class and task effects are (a task
lies within one class), the columns that were kept did not span the whole design,
and the slope depended on rounding inside the factorisation, so it differed between
machines. The projection now uses an orthonormal basis from the singular value
decomposition and agrees with ordinary least squares
(`test_twoway_fe_with_aliased_effects_matches_least_squares`). What changed:

- H2b: slope −0.0076, was −0.0080; permutation p = 0.832, was 0.825. The interval,
  −0.128 to 0.121, is the same to three decimals.
- H3b: interaction −0.0002, was 0.0006; p = 0.995, was 0.989; interval −0.154 to
  0.134 as before.
- T18, slope on *recognises*: at most 0.0007 from the earlier value in any variant,
  p-values at most 0.016.

H2a and every other result are unchanged: their fixed effects are not aliased, and
both calculations give the same slope to 15 decimals. `report.md`, `results.json`,
T9 and T18 were written again; the release archived as version 1.0.1 holds the
earlier values.

**Ratings by two authors.** Two of the authors rated the 140 programs of the audit
sample on the pages described above, independently of each other and after the
analysis was complete. Table T27 gives the agreement. Kappa between the raters is
0.89 (95% interval 0.83 to 0.94). For the automatic verdict it is 0.79 (0.70 to
0.87) against rater A and 0.73 (0.63 to 0.81) against rater B; against the scorer it
is 0.80 (0.71 to 0.89), a row that T27 repeats from T20 with the interval computed
in the same way. For the scorer it is 0.96 against rater A and 0.90 against rater B.
Six of the eight programs on which the raters differ store a session or a cache with
pickle and read the file back: the automatic verdict, the scorer and rater A count
them as vulnerable, rater B does not. No outcome was changed.
