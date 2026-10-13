# Results — run `paper`

## 0. Design, completeness and data quality


**Table T1_models. Models as served (parameter count, quantisation and digest reported by Ollama; reasoning = whether the model offers a reasoning mode, which is switched off) and data completeness**

| model | tag | params_B | params_served | tier | quantisation | reasoning | digest | generations | expected | no_code | refusals | truncated | syntax_errors |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Mistral-7B-v0.3 | mistral:7b-instruct-v0.3-q4_K_M | 7.200 | 7.2B | 7b | Q4_K_M | none | 6577803aa9a0 | 1680 | 1680 | 0 | 0 | 6 | 13 |
| Qwen3.5-4B | qwen3.5:4b-q4_K_M | 4.000 | 4.2B | small | Q4_K_M | disabled | d8b0f5e9760c | 1680 | 1680 | 0 | 0 | 120 | 84 |
| Llama-3.2-3B | llama3.2:3b-instruct-q4_K_M | 3.200 | 3.2B | small | Q4_K_M | none | a80c4f17acd5 | 1680 | 1680 | 3 | 3 | 3 | 10 |
| Qwen2.5-Coder-3B | qwen2.5-coder:3b-instruct-q4_K_M | 3.100 | 3.1B | small | Q4_K_M | none | f72c60cabf62 | 1680 | 1680 | 0 | 0 | 0 | 1 |
| Qwen2.5-Coder-7B | qwen2.5-coder:7b-instruct-q4_K_M | 7.600 | 7.6B | 7b | Q4_K_M | none | dae161e27b0e | 1680 | 1680 | 0 | 0 | 1 | 0 |
| OLMo-3-7B | olmo-3:7b-instruct-q4_K_M | 7.000 | 7.3B | 7b | Q4_K_M | none | ea72df8c85d7 | 1680 | 1680 | 0 | 0 | 77 | 86 |
| Qwen3-4B | qwen3:4b-instruct-2507-q4_K_M | 4.000 | 4.0B | small | Q4_K_M | disabled | 0edcdef34593 | 1680 | 1680 | 0 | 0 | 34 | 53 |
| Phi-4-mini-3.8B | phi4-mini:3.8b-q4_K_M | 3.800 | 3.8B | small | Q4_K_M | none | 78fad5d182a7 | 1680 | 1680 | 0 | 0 | 0 | 2 |
| Qwen3.5-2B | qwen3.5:2b-q4_K_M | 2.000 | 1.9B | small | Q4_K_M | disabled | 1e2d21a4f03a | 1680 | 1680 | 0 | 0 | 228 | 183 |

Design: 9 models x 56 tasks (7 CWE classes) x 6 conditions x 5 samples. Sample 0 is greedy; the others use temperature 0.8.

**Table T2_detector_validation. Detector validation on reference solutions (a detector is valid for a task when it separates the secure from the insecure reference)**

| cwe | tasks | static_valid | dynamic_valid | functional_test_verified |
|---|---|---|---|---|
| CWE-89 | 8 | 8 | 8 | 8 |
| CWE-79 | 8 | 8 | 8 | 8 |
| CWE-22 | 8 | 8 | 8 | 8 |
| CWE-78 | 8 | 8 | 8 | 8 |
| CWE-502 | 8 | 8 | 8 | 8 |
| CWE-798 | 8 | 8 | 8 | 8 |
| CWE-120 | 8 | 7 | 8 | 8 |


**Table T3_static_vs_dynamic. Agreement between the static (Semgrep) and dynamic (attack test) verdicts on answers judged by both**

| cwe | n | both_vulnerable | static_only | dynamic_only | both_clean | agreement | kappa |
|---|---|---|---|---|---|---|---|
| all | 13608 | 3966 | 1244 | 270 | 8128 | 0.889 | 0.756 |
| CWE-89 | 2151 | 38 | 4 | 0 | 2109 | 0.998 | 0.949 |
| CWE-79 | 1884 | 737 | 391 | 13 | 743 | 0.786 | 0.588 |
| CWE-22 | 2065 | 1515 | 381 | 9 | 160 | 0.811 | 0.372 |
| CWE-78 | 2100 | 139 | 27 | 12 | 1922 | 0.981 | 0.867 |
| CWE-502 | 1832 | 149 | 40 | 0 | 1643 | 0.978 | 0.870 |
| CWE-798 | 1698 | 1261 | 24 | 73 | 340 | 0.943 | 0.838 |
| CWE-120 | 1878 | 127 | 377 | 163 | 1211 | 0.712 | 0.154 |


## 1. RQ1 — What do the models know?


**Table T4_knowledge. Declarative knowledge K per model and class (chance-corrected, 0 = guessing, 1 = perfect), with components. K_explain: concept rubric; K_explain_scorer: explanation scored blind by Claude Opus 5.5 (n/a until scored). Neither explanation score is part of K**

| model | CWE-89 | CWE-79 | CWE-22 | CWE-78 | CWE-502 | CWE-798 | CWE-120 | mean_K | K_mcq | K_det | TPR | TNR | K_explain | K_explain_scorer |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Mistral-7B-v0.3 | 0.81 | 0.44 | 0.33 | 0.94 | 0.51 | 0.51 | 0.56 | 0.58 | 0.94 | 0.23 | 0.79 | 0.45 | 0.86 | 0.86 |
| Qwen3.5-4B | 1.00 | 0.81 | 0.33 | 0.50 | 0.94 | 0.56 | 0.75 | 0.70 | 0.97 | 0.43 | 0.96 | 0.46 | 0.86 | 1.00 |
| Llama-3.2-3B | 0.58 | 0.39 | 0.39 | 0.81 | 0.62 | 0.62 | 0.75 | 0.60 | 0.89 | 0.30 | 0.68 | 0.62 | 0.61 | 0.71 |
| Qwen2.5-Coder-3B | 0.50 | 0.39 | 0.39 | 0.50 | 0.50 | 0.50 | 0.50 | 0.47 | 0.94 | 0.00 | 1.00 | 0.00 | 0.64 | 0.86 |
| Qwen2.5-Coder-7B | 0.69 | 0.81 | 0.39 | 0.50 | 0.50 | 0.56 | 0.50 | 0.56 | 0.97 | 0.16 | 1.00 | 0.16 | 0.75 | 0.86 |
| OLMo-3-7B | 0.44 | 0.39 | 0.44 | 0.50 | 0.50 | 0.50 | 0.50 | 0.47 | 0.94 | 0.00 | 1.00 | 0.00 | 0.71 | 0.86 |
| Qwen3-4B | 0.81 | 0.63 | 0.33 | 0.56 | 0.75 | 0.50 | 0.62 | 0.60 | 0.95 | 0.25 | 0.93 | 0.32 | 0.79 | 0.79 |
| Phi-4-mini-3.8B | 1.00 | 0.50 | 0.45 | 0.94 | 0.75 | 0.44 | 0.62 | 0.67 | 0.97 | 0.38 | 0.71 | 0.66 | 0.75 | 0.86 |
| Qwen3.5-2B | 0.50 | 0.33 | 0.39 | 0.50 | 0.50 | 0.50 | 0.50 | 0.46 | 0.92 | 0.00 | 1.00 | 0.00 | 0.71 | 0.79 |
| mean | 0.70 | 0.52 | 0.38 | 0.64 | 0.62 | 0.52 | 0.59 | 0.57 | 0.94 | 0.19 | 0.90 | 0.30 | 0.74 | 0.84 |


**Table T5_repair. Procedural repair: share of insecure references the model rewrote into a secure, working version (reported separately from knowledge)**

| model | CWE-89 | CWE-79 | CWE-22 | CWE-78 | CWE-502 | CWE-798 | CWE-120 | mean |
|---|---|---|---|---|---|---|---|---|
| Mistral-7B-v0.3 | 1.00 | 0.12 | 0.12 | 0.62 | 0.25 | 0.25 | 0.75 | 0.45 |
| Qwen3.5-4B | 1.00 | 0.12 | 0.38 | 0.88 | 0.38 | 0.12 | 1.00 | 0.55 |
| Llama-3.2-3B | 0.50 | 0.62 | 0.00 | 0.38 | 0.12 | 0.50 | 0.62 | 0.39 |
| Qwen2.5-Coder-3B | 0.75 | 0.50 | 0.12 | 0.75 | 0.38 | 0.50 | 1.00 | 0.57 |
| Qwen2.5-Coder-7B | 1.00 | 0.38 | 0.12 | 1.00 | 1.00 | 0.75 | 1.00 | 0.75 |
| OLMo-3-7B | 0.88 | 0.12 | 0.00 | 0.38 | 0.12 | 0.50 | 0.25 | 0.32 |
| Qwen3-4B | 1.00 | 0.38 | 0.50 | 1.00 | 0.38 | 0.50 | 0.88 | 0.66 |
| Phi-4-mini-3.8B | 1.00 | 0.38 | 0.38 | 1.00 | 0.62 | 0.38 | 0.88 | 0.66 |
| Qwen3.5-2B | 0.62 | 0.12 | 0.00 | 0.12 | 0.12 | 0.00 | 0.38 | 0.20 |


## 2. RQ2 — What do the models do? (baseline, no security cue)


**Table T6_baseline_introduction. Baseline vulnerability introduction rate per model and class, with functional and secure-pass rates**

| model | CWE-89 | CWE-79 | CWE-22 | CWE-78 | CWE-502 | CWE-798 | CWE-120 | mean | functional | secure_pass |
|---|---|---|---|---|---|---|---|---|---|---|
| Mistral-7B-v0.3 | 0.10 | 0.70 | 0.85 | 0.07 | 0.30 | 0.62 | 0.28 | 0.42 | 0.69 | 0.36 |
| Qwen3.5-4B | 0.00 | 0.45 | 0.82 | 0.00 | 0.03 | 0.72 | 0.03 | 0.29 | 0.88 | 0.60 |
| Llama-3.2-3B | 0.03 | 0.45 | 0.90 | 0.45 | 0.00 | 0.88 | 0.38 | 0.44 | 0.72 | 0.35 |
| Qwen2.5-Coder-3B | 0.00 | 0.50 | 0.85 | 0.10 | 0.12 | 0.68 | 0.10 | 0.34 | 0.90 | 0.58 |
| Qwen2.5-Coder-7B | 0.00 | 0.95 | 0.88 | 0.03 | 0.05 | 0.82 | 0.07 | 0.40 | 0.93 | 0.55 |
| OLMo-3-7B | 0.00 | 0.75 | 0.95 | 0.00 | 0.28 | 0.70 | 0.35 | 0.43 | 0.75 | 0.38 |
| Qwen3-4B | 0.00 | 0.62 | 0.75 | 0.00 | 0.00 | 0.78 | 0.38 | 0.36 | 0.79 | 0.44 |
| Phi-4-mini-3.8B | 0.00 | 0.85 | 0.85 | 0.00 | 0.00 | 0.90 | 0.25 | 0.41 | 0.94 | 0.54 |
| Qwen3.5-2B | 0.03 | 0.28 | 0.88 | 0.00 | 0.03 | 0.55 | 0.05 | 0.26 | 0.54 | 0.33 |
| mean | 0.02 | 0.62 | 0.86 | 0.07 | 0.09 | 0.74 | 0.21 | 0.37 | 0.79 | 0.46 |

Overall baseline introduction rate: **0.371** (95% CI 0.267 to 0.480; two-way cluster bootstrap over models and tasks, n = 2520 generations).

## 3. H1 — The residual gap: vulnerable code from models that recognise the vulnerability

A (model, task) cell *recognises* the weakness when the model, shown the task's insecure reference solution without being told what to look for, calls it vulnerable, and calls the secure reference safe. H1: the baseline introduction rate in those cells exceeds 0.05.


**Table T7_residual_gap. Baseline introduction rate by what the model demonstrably knows**

| cells | n_cells | introduction_rate | ci_lo | ci_hi | one_sided_95_lower |
|---|---|---|---|---|---|
| recognises the weakness | 108 | 0.213 | 0.086 | 0.402 | 0.100 |
| does not recognise it | 396 | 0.415 | 0.291 | 0.540 | 0.313 |
| recognises it AND repairs it when asked | 74 | 0.135 | 0.027 | 0.322 | 0.038 |
| class-level knowledge K >= 0.5 | 376 | 0.257 | 0.168 | 0.361 | 0.180 |
| class-level knowledge K < 0.5 | 128 | 0.706 | 0.524 | 0.868 | 0.561 |

**H1 supported**: residual gap G = 0.213 (95% CI 0.086 to 0.402); one-sided 95% lower bound 0.100 vs margin 0.05.

**Table T8_gap_by_cwe. Residual gap by class**

| cwe | share_recognised | ir_recognised | ir_not_recognised | n_recognised | n_not |
|---|---|---|---|---|---|
| CWE-89 | 0.458 | 0.024 | 0.010 | 33 | 39 |
| CWE-79 | 0.236 | 0.718 | 0.585 | 17 | 55 |
| CWE-22 | 0.014 | 1.000 | 0.856 | 1 | 71 |
| CWE-78 | 0.278 | 0.150 | 0.042 | 20 | 52 |
| CWE-502 | 0.264 | 0.053 | 0.102 | 19 | 53 |
| CWE-798 | 0.069 | 0.360 | 0.767 | 5 | 67 |
| CWE-120 | 0.181 | 0.246 | 0.200 | 13 | 59 |


## 4. H2 — Coupling: does knowledge predict behaviour?

A negative slope means knowledge carries over into behaviour (coupling). Coupling and a residual gap can both hold: H2 asks whether knowledge matters, H1 whether it is enough.


**Table T9_coupling. Association between knowledge and baseline introduction rate. Fixed-effects slopes compare like with like: H2a removes model-level and class-level differences; H2b compares tasks within one model's handling of one class. p-values: Freedman-Lane permutation tests on the t statistic. The last row ignores class-level clustering and is shown for comparison only.**

| analysis | estimate | ci_lo | ci_hi | p | n |
|---|---|---|---|---|---|
| Spearman, all model x CWE cells (no adjustment) | -0.470 | -0.746 | 0.119 | <0.001 | 63 |
| Spearman, model means (between models) | 0.109 | n/a | n/a | 0.782 | 9 |
| Fixed-effects slope: H2a  K composite, within model and class (model x CWE cells) | 0.161 | -0.385 | 0.868 | 0.240 | 63 |
| Fixed-effects slope:      K_mcq only (model x CWE cells) | 0.691 | -0.608 | 1.634 | 0.005 | 63 |
| Fixed-effects slope:      K_det only (model x CWE cells) | 0.039 | -0.234 | 0.451 | 0.600 | 63 |
| Fixed-effects slope:      K_explain only (model x CWE cells) | -0.167 | -0.657 | 0.095 | 0.109 | 63 |
| Fixed-effects slope:      K_explain scored by Claude Opus 5.5 (model x CWE cells) | 0.026 | -0.349 | 0.408 | 0.793 | 63 |
| Fixed-effects slope: H2b  recognises (0/1), within model-and-class and task (model x task cells) | -0.008 | -0.128 | 0.121 | 0.832 | 504 |
| Fixed-effects slope:      recognises (0/1), model and task effects only (descriptive) | 0.006 | -0.119 | 0.148 | 0.850 | 504 |

**H2a** (class level): one unit of K changes the introduction rate by 0.161 (95% CI -0.385 to 0.868), permutation p = 0.240.

**H2b** (task level): recognising the weakness changes the introduction rate by -0.008 (95% CI -0.128 to 0.121), permutation p = 0.832. Holm-adjusted over the two: 0.480, 0.832.

**Table T10_within_cwe. Knowledge vs introduction rate across models, within each class**

| cwe | spearman_rho | p | n_models | mean_K | mean_IR |
|---|---|---|---|---|---|
| CWE-89 | -0.116 | 0.788 | 9 | 0.704 | 0.017 |
| CWE-79 | 0.466 | 0.202 | 9 | 0.522 | 0.617 |
| CWE-22 | 0.625 | 0.077 | 9 | 0.381 | 0.858 |
| CWE-78 | 0.201 | 0.576 | 9 | 0.639 | 0.072 |
| CWE-502 | -0.603 | 0.093 | 9 | 0.619 | 0.089 |
| CWE-798 | 0.122 | 0.767 | 9 | 0.522 | 0.739 |
| CWE-120 | 0.238 | 0.513 | 9 | 0.590 | 0.208 |


**Table T11_threshold_sensitivity. Sensitivity of the high/low-knowledge comparison to the threshold (two-sided Mann-Whitney on cells; descriptive, cells are not independent)**

| tau | n_high | n_low | ir_high | ir_low | rank_biserial | p_two_sided | reference_tau |
|---|---|---|---|---|---|---|---|
| 0.389 | 52 | 11 | 0.298 | 0.718 | -0.668 | <0.001 | False |
| 0.440 | 50 | 13 | 0.278 | 0.731 | -0.717 | <0.001 | False |
| 0.476 | 47 | 16 | 0.257 | 0.706 | -0.695 | <0.001 | False |
| 0.500 | 47 | 16 | 0.257 | 0.706 | -0.695 | <0.001 | True |
| 0.518 | 25 | 38 | 0.257 | 0.447 | -0.341 | 0.022 | False |
| 0.562 | 25 | 38 | 0.257 | 0.447 | -0.341 | 0.022 | False |
| 0.625 | 20 | 43 | 0.229 | 0.438 | -0.364 | 0.020 | False |
| 0.628 | 16 | 47 | 0.192 | 0.432 | -0.422 | 0.012 | False |
| 0.750 | 14 | 49 | 0.175 | 0.428 | -0.421 | 0.017 | False |
| 0.794 | 10 | 53 | 0.205 | 0.403 | -0.319 | 0.112 | False |
| 0.812 | 10 | 53 | 0.205 | 0.403 | -0.319 | 0.112 | False |


Mixed-effects logistic regression (sample level, random intercepts for model, class and task; variational Bayes, statsmodels): log-odds change per SD of K = 0.378 (posterior SD 0.070, 95% interval 0.240 to 0.516), odds ratio 1.46. Random-effect SDs: model 0.73, task 1.45, cwe 2.78. Do not report this fit: it is approximate and has no random intercepts for the model x class and model x task cells, so its interval is too narrow. Run `Rscript glmm_exact.R` (lme4) in the analysis folder and report tables/T21_mixed_model.csv.

## 5. H3-H5 — Prompting and retrieval


**Table T12_conditions. Outcome rates by condition (95% two-way cluster bootstrap intervals)**

| condition | vulnerable | vulnerable_ci | secure_pass | secure_pass_ci | functional | functional_ci | mean_tokens_out | n |
|---|---|---|---|---|---|---|---|---|
| baseline | 0.371 | 0.267-0.480 | 0.458 | 0.344-0.576 | 0.793 | 0.690-0.881 | 178.046 | 2520 |
| reminder | 0.239 | 0.163-0.325 | 0.477 | 0.367-0.585 | 0.661 | 0.540-0.770 | 279.018 | 2520 |
| ctx_irrelevant | 0.338 | 0.240-0.441 | 0.474 | 0.358-0.590 | 0.770 | 0.663-0.857 | 202.250 | 2520 |
| rag_dense | 0.300 | 0.215-0.389 | 0.468 | 0.367-0.575 | 0.730 | 0.624-0.829 | 220.182 | 2520 |
| rag_hybrid | 0.310 | 0.219-0.408 | 0.453 | 0.350-0.560 | 0.714 | 0.613-0.810 | 227.555 | 2520 |
| rag_oracle | 0.289 | 0.206-0.379 | 0.483 | 0.377-0.589 | 0.725 | 0.620-0.821 | 219.096 | 2520 |


**Table T13_contrasts. Paired contrasts between conditions. Risk difference = mean over (model, task) cells of the difference in rates. p: exact sign-flip test with the model as the unit, Holm-adjusted within each outcome.**

| outcome | contrast | label | risk_difference | ci_lo | ci_hi | p_model_signflip | models_improved | n_models | p_holm |
|---|---|---|---|---|---|---|---|---|---|
| vulnerable | reminder - baseline | H3  generic security reminder | -0.133 | -0.196 | -0.077 | 0.004 | 9 | 9 | 0.035 |
| vulnerable | ctx_irrelevant - baseline | ctrl irrelevant security notes | -0.033 | -0.064 | -0.002 | 0.008 | 8 | 9 | 0.039 |
| vulnerable | rag_dense - baseline | H4  dense RAG, mixed corpus | -0.072 | -0.123 | -0.026 | 0.004 | 9 | 9 | 0.035 |
| vulnerable | rag_hybrid - baseline | H4  hybrid RAG, mixed corpus | -0.061 | -0.102 | -0.023 | 0.008 | 8 | 9 | 0.039 |
| vulnerable | rag_oracle - baseline | ref  oracle RAG (target-CWE notes) | -0.082 | -0.144 | -0.022 | 0.004 | 9 | 9 | 0.035 |
| vulnerable | rag_dense - reminder | H4b dense RAG beyond a reminder | 0.061 | 0.021 | 0.105 | 0.004 | 0 | 9 | 0.035 |
| vulnerable | rag_dense - ctx_irrelevant | H4c dense RAG beyond irrelevant notes | -0.038 | -0.087 | 0.008 | 0.047 | 6 | 9 | 0.117 |
| vulnerable | rag_hybrid - ctx_irrelevant | H4c hybrid RAG beyond irrelevant notes | -0.028 | -0.073 | 0.009 | 0.039 | 7 | 9 | 0.117 |
| vulnerable | rag_hybrid - rag_dense | H5  hybrid vs dense | 0.011 | -0.020 | 0.040 | 0.164 | 2 | 9 | 0.164 |
| secure_pass | reminder - baseline | H3  generic security reminder | 0.019 | -0.038 | 0.078 | 0.184 | 7 | 9 | 1.000 |
| secure_pass | ctx_irrelevant - baseline | ctrl irrelevant security notes | 0.015 | -0.022 | 0.051 | 0.207 | 6 | 9 | 1.000 |
| secure_pass | rag_dense - baseline | H4  dense RAG, mixed corpus | 0.010 | -0.034 | 0.052 | 0.484 | 5 | 9 | 1.000 |
| secure_pass | rag_hybrid - baseline | H4  hybrid RAG, mixed corpus | -0.005 | -0.052 | 0.041 | 0.680 | 4 | 9 | 1.000 |
| secure_pass | rag_oracle - baseline | ref  oracle RAG (target-CWE notes) | 0.025 | -0.028 | 0.080 | 0.195 | 6 | 9 | 1.000 |
| secure_pass | rag_dense - reminder | H4b dense RAG beyond a reminder | -0.009 | -0.051 | 0.033 | 0.379 | 2 | 9 | 1.000 |
| secure_pass | rag_dense - ctx_irrelevant | H4c dense RAG beyond irrelevant notes | -0.006 | -0.048 | 0.039 | 0.508 | 3 | 9 | 1.000 |
| secure_pass | rag_hybrid - ctx_irrelevant | H4c hybrid RAG beyond irrelevant notes | -0.021 | -0.066 | 0.027 | 0.082 | 2 | 9 | 0.738 |
| secure_pass | rag_hybrid - rag_dense | H5  hybrid vs dense | -0.015 | -0.048 | 0.017 | 0.102 | 2 | 9 | 0.812 |
| functional | reminder - baseline | H3  generic security reminder | -0.132 | -0.190 | -0.083 | 0.004 | 0 | 9 | 0.035 |
| functional | ctx_irrelevant - baseline | ctrl irrelevant security notes | -0.023 | -0.061 | 0.014 | 0.117 | 2 | 9 | 0.180 |
| functional | rag_dense - baseline | H4  dense RAG, mixed corpus | -0.063 | -0.111 | -0.020 | 0.004 | 0 | 9 | 0.035 |
| functional | rag_hybrid - baseline | H4  hybrid RAG, mixed corpus | -0.079 | -0.122 | -0.042 | 0.004 | 0 | 9 | 0.035 |
| functional | rag_oracle - baseline | ref  oracle RAG (target-CWE notes) | -0.067 | -0.117 | -0.025 | 0.004 | 0 | 9 | 0.035 |
| functional | rag_dense - reminder | H4b dense RAG beyond a reminder | 0.069 | 0.018 | 0.123 | 0.008 | 8 | 9 | 0.039 |
| functional | rag_dense - ctx_irrelevant | H4c dense RAG beyond irrelevant notes | -0.040 | -0.097 | 0.014 | 0.090 | 3 | 9 | 0.180 |
| functional | rag_hybrid - ctx_irrelevant | H4c hybrid RAG beyond irrelevant notes | -0.056 | -0.107 | -0.009 | 0.023 | 1 | 9 | 0.094 |
| functional | rag_hybrid - rag_dense | H5  hybrid vs dense | -0.016 | -0.056 | 0.020 | 0.043 | 2 | 9 | 0.129 |

With 9 models the smallest attainable two-sided sign-flip p-value is 0.0039; a contrast in which every model moves the same way reaches it.

**Activation test (H3b).** If knowledge is present but not used, a reminder that adds no information should help most where the model recognises the weakness. Reminder effect on the introduction rate: -0.119 in recognised cells vs -0.136 in the others; interaction within model-and-class and task -0.000 (95% CI -0.154 to 0.134), permutation p = 0.995.

**Table T14_effect_by_cwe. Change in introduction rate vs baseline, by class**

| condition | CWE-89 | CWE-79 | CWE-22 | CWE-78 | CWE-502 | CWE-798 | CWE-120 |
|---|---|---|---|---|---|---|---|
| reminder | -0.017 | -0.403 | -0.211 | -0.036 | -0.033 | -0.161 | -0.067 |
| ctx_irrelevant | 0.006 | -0.053 | -0.036 | 0.014 | -0.011 | -0.069 | -0.083 |
| rag_dense | 0.008 | -0.228 | -0.194 | 0.000 | -0.014 | -0.008 | -0.067 |
| rag_hybrid | 0.003 | -0.233 | -0.097 | -0.019 | -0.014 | 0.006 | -0.072 |
| rag_oracle | 0.006 | -0.356 | -0.203 | 0.036 | 0.033 | -0.019 | -0.072 |


**Table T15_effect_by_model. Change in introduction rate vs baseline, by model**

| model | baseline_ir | reminder | ctx_irrelevant | rag_dense | rag_hybrid | rag_oracle |
|---|---|---|---|---|---|---|
| Mistral-7B-v0.3 | 0.418 | -0.186 | 0.000 | -0.107 | -0.093 | -0.057 |
| Qwen3.5-4B | 0.293 | -0.143 | -0.011 | -0.082 | -0.050 | -0.114 |
| Llama-3.2-3B | 0.439 | -0.139 | -0.036 | -0.104 | -0.096 | -0.171 |
| Qwen2.5-Coder-3B | 0.336 | -0.043 | -0.011 | -0.007 | 0.000 | -0.039 |
| Qwen2.5-Coder-7B | 0.400 | -0.146 | -0.025 | -0.071 | -0.064 | -0.096 |
| OLMo-3-7B | 0.432 | -0.193 | -0.068 | -0.125 | -0.079 | -0.096 |
| Qwen3-4B | 0.361 | -0.196 | -0.064 | -0.071 | -0.061 | -0.089 |
| Phi-4-mini-3.8B | 0.407 | -0.079 | -0.068 | -0.064 | -0.079 | -0.043 |
| Qwen3.5-2B | 0.257 | -0.068 | -0.018 | -0.014 | -0.029 | -0.032 |


**Table T16_retrieval_quality. Retrieval quality: share of tasks with at least one note of the task's own class among the top 3 (hit@k) and mean share of on-class notes (corpus: 1845 notes)**

| condition | hit_at_k | precision_at_k |
|---|---|---|
| ctx_irrelevant | 0.000 | 0.000 |
| rag_dense | 0.357 | 0.173 |
| rag_hybrid | 0.393 | 0.196 |
| rag_oracle | 1.000 | 1.000 |


## 6. Model size tier


**Table T17_tiers. Small (<=4B) vs ~7B models; exact permutation test over models**

| measure | small_mean | 7b_mean | difference | p_permutation | n_small | n_7b |
|---|---|---|---|---|---|---|
| knowledge K | 0.583 | 0.539 | -0.044 | 0.452 | 6 | 3 |
| baseline introduction rate | 0.349 | 0.417 | 0.068 | 0.155 | 6 | 3 |
| baseline secure-pass | 0.473 | 0.430 | -0.043 | 0.679 | 6 | 3 |
| residual gap (recognised cells) | 0.191 | 0.373 | 0.183 | 0.333 | 6 | 3 |


## 7. Robustness


**Table T18_robustness. Key results under alternative outcome definitions and subsets**

| variant | baseline_ir | gap_recognised | slope_K | p_K | slope_recognises | p_recognises | rd_reminder | rd_rag_dense | rd_rag_hybrid |
|---|---|---|---|---|---|---|---|---|---|
| primary outcome | 0.371 | 0.213 | 0.161 | 0.242 | -0.008 | 0.836 | -0.133 | -0.072 | -0.061 |
| static verdict only | 0.401 | 0.243 | 0.159 | 0.230 | 0.011 | 0.718 | -0.085 | -0.026 | -0.031 |
| dynamic verdict only | 0.378 | 0.208 | 0.158 | 0.239 | -0.022 | 0.532 | -0.131 | -0.070 | -0.058 |
| greedy sample only | 0.373 | 0.222 | 0.250 | 0.089 | 0.062 | 0.210 | -0.115 | -0.067 | -0.052 |
| sampled only (T>0) | 0.371 | 0.211 | 0.139 | 0.319 | -0.025 | 0.496 | -0.137 | -0.073 | -0.063 |
| functional answers only | 0.414 | 0.217 | 0.061 | 0.651 | -0.035 | 0.371 | -0.131 | -0.045 | -0.058 |
| placeholder credentials not counted | 0.284 | 0.204 | 0.204 | 0.124 | -0.001 | 0.970 | -0.100 | -0.069 | -0.058 |


## 8. Compute


**Table T19_compute. Generation cost per model (request seconds summed over parallel slots; early_stop = share of replies cut off once the answer was complete)**

| model | generations | tokens_out | gpu_hours | early_stop |
|---|---|---|---|---|
| Llama-3.2-3B | 1680 | 373688 | 3.60 | 0.99 |
| Mistral-7B-v0.3 | 1680 | 385315 | 7.11 | 0.99 |
| OLMo-3-7B | 1680 | 412797 | 8.88 | 0.95 |
| Phi-4-mini-3.8B | 1680 | 272269 | 3.00 | 1.00 |
| Qwen2.5-Coder-3B | 1680 | 263404 | 2.06 | 1.00 |
| Qwen2.5-Coder-7B | 1680 | 283650 | 5.12 | 1.00 |
| Qwen3.5-2B | 1680 | 510077 | 8.65 | 0.86 |
| Qwen3.5-4B | 1680 | 445046 | 14.96 | 0.93 |
| Qwen3-4B | 1680 | 395643 | 4.44 | 0.98 |


## 9. Blind audit by the scorer model

Claude Opus 5.5 (`claude-opus-5-5`) judged a stratified random sample of generated answers and scored the explanations, seeing the task and the text only (rubric: `audit/SCORER_INSTRUCTIONS.md`). Its ratings do not enter any primary measure. The authors checked the ratings informally afterwards; no rating was changed.


**Table T20_scorer_audit. Automatic verdict against the scorer on the audited sample (tp = both vulnerable; fp = automatic verdict vulnerable, scorer not). The sample is stratified by automatic verdict: precision is unbiased, recall is not a population estimate**

| cwe | n | tp | fp | fn | tn | agreement | precision | recall | kappa |
|---|---|---|---|---|---|---|---|---|---|
| all | 140 | 66 | 4 | 10 | 60 | 0.900 | 0.943 | 0.868 | 0.800 |
| CWE-89 | 20 | 10 | 0 | 0 | 10 | 1.000 | 1.000 | 1.000 | 1.000 |
| CWE-79 | 20 | 9 | 1 | 2 | 8 | 0.850 | 0.900 | 0.818 | 0.700 |
| CWE-22 | 20 | 10 | 0 | 4 | 6 | 0.800 | 1.000 | 0.714 | 0.600 |
| CWE-78 | 20 | 10 | 0 | 0 | 10 | 1.000 | 1.000 | 1.000 | 1.000 |
| CWE-502 | 20 | 10 | 0 | 0 | 10 | 1.000 | 1.000 | 1.000 | 1.000 |
| CWE-798 | 20 | 10 | 0 | 3 | 7 | 0.850 | 1.000 | 0.769 | 0.700 |
| CWE-120 | 20 | 7 | 3 | 1 | 9 | 0.800 | 0.700 | 0.875 | 0.600 |


Explanations: 63 scored; Spearman correlation between the scorer and the concept rubric 0.121 (permutation p = 0.316).

**Table T27_human_audit. The audited sample rated by human raters, blind to model, condition and verdict, beside the scorer's audit (95% interval of kappa from a bootstrap within class and automatic verdict; precision and recall of the automatic verdict against the scorer or rater). Ratings left as set for all items at once: rater A 0, rater B 0**

| comparison | n | agreement | kappa | kappa_lo | kappa_hi | precision | recall |
|---|---|---|---|---|---|---|---|
| automatic verdict against scorer | 140 | 0.900 | 0.800 | 0.714 | 0.886 | 0.943 | 0.868 |
| automatic verdict against rater A | 140 | 0.893 | 0.786 | 0.700 | 0.871 | 0.957 | 0.848 |
| automatic verdict against rater B | 140 | 0.864 | 0.729 | 0.629 | 0.814 | 0.871 | 0.859 |
| rater A against rater B | 140 | 0.943 | 0.886 | 0.829 | 0.942 | n/a | n/a |
| scorer against rater A | 140 | 0.979 | 0.957 | 0.911 | 1.000 | n/a | n/a |
| scorer against rater B | 140 | 0.950 | 0.900 | 0.843 | 0.956 | n/a | n/a |


## 10. Sensitivity of the design

With 63 model x CWE cells a two-sided correlation test at alpha = 0.05 has 80% power for |rho| >= 0.35 (Fisher z approximation; cells treated as independent, so this is optimistic). Simulation-based power for the fixed-effects test under the planned design is in docs/analysis_plan.md.
