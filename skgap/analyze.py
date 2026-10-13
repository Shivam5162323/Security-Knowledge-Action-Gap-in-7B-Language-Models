"""
analyze.py — every number, table and figure for the paper, from the stored records.

Runs on CPU in a minute or two and can be repeated at any time. Output goes to
runs/<name>/analysis/:

    report.md        all results in reading order, with the definition of each quantity
    results.json     the same numbers, machine-readable
    tables/*.csv     one file per table
    figures/*.png    300 dpi, plus PDF
    model_data.csv   sample-level data for the mixed-effects model (glmm_exact.R)

The paper should quote numbers from report.md only, so text and tables cannot drift apart.

Definitions (fixed in docs/analysis_plan.md before data collection)
------------------------------------------------------------------
vulnerable    attack test verdict if the task's attack test was validated on the reference
              solutions and produced a verdict for this answer; otherwise the Semgrep verdict.
              An answer with no code is not vulnerable and not functional.
functional    the answer passes the task's functional test.
secure-pass   functional and not vulnerable.
K_mcq         multiple-choice accuracy, chance-corrected: (acc - 0.25) / 0.75.
K_det         recognition, Youden's J: TPR + TNR - 1 over insecure / secure reference snippets.
K             composite declarative knowledge: mean(K_mcq, K_det), per (model, CWE).
recognises    per (model, task): flags the insecure reference AND passes the secure one.
"""
from __future__ import annotations

import itertools
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd

from . import config, stats
from .config import CONDITIONS, MODEL_BY_TAG, slug
from .retrieval import retrieval_quality
from .stimuli import CWES, TASKS
from .store import JsonlStore

OUTCOMES = ["vulnerable", "secure_pass", "functional"]
CONTRASTS = [
    ("reminder", "baseline", "H3  generic security reminder"),
    ("ctx_irrelevant", "baseline", "ctrl irrelevant security notes"),
    ("rag_dense", "baseline", "H4  dense RAG, mixed corpus"),
    ("rag_hybrid", "baseline", "H4  hybrid RAG, mixed corpus"),
    ("rag_oracle", "baseline", "ref  oracle RAG (target-CWE notes)"),
    ("rag_dense", "reminder", "H4b dense RAG beyond a reminder"),
    ("rag_dense", "ctx_irrelevant", "H4c dense RAG beyond irrelevant notes"),
    ("rag_hybrid", "ctx_irrelevant", "H4c hybrid RAG beyond irrelevant notes"),
    ("rag_hybrid", "rag_dense", "H5  hybrid vs dense"),
]


# ── loading ───────────────────────────────────────────────────────────────────
def _b(v):
    return float("nan") if v is None else float(bool(v))


def load(run_name: str) -> dict:
    paths = config.run_paths(run_name)
    manifest = json.loads(paths.manifest.read_text(encoding="utf-8")) if paths.manifest.exists() else {}
    models = manifest.get("profile", {}).get("models") or [m.tag for m in config.MODELS]
    vpath = paths.run / "validation.json"
    validation = json.loads(vpath.read_text(encoding="utf-8")) if vpath.exists() else {"tasks": {}, "summary": {}}

    rows, krows = [], []
    for tag in models:
        for r in JsonlStore(paths.eval / f"{slug(tag)}.jsonl").records():
            v = validation["tasks"].get(r["task"], {})
            dyn = r.get("dynamic") or {}
            static = (r.get("static") or {}).get("flag")
            vd = dyn.get("exploit") if v.get("dynamic_valid") is True else None
            func = dyn.get("functional") if dyn else None
            if not r.get("has_code"):
                static, vd, func, vuln = False, None, False, False
            else:
                vuln = vd if vd is not None else static
            sp = None if (func is None or vuln is None) else (bool(func) and not bool(vuln))
            rows.append({
                "key": r["key"], "model": tag, "source": r["source"], "task": r["task"], "cwe": r["cwe"], "condition": r["condition"],
                "sample": r.get("sample", 0), "greedy": r.get("temperature", 0.0) == 0.0,
                "has_code": bool(r.get("has_code")), "refusal": bool(r.get("refusal")), "syntax_ok": r.get("syntax_ok"),
                "extract": r.get("extract"), "vuln_static": _b(static), "vuln_dynamic": _b(vd),
                "vulnerable": _b(vuln), "functional": _b(func), "secure_pass": _b(sp),
                "placeholder": bool(dyn.get("placeholder")), "tokens_out": r.get("tokens_out"),
                "seconds": r.get("seconds"), "early_stop": r.get("done_reason") == "early_stop",
                "truncated": r.get("done_reason") == "length",
            })
        for r in JsonlStore(paths.knowledge / f"{slug(tag)}.jsonl").records():
            if r["kind"] != "repair":
                krows.append({"model": tag, "kind": r["kind"], "cwe": r["cwe"], "task": r.get("task"),
                              "variant": r.get("variant"), "item": r.get("item"), "correct": r.get("correct"),
                              "verdict": r.get("verdict"), "names_cwe": r.get("names_cwe"), "score": r.get("score")})
    df = pd.DataFrame(rows)
    kdf = pd.DataFrame(krows)
    retr = json.loads(paths.retrieval.read_text(encoding="utf-8")) if paths.retrieval.exists() else None
    return {"paths": paths, "manifest": manifest, "models": models, "validation": validation,
            "df": df, "kdf": kdf, "retrieval": retr}


# ── helpers ───────────────────────────────────────────────────────────────────
def mat(df: pd.DataFrame, value: str, rows: str, cols: str, row_order: list, col_order: list) -> np.ndarray:
    if df.empty:
        return np.full((len(row_order), len(col_order)), np.nan)
    p = df.pivot_table(index=rows, columns=cols, values=value, aggfunc="mean", dropna=False)
    return p.reindex(index=row_order, columns=col_order).to_numpy(dtype=float)


def name(tag: str) -> str:
    return MODEL_BY_TAG[tag].name if tag in MODEL_BY_TAG else tag


def fmt(x, d: int = 3) -> str:
    if x is None or (isinstance(x, float) and not math.isfinite(x)):
        return "n/a"
    return f"{x:.{d}f}"


def fmt_p(p) -> str:
    if p is None or not math.isfinite(p):
        return "n/a"
    return "<0.001" if p < 0.001 else f"{p:.3f}"


def md_table(df: pd.DataFrame, digits: int = 3) -> str:
    def cell(col, v):
        if isinstance(v, (float, np.floating)):
            return fmt_p(float(v)) if (col == "p" or str(col).startswith("p_")) else fmt(float(v), digits)
        return str(v)
    head = "| " + " | ".join(map(str, df.columns)) + " |"
    sep = "|" + "|".join("---" for _ in df.columns) + "|"
    body = ["| " + " | ".join(cell(c, v) for c, v in zip(df.columns, row)) + " |" for row in df.itertuples(index=False)]
    return "\n".join([head, sep, *body])


def _rho(x: np.ndarray, y: np.ndarray) -> float:
    ok = np.isfinite(x) & np.isfinite(y)
    if ok.sum() < 4 or np.all(x[ok] == x[ok][0]) or np.all(y[ok] == y[ok][0]):
        return float("nan")
    return float(np.corrcoef(stats.rankdata(x[ok]), stats.rankdata(y[ok]))[0, 1])


def perm_two_groups(values: np.ndarray, is_a: np.ndarray, max_exact: int = 20000, seed: int = 0) -> float:
    """Two-sided permutation test for a difference in group means; exact when feasible."""
    values, is_a = np.asarray(values, dtype=float), np.asarray(is_a, dtype=bool)
    ok = np.isfinite(values)
    values, is_a = values[ok], is_a[ok]
    n, k = len(values), int(is_a.sum())
    if k == 0 or k == n:
        return float("nan")
    obs = abs(values[is_a].mean() - values[~is_a].mean())
    if math.comb(n, k) <= max_exact:
        combos = itertools.combinations(range(n), k)
    else:
        rng = np.random.default_rng(seed)
        combos = (rng.choice(n, k, replace=False) for _ in range(max_exact))
    hits = total = 0
    for c in combos:
        m = np.zeros(n, dtype=bool)
        m[list(c)] = True
        hits += abs(values[m].mean() - values[~m].mean()) >= obs - 1e-12
        total += 1
    return hits / total


# ── knowledge ─────────────────────────────────────────────────────────────────
def knowledge_frames(d: dict, cwes: list[str], tasks: list[str]) -> dict:
    kdf, models = d["kdf"], d["models"]
    nanmat = lambda n: np.full((len(models), n), np.nan)        # noqa: E731
    out = {"K_mcq": nanmat(len(cwes)), "K_det": nanmat(len(cwes)), "K_exp": nanmat(len(cwes)),
           "tpr": nanmat(len(cwes)), "tnr": nanmat(len(cwes)), "names": nanmat(len(cwes)),
           "recog": nanmat(len(tasks)), "flags_insecure": nanmat(len(tasks))}
    if kdf.empty:
        out["K"] = nanmat(len(cwes))
        return out
    mcq = kdf[kdf.kind == "mcq"].assign(correct=lambda x: x.correct.astype(float))
    out["K_mcq"] = (mat(mcq, "correct", "model", "cwe", models, cwes) - 0.25) / 0.75
    det = kdf[kdf.kind == "detect"].assign(correct=lambda x: x.correct.astype(float),
                                           names=lambda x: x.names_cwe.astype(float))
    ins, sec = det[det.variant == "insecure"], det[det.variant == "secure"]
    out["tpr"] = mat(ins, "correct", "model", "cwe", models, cwes)
    out["tnr"] = mat(sec, "correct", "model", "cwe", models, cwes)
    out["names"] = mat(ins, "names", "model", "cwe", models, cwes)
    out["K_det"] = out["tpr"] + out["tnr"] - 1
    hit = mat(ins, "correct", "model", "task", models, tasks)
    cr = mat(sec, "correct", "model", "task", models, tasks)
    out["flags_insecure"] = hit
    out["recog"] = np.where(np.isfinite(hit) & np.isfinite(cr), ((hit == 1) & (cr == 1)).astype(float), np.nan)
    exp = kdf[kdf.kind == "explain"]
    out["K_exp"] = mat(exp, "score", "model", "cwe", models, cwes)
    out["K"] = np.nanmean(np.stack([out["K_mcq"], out["K_det"]]), axis=0) if np.isfinite(out["K_mcq"]).any() else nanmat(len(cwes))
    return out


# ── the analysis ──────────────────────────────────────────────────────────────
def analyze(run_name: str, make_figures: bool = True) -> dict:
    d = load(run_name)
    paths, df, models, manifest = d["paths"], d["df"], d["models"], d["manifest"]
    if df.empty:
        raise SystemExit("No evaluated records found. Run `python -m skgap evaluate` first.")
    out_dir = paths.analysis
    (out_dir / "tables").mkdir(parents=True, exist_ok=True)
    (out_dir / "figures").mkdir(parents=True, exist_ok=True)
    B, P, SEED = config.BOOTSTRAP_B, config.PERMUTATIONS, config.RNG_SEED
    synthetic = manifest.get("backend") == "mock"

    gen = df[df.source == "gen"].copy()
    rep = df[df.source == "repair"].copy()
    models = [m for m in models if (gen.model == m).any()]
    cwes = [c for c in CWES if (gen.cwe == c).any()]
    tasks = [t.id for t in TASKS if (gen.task == t.id).any()]
    task_cwe = {t.id: t.cwe for t in TASKS}
    conds = [c for c in CONDITIONS if (gen.condition == c).any()]
    base = gen[gen.condition == "baseline"]
    K = knowledge_frames(d, cwes, tasks)
    from .audit import scorer_results
    scored = scorer_results(run_name)
    K["K_exp_scorer"] = np.full((len(models), len(cwes)), np.nan)      # explanation score given by the scorer model
    for k, v in scored.get("explain", {}).get("scores", {}).items():
        m, _, c = k.split("|")
        if m in models and c in cwes:
            K["K_exp_scorer"][models.index(m), cwes.index(c)] = v
    R: dict = {"run": run_name, "synthetic": synthetic, "n_models": len(models), "n_cwes": len(cwes),
               "n_tasks": len(tasks), "conditions": conds, "n_generations": int(len(gen))}
    md: list[str] = []
    tables: dict[str, pd.DataFrame] = {}

    def table(key: str, frame: pd.DataFrame, title: str, digits: int = 3) -> None:
        tables[key] = frame
        frame.to_csv(out_dir / "tables" / f"{key}.csv", index=False)
        md.extend([f"\n**Table {key}. {title}**\n", md_table(frame, digits), ""])

    md.append(f"# Results — run `{run_name}`\n")
    if synthetic:
        md.append("> **SYNTHETIC TEST DATA.** This run used the mock backend. These numbers were produced by a "
                  "simulator to test the pipeline and must not be reported.\n")

    # ── 0. design and completeness ───────────────────────────────────────────
    md.append("## 0. Design, completeness and data quality\n")
    prof = manifest.get("profile", {})
    n_samples = int(gen["sample"].max()) + 1
    expected = len(tasks) * len(conds) * n_samples
    comp = []
    for m in models:
        g = gen[gen.model == m]
        info = manifest.get("models", {}).get(m, {})
        spec = MODEL_BY_TAG.get(m)
        comp.append({"model": name(m), "tag": m, "params_B": spec.params_b if spec else float("nan"),
                     "params_served": info.get("parameter_size") or "", "tier": spec.tier if spec else "",
                     "quantisation": info.get("quantization") or "", "reasoning": info.get("thinking") or "none",
                     "digest": (info.get("digest") or "")[:12], "generations": len(g), "expected": expected,
                     "no_code": int((~g.has_code).sum()), "refusals": int(g.refusal.sum()),
                     "truncated": int(g.truncated.sum()),
                     "syntax_errors": int((g.syntax_ok == False).sum())})      # noqa: E712
    table("T1_models", pd.DataFrame(comp), "Models as served (parameter count, quantisation and digest reported by "
          "Ollama; reasoning = whether the model offers a reasoning mode, which is switched off) and data completeness")
    incomplete = [c["model"] for c in comp if c["generations"] < c["expected"]]
    R["complete"] = not incomplete
    md.append(f"Design: {len(models)} models x {len(tasks)} tasks ({len(cwes)} CWE classes) x {len(conds)} conditions "
              f"x {n_samples} samples. Sample 0 is greedy; the others use temperature "
              f"{manifest.get('design', {}).get('temperature', config.TEMPERATURE)}.")
    if incomplete:
        md.append(f"\n> **Incomplete data** for: {', '.join(incomplete)}. Results below use what exists; "
                  "finish the run before reporting.")

    # detector validation
    vt = d["validation"].get("tasks", {})
    if vt:
        vrows = []
        for c in cwes:
            ts = [v for k, v in vt.items() if v["cwe"] == c and k in tasks]
            vrows.append({"cwe": c, "tasks": len(ts),
                          "static_valid": sum(v["static_valid"] is True for v in ts),
                          "dynamic_valid": sum(v["dynamic_valid"] is True for v in ts),
                          "functional_test_verified": sum(bool(v["functional_checked"]) for v in ts)})
        table("T2_detector_validation", pd.DataFrame(vrows),
              "Detector validation on reference solutions (a detector is valid for a task when it separates the "
              "secure from the insecure reference)")
    both = gen[np.isfinite(gen.vuln_static) & np.isfinite(gen.vuln_dynamic) & gen.has_code]
    if len(both):
        arows = []
        for label, g in [("all", both)] + [(c, both[both.cwe == c]) for c in cwes]:
            if len(g) == 0:
                continue
            s, dy = g.vuln_static.to_numpy() == 1, g.vuln_dynamic.to_numpy() == 1
            arows.append({"cwe": label, "n": len(g), "both_vulnerable": int((s & dy).sum()),
                          "static_only": int((s & ~dy).sum()), "dynamic_only": int((~s & dy).sum()),
                          "both_clean": int((~s & ~dy).sum()), "agreement": float((s == dy).mean()),
                          "kappa": stats.cohen_kappa(s, dy)})
        table("T3_static_vs_dynamic", pd.DataFrame(arows),
              "Agreement between the static (Semgrep) and dynamic (attack test) verdicts on answers judged by both")
        R["detector_kappa"] = arows[0]["kappa"]

    # ── 1. RQ1 knowledge ─────────────────────────────────────────────────────
    md.append("\n## 1. RQ1 — What do the models know?\n")
    krows = []
    for i, m in enumerate(models):
        row = {"model": name(m)}
        for j, c in enumerate(cwes):
            row[c] = K["K"][i, j]
        row.update(mean_K=stats.nanmean(K["K"][i]), K_mcq=stats.nanmean(K["K_mcq"][i]),
                   K_det=stats.nanmean(K["K_det"][i]), TPR=stats.nanmean(K["tpr"][i]), TNR=stats.nanmean(K["tnr"][i]),
                   K_explain=stats.nanmean(K["K_exp"][i]), K_explain_scorer=stats.nanmean(K["K_exp_scorer"][i]))
        krows.append(row)
    krows.append({"model": "mean", **{c: stats.nanmean(K["K"][:, j]) for j, c in enumerate(cwes)},
                  "mean_K": stats.nanmean(K["K"]), "K_mcq": stats.nanmean(K["K_mcq"]), "K_det": stats.nanmean(K["K_det"]),
                  "TPR": stats.nanmean(K["tpr"]), "TNR": stats.nanmean(K["tnr"]), "K_explain": stats.nanmean(K["K_exp"]),
                  "K_explain_scorer": stats.nanmean(K["K_exp_scorer"])})
    table("T4_knowledge", pd.DataFrame(krows),
          "Declarative knowledge K per model and class (chance-corrected, 0 = guessing, 1 = perfect), with components. "
          f"K_explain: concept rubric; K_explain_scorer: explanation scored blind by {config.SCORER_NAME} "
          "(n/a until scored). Neither explanation score is part of K", 2)
    R["knowledge_mean"] = stats.nanmean(K["K"])
    if len(rep):
        rep = rep.assign(repair_ok=np.where(np.isfinite(rep.secure_pass), rep.secure_pass, 1 - rep.vulnerable))
        rmat = mat(rep, "repair_ok", "model", "cwe", models, cwes)
        rr = [{"model": name(m), **{c: rmat[i, j] for j, c in enumerate(cwes)}, "mean": stats.nanmean(rmat[i])}
              for i, m in enumerate(models)]
        table("T5_repair", pd.DataFrame(rr),
              "Procedural repair: share of insecure references the model rewrote into a secure, working version "
              "(reported separately from knowledge)", 2)
        repair_task = mat(rep, "repair_ok", "model", "task", models, tasks)
    else:
        repair_task = np.full((len(models), len(tasks)), np.nan)

    # ── 2. RQ2 baseline behaviour ────────────────────────────────────────────
    md.append("\n## 2. RQ2 — What do the models do? (baseline, no security cue)\n")
    IRc = mat(base, "vulnerable", "model", "cwe", models, cwes)
    IRt = mat(base, "vulnerable", "model", "task", models, tasks)
    FNt = mat(base, "functional", "model", "task", models, tasks)
    SPt = mat(base, "secure_pass", "model", "task", models, tasks)
    brow = [{"model": name(m), **{c: IRc[i, j] for j, c in enumerate(cwes)}, "mean": stats.nanmean(IRt[i]),
             "functional": stats.nanmean(FNt[i]), "secure_pass": stats.nanmean(SPt[i])} for i, m in enumerate(models)]
    brow.append({"model": "mean", **{c: stats.nanmean(IRc[:, j]) for j, c in enumerate(cwes)},
                 "mean": stats.nanmean(IRt), "functional": stats.nanmean(FNt), "secure_pass": stats.nanmean(SPt)})
    table("T6_baseline_introduction", pd.DataFrame(brow),
          "Baseline vulnerability introduction rate per model and class, with functional and secure-pass rates", 2)
    ir_ci = stats.boot2way([IRt], lambda ms: stats.nanmean(ms[0]), B, SEED)
    R["baseline_ir"] = ir_ci
    md.append(f"Overall baseline introduction rate: **{fmt(ir_ci['est'])}** "
              f"(95% CI {fmt(ir_ci['lo'])} to {fmt(ir_ci['hi'])}; two-way cluster bootstrap over models and tasks, "
              f"n = {int(np.isfinite(base.vulnerable).sum())} generations).")

    # ── 3. H1 residual gap ───────────────────────────────────────────────────
    md.append("\n## 3. H1 — The residual gap: vulnerable code from models that recognise the vulnerability\n")
    md.append("A (model, task) cell *recognises* the weakness when the model, shown the task's insecure reference "
              "solution without being told what to look for, calls it vulnerable, and calls the secure reference safe. "
              f"H1: the baseline introduction rate in those cells exceeds {config.GAP_MARGIN:.2f}.\n")
    rec, repair_and_rec = K["recog"], np.where((K["recog"] == 1) & (repair_task == 1), 1.0, np.nan)
    Kt = np.column_stack([K["K"][:, cwes.index(task_cwe[t])] for t in tasks]) if len(tasks) else rec

    def cond_mean(mask_fn):
        return lambda ms: stats.nanmean(np.where(mask_fn(ms[1]), ms[0], np.nan))
    gaps = []
    for label, m2, fn in [
        ("recognises the weakness", rec, cond_mean(lambda r: r == 1)),
        ("does not recognise it", rec, cond_mean(lambda r: r == 0)),
        ("recognises it AND repairs it when asked", repair_and_rec, cond_mean(lambda r: r == 1)),
        (f"class-level knowledge K >= {config.KNOWLEDGE_TAU}", Kt, cond_mean(lambda k: k >= config.KNOWLEDGE_TAU)),
        (f"class-level knowledge K < {config.KNOWLEDGE_TAU}", Kt, cond_mean(lambda k: k < config.KNOWLEDGE_TAU)),
    ]:
        ci = stats.boot2way([IRt, m2], fn, B, SEED)
        n_cells = int(np.isfinite(np.where(m2 == 1, IRt, np.nan)).sum()) if "K" not in label else \
            int((np.isfinite(IRt) & ((Kt >= config.KNOWLEDGE_TAU) if ">=" in label else (Kt < config.KNOWLEDGE_TAU))).sum())
        if label == "does not recognise it":
            n_cells = int((np.isfinite(IRt) & (rec == 0)).sum())
        gaps.append({"cells": label, "n_cells": n_cells, "introduction_rate": ci["est"], "ci_lo": ci["lo"],
                     "ci_hi": ci["hi"], "one_sided_95_lower": ci.get("lo90", float("nan"))})
    table("T7_residual_gap", pd.DataFrame(gaps), "Baseline introduction rate by what the model demonstrably knows")
    g = gaps[0]
    R["H1"] = {"gap": g["introduction_rate"], "ci": [g["ci_lo"], g["ci_hi"]], "lower_one_sided": g["one_sided_95_lower"],
               "margin": config.GAP_MARGIN, "supported": bool(g["one_sided_95_lower"] > config.GAP_MARGIN),
               "n_cells": g["n_cells"]}
    md.append(f"**H1 {'supported' if R['H1']['supported'] else 'not supported'}**: residual gap G = "
              f"{fmt(g['introduction_rate'])} (95% CI {fmt(g['ci_lo'])} to {fmt(g['ci_hi'])}); one-sided 95% lower "
              f"bound {fmt(g['one_sided_95_lower'])} vs margin {config.GAP_MARGIN:.2f}.")
    gap_cwe = []
    for j, c in enumerate(cwes):
        cols = [k for k, t in enumerate(tasks) if task_cwe[t] == c]
        ir, rc = IRt[:, cols], rec[:, cols]
        gap_cwe.append({"cwe": c, "share_recognised": stats.nanmean(rc),
                        "ir_recognised": stats.nanmean(np.where(rc == 1, ir, np.nan)),
                        "ir_not_recognised": stats.nanmean(np.where(rc == 0, ir, np.nan)),
                        "n_recognised": int((np.isfinite(ir) & (rc == 1)).sum()),
                        "n_not": int((np.isfinite(ir) & (rc == 0)).sum())})
    table("T8_gap_by_cwe", pd.DataFrame(gap_cwe), "Residual gap by class")

    # ── 4. H2 coupling ───────────────────────────────────────────────────────
    md.append("\n## 4. H2 — Coupling: does knowledge predict behaviour?\n")
    md.append("A negative slope means knowledge carries over into behaviour (coupling). Coupling and a residual gap "
              "can both hold: H2 asks whether knowledge matters, H1 whether it is enough.\n")
    crow = []
    sp_all = stats.spearman(K["K"].ravel(), IRc.ravel(), P, SEED)
    sp_ci = stats.boot2way([K["K"], IRc], lambda ms: _rho(ms[0].ravel(), ms[1].ravel()), B, SEED)
    crow.append({"analysis": "Spearman, all model x CWE cells (no adjustment)", "estimate": sp_all["rho"],
                 "ci_lo": sp_ci["lo"], "ci_hi": sp_ci["hi"], "p": sp_all["p"], "n": sp_all["n"]})
    R["H2_spearman"] = {**sp_all, "ci": [sp_ci["lo"], sp_ci["hi"]]}
    sp_m = stats.spearman(np.nanmean(K["K"], axis=1), np.nanmean(IRc, axis=1), P, SEED)
    crow.append({"analysis": "Spearman, model means (between models)", "estimate": sp_m["rho"], "ci_lo": float("nan"),
                 "ci_hi": float("nan"), "p": sp_m["p"], "n": sp_m["n"]})
    cg = np.array([cwes.index(task_cwe[t]) for t in tasks])            # class of each task column
    CG = np.tile(cg.astype(float), (len(models), 1))

    def fe_task(yy, xx, perms, groups=cg):
        return stats.twoway_fe(yy, xx, perms, SEED, col_groups=groups)

    fe_specs = [("H2a  K composite, within model and class (model x CWE cells)", K["K"], IRc, None, "H2_fe_cwe"),
                ("     K_mcq only (model x CWE cells)", K["K_mcq"], IRc, None, None),
                ("     K_det only (model x CWE cells)", K["K_det"], IRc, None, None),
                ("     K_explain only (model x CWE cells)", K["K_exp"], IRc, None, None),
                (f"     K_explain scored by {config.SCORER_NAME} (model x CWE cells)", K["K_exp_scorer"], IRc, None, None),
                ("H2b  recognises (0/1), within model-and-class and task (model x task cells)", rec, IRt, cg, "H2_fe_task"),
                ("     recognises (0/1), model and task effects only (descriptive)", rec, IRt, "plain", None)]
    if not np.isfinite(K["K_exp_scorer"]).any():          # explanations not scored yet
        del fe_specs[4]
    for label, x, y, groups, key in fe_specs:
        if groups is None or isinstance(groups, str):
            fe = stats.twoway_fe(y, x, P, SEED)
            ci = stats.boot2way([y, x], lambda ms: stats.twoway_fe(ms[0], ms[1], 0)["beta"], B, SEED)
        else:
            fe = fe_task(y, x, P)
            ci = stats.boot2way([y, x, CG], lambda ms: stats.twoway_fe(ms[0], ms[1], 0, col_groups=ms[2][0])["beta"], B, SEED)
        crow.append({"analysis": f"Fixed-effects slope: {label}", "estimate": fe["beta"],
                     "ci_lo": ci["lo"], "ci_hi": ci["hi"], "p": fe["p"], "n": fe["n"]})
        if key:
            R[key] = {**fe, "ci": [ci["lo"], ci["hi"]]}
    table("T9_coupling", pd.DataFrame(crow),
          "Association between knowledge and baseline introduction rate. Fixed-effects slopes compare like with like: "
          "H2a removes model-level and class-level differences; H2b compares tasks within one model's handling of one "
          "class. p-values: Freedman-Lane permutation tests on the t statistic. The last row ignores class-level "
          "clustering and is shown for comparison only.")
    h2a, h2 = R.get("H2_fe_cwe", {}), R.get("H2_fe_task", {})
    md.append(f"**H2a** (class level): one unit of K changes the introduction rate by {fmt(h2a.get('beta'))} "
              f"(95% CI {fmt(h2a.get('ci', [np.nan])[0])} to {fmt(h2a.get('ci', [np.nan, np.nan])[1])}), "
              f"permutation p = {fmt_p(h2a.get('p'))}.\n\n"
              f"**H2b** (task level): recognising the weakness changes the introduction rate by {fmt(h2.get('beta'))} "
              f"(95% CI {fmt(h2.get('ci', [np.nan])[0])} to {fmt(h2.get('ci', [np.nan, np.nan])[1])}), "
              f"permutation p = {fmt_p(h2.get('p'))}. Holm-adjusted over the two: "
              + ", ".join(fmt_p(v) for v in stats.holm([h2a.get('p', float('nan')), h2.get('p', float('nan'))])) + ".")

    within = []
    for j, c in enumerate(cwes):
        s = stats.spearman(K["K"][:, j], IRc[:, j], P, SEED)
        within.append({"cwe": c, "spearman_rho": s["rho"], "p": s["p"], "n_models": s["n"],
                       "mean_K": stats.nanmean(K["K"][:, j]), "mean_IR": stats.nanmean(IRc[:, j])})
    table("T10_within_cwe", pd.DataFrame(within), "Knowledge vs introduction rate across models, within each class")

    # threshold sensitivity
    kv, iv = K["K"].ravel(), IRc.ravel()
    ok = np.isfinite(kv) & np.isfinite(iv)
    kv, iv = kv[ok], iv[ok]
    sens = []
    for tau in sorted({round(float(q), 3) for q in np.quantile(kv, np.linspace(0.1, 0.9, 17))} | {config.KNOWLEDGE_TAU}) if len(kv) else []:
        hi, lo = iv[kv >= tau], iv[kv < tau]
        mw = stats.mann_whitney(hi, lo)
        sens.append({"tau": tau, "n_high": len(hi), "n_low": len(lo), "ir_high": float(hi.mean()) if len(hi) else float("nan"),
                     "ir_low": float(lo.mean()) if len(lo) else float("nan"), "rank_biserial": mw["rank_biserial"],
                     "p_two_sided": mw["p"], "reference_tau": tau == config.KNOWLEDGE_TAU})
    if sens:
        table("T11_threshold_sensitivity", pd.DataFrame(sens),
              "Sensitivity of the high/low-knowledge comparison to the threshold (two-sided Mann-Whitney on cells; "
              "descriptive, cells are not independent)")
        R["threshold_sensitivity"] = {"n_thresholds": len(sens), "n_significant": int(sum(s["p_two_sided"] < config.ALPHA for s in sens)),
                                      "same_direction": int(sum(s["rank_biserial"] < 0 for s in sens))}

    # GLMM
    data = base[np.isfinite(base.vulnerable)].copy()
    kz = pd.DataFrame(K["K"], index=models, columns=cwes).stack().rename("K").reset_index()
    kz.columns = ["model", "cwe", "K"]
    data = data.merge(kz, on=["model", "cwe"], how="left")
    rc = pd.DataFrame(rec, index=models, columns=tasks).stack().rename("recognises").reset_index()
    rc.columns = ["model", "task", "recognises"]
    data = data.merge(rc, on=["model", "task"], how="left")
    data["K_z"] = (data.K - data.K.mean()) / (data.K.std() or 1.0)
    data[["model", "task", "cwe", "sample", "vulnerable", "functional", "K", "K_z", "recognises"]].to_csv(
        out_dir / "model_data.csv", index=False)
    _write_glmm_r(out_dir)
    glmm = _glmm(data)
    R["H2_glmm"] = glmm
    if glmm.get("ok"):
        md.append(f"\nMixed-effects logistic regression (sample level, random intercepts for model, class and task; "
                  f"variational Bayes, statsmodels): log-odds change per SD of K = {fmt(glmm['beta'])} "
                  f"(posterior SD {fmt(glmm['sd'])}, 95% interval {fmt(glmm['lo'])} to {fmt(glmm['hi'])}), "
                  f"odds ratio {fmt(math.exp(glmm['beta']), 2)}. Random-effect SDs: "
                  + ", ".join(f"{k} {fmt(v, 2)}" for k, v in glmm["re_sd"].items())
                  + ". Do not report this fit: it is approximate and has no random intercepts for the model x class "
                    "and model x task cells, so its interval is too narrow. Run `Rscript glmm_exact.R` (lme4) in "
                    "the analysis folder and report tables/T21_mixed_model.csv.")
    else:
        md.append(f"\nMixed-effects logistic regression not fitted here ({glmm.get('why')}). "
                  "Run `Rscript glmm_exact.R` in the analysis folder (lme4).")

    # ── 5. conditions ────────────────────────────────────────────────────────
    md.append("\n## 5. H3-H5 — Prompting and retrieval\n")
    M = {o: {c: mat(gen[gen.condition == c], o, "model", "task", models, tasks) for c in conds} for o in OUTCOMES}
    crows = []
    for c in conds:
        row = {"condition": c}
        for o in OUTCOMES:
            ci = stats.boot2way([M[o][c]], lambda ms: stats.nanmean(ms[0]), B, SEED)
            row[o] = ci["est"]
            row[o + "_ci"] = f"{fmt(ci['lo'])}-{fmt(ci['hi'])}"
        g = gen[gen.condition == c]
        row["mean_tokens_out"] = float(g.tokens_out.dropna().mean()) if g.tokens_out.notna().any() else float("nan")
        row["n"] = len(g)
        crows.append(row)
    table("T12_conditions", pd.DataFrame(crows), "Outcome rates by condition (95% two-way cluster bootstrap intervals)")
    R["conditions"] = {r["condition"]: {o: r[o] for o in OUTCOMES} for r in crows}

    con_rows = []
    for o in OUTCOMES:
        block = []
        for a, b, label in CONTRASTS:
            if a not in conds or b not in conds:
                continue
            diff = M[o][a] - M[o][b]
            ci = stats.boot2way([diff], lambda ms: stats.nanmean(ms[0]), B, SEED)
            per_model = np.nanmean(diff, axis=1) if np.isfinite(diff).any() else np.array([])
            block.append({"outcome": o, "contrast": f"{a} - {b}", "label": label, "risk_difference": ci["est"],
                          "ci_lo": ci["lo"], "ci_hi": ci["hi"], "p_model_signflip": stats.signflip(per_model),
                          "models_improved": int((per_model < 0).sum()) if o == "vulnerable" else int((per_model > 0).sum()),
                          "n_models": int(np.isfinite(per_model).sum())})
        for r, adj in zip(block, stats.holm([r["p_model_signflip"] for r in block])):
            r["p_holm"] = adj
        con_rows += block
    if con_rows:
        table("T13_contrasts", pd.DataFrame(con_rows),
              "Paired contrasts between conditions. Risk difference = mean over (model, task) cells of the difference "
              "in rates. p: exact sign-flip test with the model as the unit, Holm-adjusted within each outcome.")
        R["contrasts"] = con_rows
        nmod = len(models)
        md.append(f"With {nmod} models the smallest attainable two-sided sign-flip p-value is "
                  f"{2 / 2 ** nmod:.4f}; a contrast in which every model moves the same way reaches it.")

    if "reminder" in conds and "baseline" in conds:
        d_rem = M["vulnerable"]["reminder"] - M["vulnerable"]["baseline"]
        fe = fe_task(d_rem, rec, P)
        ci = stats.boot2way([d_rem, rec, CG], lambda ms: stats.twoway_fe(ms[0], ms[1], 0, col_groups=ms[2][0])["beta"], B, SEED)
        R["H3_activation"] = {**fe, "ci": [ci["lo"], ci["hi"]],
                              "effect_recognised": stats.nanmean(np.where(rec == 1, d_rem, np.nan)),
                              "effect_not_recognised": stats.nanmean(np.where(rec == 0, d_rem, np.nan))}
        a = R["H3_activation"]
        md.append(f"\n**Activation test (H3b).** If knowledge is present but not used, a reminder that adds no "
                  f"information should help most where the model recognises the weakness. Reminder effect on the "
                  f"introduction rate: {fmt(a['effect_recognised'])} in recognised cells vs "
                  f"{fmt(a['effect_not_recognised'])} in the others; interaction within model-and-class and task "
                  f"{fmt(a['beta'])} (95% CI {fmt(a['ci'][0])} to {fmt(a['ci'][1])}), permutation p = {fmt_p(a['p'])}.")

    by = []
    for a in [c for c in conds if c != "baseline"]:
        if "baseline" not in conds:
            break
        diff = M["vulnerable"][a] - M["vulnerable"]["baseline"]
        row = {"condition": a}
        for j, c in enumerate(cwes):
            cols = [k for k, t in enumerate(tasks) if task_cwe[t] == c]
            row[c] = stats.nanmean(diff[:, cols])
        by.append(row)
    if by:
        table("T14_effect_by_cwe", pd.DataFrame(by), "Change in introduction rate vs baseline, by class")
        bm = []
        for i, m in enumerate(models):
            row = {"model": name(m), "baseline_ir": stats.nanmean(M["vulnerable"]["baseline"][i])}
            for a in [c for c in conds if c != "baseline"]:
                row[a] = stats.nanmean(M["vulnerable"][a][i] - M["vulnerable"]["baseline"][i])
            bm.append(row)
        table("T15_effect_by_model", pd.DataFrame(bm), "Change in introduction rate vs baseline, by model")
    if d["retrieval"]:
        q = retrieval_quality({"tasks": {t: v for t, v in d["retrieval"]["tasks"].items() if t in tasks}})
        table("T16_retrieval_quality", pd.DataFrame([{"condition": c, **v} for c, v in q.items()]),
              f"Retrieval quality: share of tasks with at least one note of the task's own class among the top "
              f"{d['retrieval'].get('top_k')} (hit@k) and mean share of on-class notes (corpus: "
              f"{d['retrieval'].get('n_docs')} notes)")
        R["retrieval_quality"] = q

    # ── 6. tiers ─────────────────────────────────────────────────────────────
    md.append("\n## 6. Model size tier\n")
    tier = np.array([MODEL_BY_TAG[m].tier if m in MODEL_BY_TAG else ("7b" if "7b" in m else "small") for m in models])
    trows = []
    for label, vals in [("knowledge K", np.nanmean(K["K"], axis=1)), ("baseline introduction rate", np.nanmean(IRt, axis=1)),
                        ("baseline secure-pass", np.nanmean(SPt, axis=1)),
                        ("residual gap (recognised cells)", np.array([stats.nanmean(np.where(rec[i] == 1, IRt[i], np.nan)) for i in range(len(models))]))]:
        small, big = vals[tier == "small"], vals[tier == "7b"]
        if len(small) and len(big):
            trows.append({"measure": label, "small_mean": stats.nanmean(small), "7b_mean": stats.nanmean(big),
                          "difference": stats.nanmean(big) - stats.nanmean(small),
                          "p_permutation": perm_two_groups(vals, tier == "7b"), "n_small": len(small), "n_7b": len(big)})
    if trows:
        table("T17_tiers", pd.DataFrame(trows), "Small (<=4B) vs ~7B models; exact permutation test over models")

    # ── 7. robustness ────────────────────────────────────────────────────────
    md.append("\n## 7. Robustness\n")
    variants = [("primary outcome", gen, "vulnerable"), ("static verdict only", gen, "vuln_static"),
                ("dynamic verdict only", gen, "vuln_dynamic"), ("greedy sample only", gen[gen.greedy], "vulnerable"),
                ("sampled only (T>0)", gen[~gen.greedy], "vulnerable"),
                ("functional answers only", gen[gen.functional == 1], "vulnerable"),
                ("placeholder credentials not counted", gen.assign(vulnerable=np.where(gen.placeholder, 0.0, gen.vulnerable)), "vulnerable")]
    rob = []
    for label, g, col in variants:
        if g.empty or not np.isfinite(g[col]).any():
            continue
        ir_t = mat(g[g.condition == "baseline"], col, "model", "task", models, tasks)
        ir_c = mat(g[g.condition == "baseline"], col, "model", "cwe", models, cwes)
        row = {"variant": label, "baseline_ir": stats.nanmean(ir_t),
               "gap_recognised": stats.nanmean(np.where(rec == 1, ir_t, np.nan))}
        fe_c, fe_t = stats.twoway_fe(ir_c, K["K"], 2000, SEED), fe_task(ir_t, rec, 2000)
        row.update(slope_K=fe_c["beta"], p_K=fe_c["p"], slope_recognises=fe_t["beta"], p_recognises=fe_t["p"])
        for a in ("reminder", "rag_dense", "rag_hybrid"):
            if a in conds:
                row["rd_" + a] = stats.nanmean(mat(g[g.condition == a], col, "model", "task", models, tasks) - ir_t)
        rob.append(row)
    table("T18_robustness", pd.DataFrame(rob), "Key results under alternative outcome definitions and subsets")

    # ── 8. cost ──────────────────────────────────────────────────────────────
    cost = gen.groupby("model").agg(generations=("task", "size"), tokens_out=("tokens_out", "sum"),
                                    seconds=("seconds", "sum"), early_stop=("early_stop", "mean")).reset_index()
    cost["model"] = cost["model"].map(name)
    cost["gpu_hours"] = cost.seconds / 3600
    md.append("\n## 8. Compute\n")
    table("T19_compute", cost[["model", "generations", "tokens_out", "gpu_hours", "early_stop"]],
          "Generation cost per model (request seconds summed over parallel slots; early_stop = share of replies cut "
          "off once the answer was complete)", 2)

    # ── scorer audit ─────────────────────────────────────────────────────────
    md.append("\n## 9. Blind audit by the scorer model\n")
    md.append(f"{config.SCORER_NAME} (`{config.SCORER_MODEL}`) judged a stratified random "
              "sample of generated answers and scored the explanations, seeing the task and the text only "
              "(rubric: `audit/SCORER_INSTRUCTIONS.md`). Its ratings do not enter any primary measure. The authors "
              "checked the ratings informally afterwards; no rating was changed.\n")
    R["scorer"] = {k: {a: b for a, b in v.items() if a != "scores"} for k, v in scored.items()}
    if "vulnerable" in scored:
        sv = scored["vulnerable"]
        arows = [{"cwe": c, **{k: v[k] for k in ("n", "tp", "fp", "fn", "tn", "agreement", "precision", "recall", "kappa")}}
                 for c, v in [("all", sv["automatic_vs_scorer"]), *sv["by_cwe"].items()]]
        table("T20_scorer_audit", pd.DataFrame(arows),
              "Automatic verdict against the scorer on the audited sample (tp = both vulnerable; fp = automatic "
              "verdict vulnerable, scorer not). The sample is stratified by automatic verdict: precision is unbiased, "
              "recall is not a population estimate")
        if "test_retest" in sv:
            md.append(f"Test-retest agreement of the scorer over two passes: kappa {fmt(sv['test_retest']['kappa'])} "
                      f"(n = {sv['test_retest']['n']}); the table uses the items on which both passes agree.")
    else:
        md.append("> Not scored yet: `python -m skgap sheets`, score the sheets, then `python -m skgap analyze` again.")
    if "explain" in scored:
        se = scored["explain"]["rubric_vs_scorer"]
        md.append(f"\nExplanations: {se['n']} scored; Spearman correlation between the scorer and the concept rubric "
                  f"{fmt(se['spearman_rho'])} (permutation p = {fmt_p(se['p'])}).")
    from .audit_human import human_results
    human = human_results(run_name)
    if human:                               # the same sample, rated by people (`python -m skgap sheets --human`)
        R["human_audit"] = human
        pairs = [("automatic verdict against scorer", human["automatic_vs_scorer"])] if human["automatic_vs_scorer"] else []
        pairs += [(f"automatic verdict against rater {r}", v) for r, v in human["automatic_vs_rater"].items()]
        pairs += [("rater " + k.replace("_", " against rater "), v) for k, v in human["between_raters"].items()]
        pairs += [(f"scorer against rater {r}", v) for r, v in human["scorer_vs_rater"].items()]
        hrows = [{"comparison": label, "n": v["n"], "agreement": v["agreement"], "kappa": v["kappa"],
                  "kappa_lo": v["kappa_ci"][0], "kappa_hi": v["kappa_ci"][1],
                  "precision": v.get("precision", float("nan")), "recall": v.get("recall", float("nan"))}
                 for label, v in pairs]
        table("T27_human_audit", pd.DataFrame(hrows),
              "The audited sample rated by human raters, blind to model, condition and verdict, beside the scorer's "
              "audit (95% interval of kappa from a bootstrap within class and automatic verdict; precision and recall "
              "of the automatic verdict against the scorer or rater). Ratings left as set for all items at once: "
              + ", ".join(f"rater {r} {n}" for r, n in human["left_as_set_in_bulk"].items()))

    # ── power statement ──────────────────────────────────────────────────────
    md.append("\n## 10. Sensitivity of the design\n")
    n_cells = int(np.isfinite(K["K"].ravel()) .sum())
    md.append(f"With {n_cells} model x CWE cells a two-sided correlation test at alpha = 0.05 has 80% power for "
              f"|rho| >= {fmt(stats.correlation_detectable(max(n_cells, 4)), 2)} "
              f"(Fisher z approximation; cells treated as independent, so this is optimistic). "
              "Simulation-based power for the fixed-effects test under the planned design is in docs/analysis_plan.md.")

    (out_dir / "results.json").write_text(json.dumps(R, indent=1, default=_json), encoding="utf-8")
    (out_dir / "report.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    if make_figures:
        try:
            from . import figures
            figures.make_all(out_dir / "figures", models=[name(m) for m in models], cwes=cwes, K=K, IRc=IRc, IRt=IRt,
                             rec=rec, tasks=tasks, task_cwe=task_cwe, tables=tables, tier=tier, synthetic=synthetic,
                             manifest=manifest)
        except Exception as exc:          # figures must never block the numbers
            print(f"WARNING: figures not produced ({type(exc).__name__}: {exc})")
    return R


def _json(o):
    if isinstance(o, (np.floating, np.integer)):
        return o.item()
    if isinstance(o, np.bool_):
        return bool(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    return str(o)


def _glmm(data: pd.DataFrame) -> dict:
    if data.K_z.isna().all() or data.vulnerable.nunique() < 2:
        return {"ok": False, "why": "no variation in the outcome or knowledge missing"}
    try:
        from statsmodels.genmod.bayes_mixed_glm import BinomialBayesMixedGLM
    except ImportError:
        return {"ok": False, "why": "statsmodels not installed"}
    try:
        dd = data.dropna(subset=["K_z", "vulnerable"]).copy()
        dd["y"] = dd.vulnerable.astype(int)
        vc = {"model": "0 + C(model)", "task": "0 + C(task)"}
        if dd.cwe.nunique() > 1:
            vc["cwe"] = "0 + C(cwe)"
        res = BinomialBayesMixedGLM.from_formula("y ~ K_z", vc, dd).fit_vb(verbose=False)
        names = list(res.model.exog_names)
        i = names.index("K_z")
        beta, sd = float(res.fe_mean[i]), float(res.fe_sd[i])
        re_sd = {n: float(math.exp(m)) for n, m in zip(res.model.vcp_names, res.vcp_mean)}
        return {"ok": True, "beta": beta, "sd": sd, "lo": beta - 1.96 * sd, "hi": beta + 1.96 * sd,
                "re_sd": re_sd, "n": int(len(dd)), "method": "statsmodels BinomialBayesMixedGLM.fit_vb"}
    except Exception as exc:
        return {"ok": False, "why": f"{type(exc).__name__}: {exc}"[:200]}


def _write_glmm_r(out_dir: Path) -> None:
    (out_dir / "glmm_exact.R").write_text(r'''# Mixed-effects logistic regression of the baseline programs, fitted by maximum likelihood
# (Laplace approximation, lme4::glmer). Replaces the variational fit quoted in report.md.
#
# Usage, from this folder:  Rscript glmm_exact.R        (needs the lme4 package)
# Writes glmm_exact_output.txt and tables/T21_mixed_model.csv.
#
# K is constant within a model x class cell and `recognises` within a model x task cell, so the
# models used in the manuscript carry random intercepts for those cells as well as for model,
# class and task. The fit without the cell-level intercepts is kept for comparison: it treats the
# programs of a cell as independent given model, class and task, and its interval is too narrow.
suppressPackageStartupMessages(library(lme4))
d <- read.csv("model_data.csv")
d$model <- factor(d$model); d$task <- factor(d$task); d$cwe <- factor(d$cwe)
d$cell_mc <- interaction(d$model, d$cwe, drop = TRUE)
d$cell_mt <- interaction(d$model, d$task, drop = TRUE)
ctl <- glmerControl(optimizer = "bobyqa", optCtrl = list(maxfun = 2e5))
SIMPLE <- "(1 | model) + (1 | cwe) + (1 | task)"
FULL   <- paste(SIMPLE, "+ (1 | cell_mc) + (1 | cell_mt)")

rows <- list()
fit <- function(label, term, re, re_label, data, subset_label) {
  m  <- glmer(as.formula(paste("vulnerable ~", term, "+", re)), data = data, family = binomial, control = ctl)
  m0 <- glmer(as.formula(paste("vulnerable ~ 1 +", re)), data = data, family = binomial, control = ctl)
  b <- fixef(m)[term]; se <- sqrt(diag(vcov(m)))[term]; a <- anova(m0, m)
  cat("\n=====", label, "=====\n"); print(summary(m)$coefficients); print(VarCorr(m))
  cat(sprintf("OR = %.3f, Wald 95%% CI %.3f to %.3f, z = %.3f, p = %.4f | LRT chisq = %.3f, p = %.4f | logLik = %.2f | singular: %s\n",
              exp(b), exp(b - 1.96 * se), exp(b + 1.96 * se), b / se, 2 * pnorm(-abs(b / se)), a$Chisq[2], a$`Pr(>Chisq)`[2],
              as.numeric(logLik(m)), isSingular(m)))
  sds <- as.data.frame(VarCorr(m))
  rows[[length(rows) + 1]] <<- data.frame(
    predictor = term, random_intercepts = re_label, programs = subset_label, n = nrow(data),
    odds_ratio = exp(b), ci_lo = exp(b - 1.96 * se), ci_hi = exp(b + 1.96 * se), z = b / se, p = 2 * pnorm(-abs(b / se)),
    lrt_chisq = a$Chisq[2], lrt_p = a$`Pr(>Chisq)`[2], logLik = as.numeric(logLik(m)),
    sd_model = sds$sdcor[sds$grp == "model"], sd_class = sds$sdcor[sds$grp == "cwe"], sd_task = sds$sdcor[sds$grp == "task"],
    sd_model_class = ifelse(any(sds$grp == "cell_mc"), sds$sdcor[sds$grp == "cell_mc"], NA),
    sd_model_task = ifelse(any(sds$grp == "cell_mt"), sds$sdcor[sds$grp == "cell_mt"], NA), row.names = NULL)
  m
}

sink("glmm_exact_output.txt", split = TRUE)
cat("R", as.character(getRversion()), "| lme4", as.character(packageVersion("lme4")), "\n")
cat("programs:", nrow(d), "| vulnerable:", sum(d$vulnerable), "| models:", nlevels(d$model), "| classes:", nlevels(d$cwe),
    "| tasks:", nlevels(d$task), "| model x class cells:", nlevels(d$cell_mc), "| model x task cells:", nlevels(d$cell_mt), "\n")
f <- droplevels(d[d$functional == 1, ])
mA <- fit("K, intercepts for model, class and task", "K_z", SIMPLE, "model, class, task", d, "all")
mB <- fit("K, with cell-level intercepts", "K_z", FULL, "model, class, task, model x class, model x task", d, "all")
cat("\nLRT, cell-level intercepts (K model):\n"); print(anova(mA, mB))
fit("recognises, intercepts for model, class and task", "recognises", SIMPLE, "model, class, task", d, "all")
fit("recognises, with cell-level intercepts", "recognises", FULL, "model, class, task, model x class, model x task", d, "all")
fit("K, with cell-level intercepts, functional programs", "K_z", FULL, "model, class, task, model x class, model x task", f, "functional")
fit("recognises, with cell-level intercepts, functional programs", "recognises", FULL,
    "model, class, task, model x class, model x task", f, "functional")
sink()
write.csv(do.call(rbind, rows), file.path("tables", "T21_mixed_model.csv"), row.names = FALSE)
''', encoding="utf-8")
