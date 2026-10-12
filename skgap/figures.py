"""
figures.py — publication figures (300 dpi PNG + PDF), drawn from the analysis tables.

Conventions: one sequential hue for magnitudes; at most two categorical hues
(blue / orange, validated for colour-vision deficiency) and always paired with a
second cue (marker shape, legend, direct labels); thin marks; quiet axes; text in
ink colours, never in series colours. Every figure has its numbers in tables/.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

from . import config  # noqa: E402

INK, INK2, MUTED, GRID, AXIS = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
BLUE, ORANGE = "#2a78d6", "#eb6834"
SEQ = LinearSegmentedColormap.from_list("skgap_blue", ["#f3f7fd", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5",
                                                       "#256abf", "#184f95", "#0d366b"])
plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 8, "axes.edgecolor": AXIS, "axes.labelcolor": INK2,
    "axes.titlesize": 9, "axes.titleweight": "bold", "axes.titlecolor": INK, "xtick.color": MUTED,
    "ytick.color": MUTED, "xtick.labelcolor": INK2, "ytick.labelcolor": INK2, "axes.spines.top": False,
    "axes.spines.right": False, "axes.grid": False, "legend.frameon": False, "figure.dpi": 100,
    "savefig.dpi": 300, "savefig.bbox": "tight", "pdf.fonttype": 42,
})


def _save(fig, out: Path, stem: str, synthetic: bool) -> None:
    if synthetic:
        fig.text(0.5, 0.5, "SYNTHETIC TEST DATA", color="#d03b3b", alpha=0.25, fontsize=26, rotation=20,
                 ha="center", va="center", weight="bold")
    fig.savefig(out / f"{stem}.png")
    fig.savefig(out / f"{stem}.pdf")
    plt.close(fig)


def heatmap(mat, rows, cols, title, cbar, out, stem, synthetic, vmin=0.0, vmax=1.0):
    fig, ax = plt.subplots(figsize=(1.6 + 0.62 * len(cols), 0.9 + 0.3 * len(rows)))
    data = np.ma.masked_invalid(mat)
    mesh = ax.pcolormesh(data, cmap=SEQ, vmin=vmin, vmax=vmax, edgecolors="white", linewidth=2)
    for i in range(len(rows)):
        for j in range(len(cols)):
            v = mat[i, j]
            if np.isfinite(v):
                ax.text(j + 0.5, i + 0.5, f"{v:.2f}", ha="center", va="center", fontsize=7,
                        color="white" if (v - vmin) / (vmax - vmin) > 0.55 else INK)
            else:
                ax.text(j + 0.5, i + 0.5, "–", ha="center", va="center", fontsize=7, color=MUTED)
    ax.set_xticks(np.arange(len(cols)) + 0.5, cols)
    ax.set_yticks(np.arange(len(rows)) + 0.5, rows)
    ax.invert_yaxis()
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title(title, loc="left")
    cb = fig.colorbar(mesh, ax=ax, fraction=0.035, pad=0.02)
    cb.set_label(cbar, color=INK2)
    cb.outline.set_visible(False)
    _save(fig, out, stem, synthetic)


def scatter_by_cwe(K, IR, models, cwes, tier, out, synthetic, title=True, stem="fig4_knowledge_vs_introduction"):
    n = len(cwes)
    ncol = min(4, n)
    nrow = int(np.ceil(n / ncol))
    fig, axes = plt.subplots(nrow, ncol, figsize=(1.9 * ncol, 1.9 * nrow), sharex=True, sharey=True, squeeze=False)
    for k, ax in enumerate(axes.ravel()):
        if k >= n:
            ax.set_visible(False)
            continue
        if k + ncol >= n:                     # no panel below this one: it carries the x tick labels itself
            ax.tick_params(labelbottom=True)
        for t, color, marker, label in (("small", BLUE, "o", "≤4B models"), ("7b", ORANGE, "s", "~7B models")):
            m = tier == t
            ax.scatter(K[m, k], IR[m, k], s=26, c=color, marker=marker, edgecolors="white", linewidths=0.8,
                       label=label if k == 0 else None, zorder=3)
        ax.set_title(cwes[k], loc="left", fontsize=8)
        ax.set_xlim(-0.3, 1.05)
        ax.set_ylim(-0.05, 1.05)
        ax.axhline(0, color=GRID, lw=0.6, zorder=1)
        ax.grid(color=GRID, lw=0.5, zorder=0)
    fig.supxlabel("Knowledge K (0 = guessing, 1 = perfect)", fontsize=8, color=INK2)
    fig.supylabel("Baseline introduction rate", fontsize=8, color=INK2)
    if n < nrow * ncol:                       # an empty cell of the grid holds the legend
        spare = axes.ravel()[-1]
        spare.set_visible(True)
        spare.axis("off")
        spare.legend(*axes[0, 0].get_legend_handles_labels(), loc="center", fontsize=7)
    else:
        fig.legend(loc="upper right", ncol=2, fontsize=7, bbox_to_anchor=(0.99, 1.02))
    if title:
        fig.suptitle("Knowledge vs behaviour: one point per model, one panel per class", x=0.02, ha="left", fontsize=9,
                     weight="bold", color=INK)
    fig.tight_layout()
    _save(fig, out, stem, synthetic)


def _ci(s: str):
    lo, hi = s.split("-")
    return float(lo), float(hi)


def conditions(t12, out, synthetic):
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.6), sharey=True)
    labels = list(t12["condition"])
    y = np.arange(len(labels))[::-1]
    for ax, col, title in zip(axes, ("vulnerable", "secure_pass"),
                              ("Vulnerable answers", "Secure and functional answers (secure-pass)")):
        vals = t12[col].to_numpy(dtype=float)
        cis = [_ci(s) for s in t12[col + "_ci"]]
        ax.barh(y, vals, height=0.55, color=BLUE, zorder=2)
        ax.hlines(y, [c[0] for c in cis], [c[1] for c in cis], color=INK, lw=1, zorder=3)
        for yi, v, c in zip(y, vals, cis):
            ax.text(max(c[1], v) + 0.015, yi, f"{v:.2f}", va="center", fontsize=7, color=INK)
        ax.set_yticks(y, labels)
        ax.set_xlim(0, 1.0)
        ax.set_title(title, loc="left")
        ax.set_xlabel("Share of generations")
        ax.grid(axis="x", color=GRID, lw=0.5, zorder=0)
        ax.tick_params(axis="y", length=0)
    fig.tight_layout()
    _save(fig, out, "fig5_conditions", synthetic)


def forest(t13, out, synthetic):
    outs = [("vulnerable", "Change in vulnerable answers"), ("secure_pass", "Change in secure-pass answers")]
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 0.6 + 0.3 * t13[t13.outcome == "vulnerable"].shape[0]), sharey=True)
    for ax, (o, title) in zip(axes, outs):
        d = t13[t13.outcome == o].reset_index(drop=True)
        y = np.arange(len(d))[::-1]
        ax.axvline(0, color=AXIS, lw=1, zorder=1)
        ax.hlines(y, d.ci_lo, d.ci_hi, color=BLUE, lw=2, zorder=2)
        sig = d.p_holm < config.ALPHA
        ax.scatter(d.risk_difference[sig], y[sig], s=34, c=BLUE, edgecolors="white", linewidths=0.8, zorder=3,
                   label="Holm-adjusted p < 0.05")
        ax.scatter(d.risk_difference[~sig], y[~sig], s=34, facecolors="white", edgecolors=BLUE, linewidths=1.4,
                   zorder=3, label="not significant")
        ax.set_yticks(y, d.contrast)
        ax.set_title(title, loc="left")
        ax.set_xlabel("Risk difference (95% CI)")
        ax.grid(axis="x", color=GRID, lw=0.5, zorder=0)
        ax.tick_params(axis="y", length=0)
        lim = max(0.05, float(np.nanmax(np.abs(np.r_[d.ci_lo, d.ci_hi]))) * 1.15)
        ax.set_xlim(-lim, lim)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=2, fontsize=7, bbox_to_anchor=(0.5, -0.06))
    fig.tight_layout()
    _save(fig, out, "fig6_condition_contrasts", synthetic)


def gap(t8, out, synthetic, title=True, stem="fig3_residual_gap"):
    fig, ax = plt.subplots(figsize=(7.0, 2.7))
    x = np.arange(len(t8))
    w = 0.36
    b1 = ax.bar(x - w / 2 - 0.01, t8.ir_recognised, w, color=BLUE, label="model recognises the weakness", zorder=2)
    b2 = ax.bar(x + w / 2 + 0.01, t8.ir_not_recognised, w, color=ORANGE, label="model does not recognise it", zorder=2)
    for bars in (b1, b2):
        for r in bars:
            if np.isfinite(r.get_height()):
                ax.text(r.get_x() + r.get_width() / 2, r.get_height() + 0.015, f"{r.get_height():.2f}", ha="center",
                        fontsize=6.5, color=INK)
    ax.axhline(config.GAP_MARGIN, color=INK2, lw=0.8, ls=(0, (3, 2)), zorder=1)
    ax.text(len(t8) - 0.45, config.GAP_MARGIN + 0.015, f"H1 margin {config.GAP_MARGIN:.2f}", fontsize=6.5, color=INK2, va="bottom")
    ax.set_xlim(-0.6, len(t8) + 0.25)
    ax.set_xticks(x, t8.cwe)
    ax.set_ylim(0, 1.25)                      # headroom so the legend clears the tallest bar label
    ax.set_yticks(np.arange(0, 1.01, 0.2))
    ax.set_ylabel("Baseline introduction rate")
    if title:
        ax.set_title("Residual gap: introduction rate by whether the model recognises the weakness", loc="left")
    ax.grid(axis="y", color=GRID, lw=0.5, zorder=0)
    ax.tick_params(axis="x", length=0)
    ax.legend(loc="upper left", fontsize=7, ncol=2)
    _save(fig, out, stem, synthetic)


def threshold(t11, out, synthetic):
    fig, axes = plt.subplots(2, 1, figsize=(3.6, 3.4), sharex=True)
    for ax, col, lab in zip(axes, ("rank_biserial", "p_two_sided"), ("Rank-biserial effect", "p (two-sided)")):
        ax.plot(t11.tau, t11[col], color=BLUE, lw=2, marker="o", ms=4, mec="white", mew=0.8, zorder=3)
        ax.axvline(config.KNOWLEDGE_TAU, color=INK2, lw=0.8, ls=(0, (3, 2)))
        ax.set_ylabel(lab)
        ax.grid(color=GRID, lw=0.5, zorder=0)
    axes[0].axhline(0, color=AXIS, lw=1)
    axes[1].axhline(config.ALPHA, color=AXIS, lw=1)
    axes[1].text(t11.tau.min(), config.ALPHA, " α = 0.05", fontsize=6.5, color=INK2, va="bottom")
    axes[0].text(config.KNOWLEDGE_TAU, axes[0].get_ylim()[1], f" τ = {config.KNOWLEDGE_TAU}", fontsize=6.5, color=INK2, va="top")
    axes[1].set_xlabel("Knowledge threshold τ")
    axes[0].set_title("Sensitivity to the knowledge threshold", loc="left")
    fig.tight_layout()
    _save(fig, out, "fig7_threshold_sensitivity", synthetic)


def pipeline(out, manifest, n_models, n_tasks, n_cwes, synthetic):
    prof = manifest.get("profile", {})
    n_s, conds = prof.get("n_samples", "n"), prof.get("conditions", config.CONDITIONS)
    boxes = [
        ("Stimuli (hashed with every run)",
         f"{n_tasks} tasks in {n_cwes} CWE classes; each task has a functional test,\nan attack test and a secure / insecure reference solution"),
        ("Detector validation",
         "Semgrep rules and attack tests must separate the two reference\nsolutions of a task before their verdicts are used"),
        ("Knowledge battery",
         "multiple choice · recognition (class not named) · repair: scored automatically\nexplanation: concept rubric and a blind 0–2 score by the scorer model"),
        ("Generation",
         f"{n_models} models × {n_tasks} tasks × {len(conds)} conditions × {n_s} samples\nbaseline · reminder · irrelevant notes · dense RAG · hybrid RAG · oracle RAG"),
        ("Automatic judgement of every answer",
         "functional test → attack test (dynamic) → Semgrep (static)\nvulnerable = dynamic verdict if available, else static"),
        ("Analysis",
         "H1 residual gap · H2 coupling (fixed effects, mixed model)\nH3–H5 paired condition contrasts, model as the unit"),
    ]
    fig, ax = plt.subplots(figsize=(5.6, 6.6))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, len(boxes))
    ax.axis("off")
    for i, (head, body) in enumerate(boxes):
        y = len(boxes) - 1 - i
        ax.add_patch(FancyBboxPatch((0.04, y + 0.14), 0.92, 0.72, boxstyle="round,pad=0.01,rounding_size=0.03",
                                    fc="#f3f7fd", ec=BLUE, lw=1))
        ax.text(0.07, y + 0.70, head, fontsize=8.5, weight="bold", color=INK, va="center")
        ax.text(0.07, y + 0.40, body, fontsize=7.2, color=INK2, va="center", linespacing=1.35)
        if i < len(boxes) - 1:
            ax.add_patch(FancyArrowPatch((0.5, y + 0.14), (0.5, y - 0.14), arrowstyle="-|>", mutation_scale=10,
                                         color=INK2, lw=1))
    ax.text(0.04, -0.05, f"Blind audit of the automatic verdicts and explanation scores: {config.SCORER_NAME}; "
                         f"ratings checked informally by the authors.", fontsize=7, color=INK2, va="top")
    _save(fig, out, "fig1_pipeline", synthetic)


def make_all(out: Path, *, models, cwes, K, IRc, IRt, rec, tasks, task_cwe, tables, tier, synthetic, manifest) -> None:
    out.mkdir(parents=True, exist_ok=True)
    pipeline(out, manifest, len(models), len(tasks), len(cwes), synthetic)
    heatmap(K["K"], models, cwes, "Knowledge K by model and class", "K (0 = guessing, 1 = perfect)",
            out, "fig2a_knowledge_heatmap", synthetic, vmin=0.0, vmax=1.0)
    heatmap(IRc, models, cwes, "Baseline vulnerability introduction rate", "share of vulnerable answers",
            out, "fig2b_introduction_heatmap", synthetic)
    if "T8_gap_by_cwe" in tables:
        gap(tables["T8_gap_by_cwe"], out, synthetic)
    scatter_by_cwe(K["K"], IRc, models, cwes, tier, out, synthetic)
    if "T12_conditions" in tables and len(tables["T12_conditions"]) > 1:
        conditions(tables["T12_conditions"], out, synthetic)
    if "T13_contrasts" in tables:
        forest(tables["T13_contrasts"], out, synthetic)
    if "T11_threshold_sensitivity" in tables and len(tables["T11_threshold_sensitivity"]) > 2:
        threshold(tables["T11_threshold_sensitivity"], out, synthetic)
