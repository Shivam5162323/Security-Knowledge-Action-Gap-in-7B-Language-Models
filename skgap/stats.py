"""
stats.py — inference routines used by the analysis.

The data are clustered twice: every observation belongs to a model and to a
task. Treating the 18,000 generations as independent would overstate certainty,
so nothing here does. Uncertainty comes from

  * a two-way cluster bootstrap (models and tasks resampled independently), and
  * permutation tests whose unit is the model or the (model, task) cell.

All routines take matrices indexed [model, task] or [model, CWE] whose entries
are cell means; missing cells are NaN.
"""
from __future__ import annotations

import itertools
import math

import numpy as np


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def nanmean(a) -> float:
    a = np.asarray(a, dtype=float)
    return float(np.nanmean(a)) if np.isfinite(a).any() else float("nan")


# ── two-way cluster bootstrap ─────────────────────────────────────────────────
def boot2way(mats: list[np.ndarray], fn, B: int, seed: int, level: float = 0.95) -> dict:
    """
    Percentile bootstrap for fn(mats) where all matrices share axes [row cluster, column cluster].
    Rows and columns are resampled with replacement, independently, in every replicate.
    """
    rng = np.random.default_rng(seed)
    est = fn(mats)
    r, c = mats[0].shape
    reps = np.empty(B)
    for b in range(B):
        ri, ci = rng.integers(0, r, r), rng.integers(0, c, c)
        reps[b] = fn([m[np.ix_(ri, ci)] for m in mats])
    reps = reps[np.isfinite(reps)]
    if len(reps) < B * 0.5:
        return {"est": est, "lo": float("nan"), "hi": float("nan"), "se": float("nan"), "B": int(len(reps))}
    a = (1 - level) / 2
    return {"est": float(est), "lo": float(np.quantile(reps, a)), "hi": float(np.quantile(reps, 1 - a)),
            "se": float(reps.std(ddof=1)), "B": int(len(reps)),
            "lo90": float(np.quantile(reps, 0.05)), "hi90": float(np.quantile(reps, 0.95))}


# ── permutation tests ─────────────────────────────────────────────────────────
def signflip(d, max_exact: int = 16, B: int = 20000, seed: int = 0) -> float:
    """Two-sided sign-flip test of mean(d) = 0. Exact when there are at most 2^16 sign patterns."""
    d = np.asarray(d, dtype=float)
    d = d[np.isfinite(d)]
    n = len(d)
    if n == 0 or np.allclose(d, 0):
        return 1.0
    obs = abs(d.mean())
    if n <= max_exact:
        signs = np.array(list(itertools.product((1.0, -1.0), repeat=n)))
        stats = np.abs(signs @ d) / n
        return float((stats >= obs - 1e-12).mean())
    rng = np.random.default_rng(seed)
    signs = rng.choice((1.0, -1.0), size=(B, n))
    stats = np.abs(signs @ d) / n
    return float((1 + (stats >= obs - 1e-12).sum()) / (B + 1))


def holm(pvals: list[float]) -> list[float]:
    p = np.asarray(pvals, dtype=float)
    order = np.argsort(p)
    adj = np.empty(len(p))
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, (len(p) - rank) * p[i])
        adj[i] = min(1.0, running)
    return [float(x) for x in adj]


def rankdata(a: np.ndarray) -> np.ndarray:
    a = np.asarray(a, dtype=float)
    order = np.argsort(a, kind="mergesort")
    ranks = np.empty(len(a))
    ranks[order] = np.arange(1, len(a) + 1)
    for v in np.unique(a):                     # average ranks over ties
        m = a == v
        if m.sum() > 1:
            ranks[m] = ranks[m].mean()
    return ranks


def spearman(x, y, B: int = 5000, seed: int = 0) -> dict:
    x, y = np.asarray(x, dtype=float), np.asarray(y, dtype=float)
    ok = np.isfinite(x) & np.isfinite(y)
    x, y = x[ok], y[ok]
    n = len(x)
    if n < 4 or np.all(x == x[0]) or np.all(y == y[0]):
        return {"rho": float("nan"), "p": float("nan"), "n": int(n)}
    rx, ry = rankdata(x), rankdata(y)
    rho = float(np.corrcoef(rx, ry)[0, 1])
    rng = np.random.default_rng(seed)
    perm = np.array([np.corrcoef(rx, rng.permutation(ry))[0, 1] for _ in range(B)])
    return {"rho": rho, "p": float((1 + (np.abs(perm) >= abs(rho) - 1e-12).sum()) / (B + 1)), "n": int(n)}


def fe_slope(y, x, factors: list, B: int = 5000, seed: int = 0) -> dict:
    """
    Slope of y on x after absorbing the given categorical factors (fixed effects).

    Inference is a Freedman-Lane permutation test on the pivotal t statistic: residuals of the
    reduced model (factors only) are permuted, the full model is refitted for every permutation,
    and |t| is compared. Using t rather than the raw slope matters: the factors use up degrees
    of freedom, and a test on the raw slope would be anti-conservative.
    """
    y, x = np.asarray(y, dtype=float), np.asarray(x, dtype=float)
    ok = np.isfinite(y) & np.isfinite(x)
    yv, xv = y[ok], x[ok]
    n = len(yv)
    cols = [np.ones(n)]
    for f in factors:
        _, codes = np.unique(np.asarray(f)[ok], return_inverse=True)
        for level in range(1, codes.max() + 1 if n else 0):
            cols.append((codes == level).astype(float))
    D = np.column_stack(cols) if n else np.zeros((0, 1))
    nan = {"beta": float("nan"), "p": float("nan"), "t": float("nan"), "n": int(n)}
    if n < D.shape[1] + 3:
        return nan
    Q, Rm = np.linalg.qr(D)
    Q = Q[:, np.abs(np.diag(Rm)) > 1e-9]                     # drop aliased dummy columns
    df = n - Q.shape[1] - 1
    resid = lambda v: v - (v @ Q) @ Q.T                      # noqa: E731  (works on rows of a matrix too)
    x_res, y_res = resid(xv), resid(yv)
    sxx = float(x_res @ x_res)
    if sxx < 1e-12 or df < 1:
        return nan

    def tstat(e):                                            # e: (..., n) residual-ised outcomes
        b = e @ x_res / sxx
        rss = np.maximum((e * e).sum(axis=-1) - b * b * sxx, 1e-300)
        return b, b * math.sqrt(sxx) / np.sqrt(rss / df)

    beta, t_obs = tstat(y_res)
    out = {"beta": float(beta), "t": float(t_obs), "n": int(n), "df_resid": int(df),
           "partial_r": float(x_res @ y_res / math.sqrt(sxx * float(y_res @ y_res))) if y_res @ y_res > 0 else float("nan")}
    if B <= 0:
        out["p"] = float("nan")
        return out
    rng = np.random.default_rng(seed)
    hits, done = 0, 0
    while done < B:
        m = min(1000, B - done)
        perms = np.array([rng.permutation(y_res) for _ in range(m)])
        _, t_perm = tstat(resid(perms))
        hits += int((np.abs(t_perm) >= abs(t_obs) - 1e-12).sum())
        done += m
    out["p"] = float((1 + hits) / (B + 1))
    return out


def twoway_fe(y: np.ndarray, x: np.ndarray, B: int = 5000, seed: int = 0, col_groups=None) -> dict:
    """
    y[r, c] = a_r + g_c + beta * x[r, c] + e   for matrices indexed [row, column].

    beta is the association between x and y after removing everything that is constant within a
    row (a model's general level) or within a column (a class's or task's general difficulty).
    With col_groups (one label per column, e.g. the CWE of each task) the row effect becomes a
    row-by-group effect: the comparison is then made within a model's handling of one class.
    """
    r_idx, c_idx = np.indices(y.shape)
    rows = r_idx.ravel()
    if col_groups is not None:
        g = np.asarray(col_groups)[c_idx.ravel()]
        rows = np.array([f"{a}|{b}" for a, b in zip(rows, g)])
    return fe_slope(y.ravel(), x.ravel(), [rows, c_idx.ravel()], B, seed)


def mann_whitney(a, b) -> dict:
    """Two-sided Mann-Whitney U with tie-corrected normal approximation and rank-biserial effect size."""
    a, b = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    a, b = a[np.isfinite(a)], b[np.isfinite(b)]
    n1, n2 = len(a), len(b)
    if n1 < 2 or n2 < 2:
        return {"U": float("nan"), "p": float("nan"), "n1": n1, "n2": n2, "rank_biserial": float("nan")}
    ranks = rankdata(np.concatenate([a, b]))
    u1 = ranks[:n1].sum() - n1 * (n1 + 1) / 2
    n = n1 + n2
    _, counts = np.unique(np.concatenate([a, b]), return_counts=True)
    tie = (counts ** 3 - counts).sum()
    sigma = math.sqrt(n1 * n2 / 12 * ((n + 1) - tie / (n * (n - 1))))
    if sigma == 0:
        return {"U": float(u1), "p": 1.0, "n1": n1, "n2": n2, "rank_biserial": 0.0}
    z = (u1 - n1 * n2 / 2 - math.copysign(0.5, u1 - n1 * n2 / 2)) / sigma
    p = math.erfc(abs(z) / math.sqrt(2))
    return {"U": float(u1), "p": float(min(1.0, p)), "n1": n1, "n2": n2,
            "rank_biserial": float(2 * u1 / (n1 * n2) - 1), "mean_a": float(a.mean()), "mean_b": float(b.mean())}


def cohen_kappa(a, b) -> float:
    a, b = np.asarray(a), np.asarray(b)
    if len(a) == 0:
        return float("nan")
    labels = np.unique(np.concatenate([a, b]))
    po = float((a == b).mean())
    pe = float(sum((a == lab).mean() * (b == lab).mean() for lab in labels))
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


# ── power ─────────────────────────────────────────────────────────────────────
def _phi(z: float) -> float:
    return 0.5 * math.erfc(-z / math.sqrt(2))


def correlation_power(n: int, rho: float, alpha: float = 0.05) -> float:
    """Two-sided power for a correlation of size rho with n pairs (Fisher z approximation)."""
    if n <= 3:
        return float("nan")
    zc = 1.959964 if alpha == 0.05 else _inv_phi(1 - alpha / 2)
    ncp = math.atanh(min(0.999999, abs(rho))) * math.sqrt(n - 3)
    return _phi(ncp - zc) + _phi(-ncp - zc)


def _inv_phi(p: float) -> float:
    lo, hi = -10.0, 10.0
    for _ in range(80):
        mid = (lo + hi) / 2
        if _phi(mid) < p:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def correlation_detectable(n: int, power: float = 0.8, alpha: float = 0.05) -> float:
    """Smallest |rho| detectable with the given power."""
    lo, hi = 0.0, 0.999
    for _ in range(60):
        mid = (lo + hi) / 2
        if correlation_power(n, mid, alpha) < power:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def simulate_design_power(n_models: int, n_cwes: int, tasks_per_cwe: int, n_samples: int, *, beta: float,
                          base_rate: float = 0.35, sd_model: float = 0.6, sd_cwe: float = 0.8, sd_task: float = 0.7,
                          sd_cell: float = 0.4, sims: int = 300, perms: int = 400, seed: int = 0,
                          alpha: float = 0.05, with_slope: bool = False):
    """
    Power of the within-model, within-class slope test (twoway_fe on model x CWE cells)
    when log-odds of a vulnerable answer fall by `beta` per SD of knowledge.
    Data are generated from a logistic model with random model, class, task and cell effects.

    with_slope=True returns (power, mean slope): the mean of the fixed-effects slopes over the
    simulated data sets, i.e. the effect size in the metric of the test itself (change in the
    introduction rate per SD of knowledge).
    """
    rng = np.random.default_rng(seed)
    logit0 = math.log(base_rate / (1 - base_rate))
    hits, slopes = 0, []
    for s in range(sims):
        k = rng.normal(size=(n_models, n_cwes)) + 0.5 * rng.normal(size=(n_models, 1)) + 0.5 * rng.normal(size=(1, n_cwes))
        k = (k - k.mean()) / k.std()
        um, uc = rng.normal(0, sd_model, (n_models, 1)), rng.normal(0, sd_cwe, (1, n_cwes))
        ut = rng.normal(0, sd_task, (1, n_cwes, tasks_per_cwe))
        ucell = rng.normal(0, sd_cell, (n_models, n_cwes))
        eta = (logit0 + um + uc + ucell - beta * k)[:, :, None] + ut
        p = 1 / (1 + np.exp(-eta))
        y = rng.binomial(n_samples, p) / n_samples
        res = twoway_fe(y.mean(axis=2), k, B=perms, seed=seed + s)
        hits += res["p"] < alpha
        slopes.append(res["beta"])
    return (hits / sims, float(np.mean(slopes))) if with_slope else hits / sims
