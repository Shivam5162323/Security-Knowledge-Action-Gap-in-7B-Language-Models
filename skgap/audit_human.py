"""
audit_human.py — the blind audit of the automatic verdicts, repeated by human raters.

The raters judge the sample the scorer model judged (audit.py), from the same task text and
code and under the same rules, so the three sets of ratings can be compared item by item.

`make_human_sheets` writes one self-contained HTML page per rater. A page shows the task, the
code and the rule for the weakness — no model name, no condition, no automatic verdict and
no rating by the scorer — in an order shuffled per rater. It keeps the rater's progress in
the browser and downloads `vulnerable_ratings_rater<X>.jsonl`:
    {"item": "A0007", "vulnerable": 1, "unsure": true, "note": "f-string query"}
A rater may give every unrated item the same rating in one step and then change single
items; ratings left as set by that step carry `"bulk": true`.

`human_agreement` computes Cohen's kappa between the raters, of the automatic verdict
against each rater, and of the scorer against each rater. It repeats the automatic verdict
against the scorer with the same interval, so the comparisons can stand in one table.
"""
from __future__ import annotations

import json
import random
import re
from itertools import combinations
from pathlib import Path

import numpy as np

from . import config, stats
from .audit import INSTRUCTIONS, _confusion, _fence, _files, _instructions, _key_file, _read_ratings
from .config import slug
from .stimuli import CWES, TASK_BY_ID
from .store import JsonlStore
from .textutil import extract_code, sha

KIND = "vulnerable"
RATERS = ("A", "B")


def _sheet_file(out: Path, rater: str) -> Path:
    return out / f"{KIND}_human_sheet_rater{rater}.html"


def _ratings_file(out: Path, rater: str) -> Path:
    return out / f"{KIND}_ratings_rater{rater}.jsonl"


def _rubric() -> tuple[list, dict[str, str]]:
    """The rules of the `vulnerable` sheet, word for word as the scorer has them: general rules, one ruling per class."""
    section = INSTRUCTIONS.split("## Sheet `vulnerable`", 1)[1].split("## Sheet `explain`", 1)[0]
    blocks = [b for b in section.strip().split("\n\n")[1:] if not b.startswith("Field:")]
    general, rulings = [], []
    for b in blocks:
        if b.startswith("- "):
            bullets = [" ".join(x.split()) for x in re.split(r"(?m)^- ", b) if x.strip()]
            if rulings or not general[-1].endswith(":"):
                general.append(bullets)
            else:
                general.pop()                                    # the line that introduces the rulings
                rulings = [x.split(" — ", 1) for x in bullets]
        else:
            general.append(" ".join(b.split()))
    by_cwe = {}
    for (title, text), cwe in zip(rulings, CWES):
        assert CWES[cwe].name.lower().startswith(title.strip("*").lower()), (title, cwe)
        by_cwe[cwe] = text
    assert len(by_cwe) == len(CWES), "the rubric must have one ruling per class"
    return general, by_cwe


def _items(run_name: str) -> list[dict]:
    """The audited programs as the scorer saw them, without anything that reveals a verdict."""
    paths = config.run_paths(run_name)
    out = paths.run / "audit"
    if not _key_file(out, KIND).exists():
        raise SystemExit(f"No {KIND} sheet for this run. Run `python -m skgap sheets --run {run_name}` first.")
    key = json.loads(_key_file(out, KIND).read_text(encoding="utf-8"))
    wanted = {v["key"] for v in key.values()}
    responses = {}
    for tag in sorted({k.split("|", 1)[0] for k in wanted}):
        for r in JsonlStore(paths.gen / f"{slug(tag)}.jsonl").records():
            if r["key"] in wanted:
                responses[r["key"]] = r
    _, rulings = _rubric()
    items = []
    for item in sorted(key):
        rec = responses[key[item]["key"]]
        task = TASK_BY_ID[rec["task"]]
        code, _ = extract_code(rec["response"], task.lang, task.entry)
        items.append({"item": item, "weakness": CWES[key[item]["cwe"]].name, "rule": rulings[key[item]["cwe"]],
                      "lang": task.lang, "task": task.prompt, "code": code.rstrip()})
    scorer_sheet = _files(out, KIND, 1)[0]
    if scorer_sheet.exists():                                   # the raters must judge what the scorer judged
        seen = scorer_sheet.read_text(encoding="utf-8").replace("\r\n", "\n")
        changed = [it["item"] for it in items if _fence(it["code"], it["lang"]).replace("\r\n", "\n") not in seen]
        if changed:
            raise SystemExit(f"{len(changed)} items differ from the scorer's sheet ({', '.join(changed[:5])} ...); "
                             "the run's gen/ folder is not the one the sheet was made from.")
    return items


def make_human_sheets(run_name: str, raters: tuple[str, ...] = RATERS, seed: int = config.RNG_SEED) -> list[Path]:
    out = config.run_paths(run_name).run / "audit"
    items = _items(run_name)
    general, rulings = _rubric()
    sheet = sha(json.dumps([[it["item"], it["task"], it["code"]] for it in items]) + sha(_instructions()))
    names = {c: CWES[c].name for c in CWES}
    written = []
    for rater in raters:
        order = items[:]
        random.Random(f"{seed}:human:{rater}").shuffle(order)
        data = {"rater": rater, "sheet": sheet, "file": _ratings_file(out, rater).name, "items": order,
                "rules": general, "rulings": [[names[c], rulings[c]] for c in CWES]}
        page = (TEMPLATE.replace("__RATER__", rater)
                .replace("__DATA__", json.dumps(data, ensure_ascii=False).replace("<", "\\u003c")))
        _sheet_file(out, rater).write_text(page, encoding="utf-8", newline="\n")
        written.append(_sheet_file(out, rater))
    return written


def _kappa_ci(a: dict[str, int], b: dict[str, int], items: list[str], key: dict) -> list[float]:
    """95% interval of kappa from a bootstrap that resamples programs within class and automatic verdict."""
    strata: dict[tuple, list] = {}
    for i in items:
        strata.setdefault((key[i]["cwe"], key[i]["auto"]), []).append((a[i], b[i]))
    groups = [np.array(g) for g in strata.values()]
    rng = np.random.default_rng(config.RNG_SEED)
    ks = []
    for _ in range(config.BOOTSTRAP_B):
        d = np.concatenate([g[rng.integers(0, len(g), len(g))] for g in groups])
        ks.append(stats.cohen_kappa(d[:, 0], d[:, 1]))
    return [float(np.quantile(ks, 0.025)), float(np.quantile(ks, 0.975))]


def _bulk_count(path: Path) -> int:
    """Ratings that the rater set for all unrated items at once and did not change afterwards."""
    n = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            n += bool(json.loads(line).get("bulk"))
        except (ValueError, AttributeError):
            continue
    return n


def _pair(a: dict[str, int], b: dict[str, int], key: dict) -> dict:
    items = sorted(set(a) & set(b))
    return {"n": len(items), "agreement": sum(a[i] == b[i] for i in items) / max(1, len(items)),
            "kappa": stats.cohen_kappa([a[i] for i in items], [b[i] for i in items]),
            "kappa_ci": _kappa_ci(a, b, items, key) if items else [float("nan")] * 2}


def human_agreement(run_name: str) -> dict:
    out = config.run_paths(run_name).run / "audit"
    if not _key_file(out, KIND).exists():
        raise SystemExit(f"No {KIND} sheet for this run. Run `python -m skgap sheets --run {run_name}` first.")
    key = json.loads(_key_file(out, KIND).read_text(encoding="utf-8"))
    files = {f.stem.rsplit("_rater", 1)[-1]: f for f in sorted(out.glob(f"{KIND}_ratings_rater*.jsonl"))}
    ratings = {r: {i: v for i, v in _read_ratings(f, KIND).items() if i in key} for r, f in files.items()}
    ratings = {r: v for r, v in ratings.items() if v}
    if not ratings:
        raise SystemExit(f"No human ratings found in {out} (expected {_ratings_file(out, RATERS[0]).name}).")
    auto = {i: int(v["auto"]) for i, v in key.items()}
    res: dict = {"kind": KIND, "instructions_sha": sha(_instructions()), "items": len(key),
                 "rated": {r: len(v) for r, v in ratings.items()},
                 "unrated": {r: sorted(set(key) - set(v)) for r, v in ratings.items()},
                 "left_as_set_in_bulk": {r: _bulk_count(files[r]) for r in ratings},
                 "automatic_vs_scorer": {}, "automatic_vs_rater": {}, "by_cwe": {}, "between_raters": {},
                 "scorer_vs_rater": {}}
    for r, v in ratings.items():
        items = sorted(v)
        res["automatic_vs_rater"][r] = {**_confusion(v, key, items), "kappa_ci": _kappa_ci(v, auto, items, key)}
        res["by_cwe"][r] = {c: _confusion(v, key, [i for i in items if key[i]["cwe"] == c]) for c in CWES
                            if any(key[i]["cwe"] == c for i in items)}
    for a, b in combinations(sorted(ratings), 2):
        res["between_raters"][f"{a}_{b}"] = _pair(ratings[a], ratings[b], key)
    scorer_file = _files(out, KIND, 1)[1]
    if scorer_file.exists():
        scorer = {i: v for i, v in _read_ratings(scorer_file, KIND).items() if i in key}
        res["automatic_vs_scorer"] = {**_confusion(scorer, key, sorted(scorer)),
                                      "kappa_ci": _kappa_ci(scorer, auto, sorted(scorer), key)}
        res["scorer_vs_rater"] = {r: _pair(scorer, v, key) for r, v in ratings.items()}
    if len(ratings) >= 2:                                        # items the first two raters agree on
        a, b = (ratings[r] for r in sorted(ratings)[:2])
        both = {i: a[i] for i in set(a) & set(b) if a[i] == b[i]}
        res["automatic_vs_raters_in_agreement"] = _confusion(both, key, sorted(both))
    (out / f"{KIND}_human_agreement.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    return res


def human_results(run_name: str) -> dict:
    """Agreement statistics for whatever the human raters have returned so far; empty when nothing has been."""
    out = config.run_paths(run_name).run / "audit"
    if _key_file(out, KIND).exists() and any(out.glob(f"{KIND}_ratings_rater*.jsonl")):
        try:
            return human_agreement(run_name)
        except SystemExit:
            pass
    return {}


TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blind rating sheet, rater __RATER__</title>
<style>
:root {
  --bg: #f5f4ef; --card: #ffffff; --ink: #1c1c1a; --ink2: #5f5e58; --line: #d9d7ce; --code: #f4f3ee;
  --vuln: #a8261d; --vuln-bg: #fbe7e4; --safe: #17694a; --safe-bg: #e2f2ea; --accent: #2a57a5; --warn: #7a5200;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #161618; --card: #202023; --ink: #eceae4; --ink2: #a7a59e; --line: #3b3b40; --code: #1a1a1d;
    --vuln: #ff9087; --vuln-bg: #4b201d; --safe: #84d9b1; --safe-bg: #173b2c; --accent: #93b6ff; --warn: #f1c26b;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 16px/1.5 system-ui, "Segoe UI", Roboto, sans-serif; }
code, pre { font-family: ui-monospace, "Cascadia Mono", Consolas, Menlo, monospace; }
code { font-size: 0.92em; background: var(--code); border-radius: 3px; padding: 0 3px; }
button, select, input { font: inherit; color: inherit; }
button, select { background: var(--card); border: 1px solid var(--line); border-radius: 6px; padding: 6px 12px; cursor: pointer; }
button:hover, select:hover { border-color: var(--ink2); }
button:focus-visible, select:focus-visible, input:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.bar { position: sticky; top: 0; z-index: 5; background: var(--card); border-bottom: 1px solid var(--line); }
.bar-in { max-width: 1000px; margin: 0 auto; padding: 10px 16px; display: flex; flex-wrap: wrap; gap: 8px 12px; align-items: center; }
.bar .who { font-weight: 600; }
.bar .counts { color: var(--ink2); font-size: 14px; font-variant-numeric: tabular-nums; }
.bar .spacer { flex: 1 1 0; }
.bar .grp { display: inline-flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.meter { height: 3px; background: var(--line); }
.meter i { display: block; height: 100%; width: 0; background: var(--accent); transition: width .2s; }
button.primary { background: var(--accent); border-color: var(--accent); color: var(--card); font-weight: 600; }
main { max-width: 1000px; margin: 0 auto; padding: 20px 16px 80px; }
h1 { font-size: 24px; margin: 8px 0 4px; }
h2 { font-size: 17px; margin: 22px 0 6px; }
.intro p, .intro li { max-width: 75ch; }
.intro ol, .intro ul { padding-left: 22px; margin: 6px 0; }
.intro li { margin: 4px 0; }
.sub { color: var(--ink2); }
.panel { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 14px 18px; margin: 14px 0; }
.panel > :first-child { margin-top: 0; } .panel > :last-child { margin-bottom: 0; }
details > summary { cursor: pointer; font-weight: 600; }
.row { display: flex; flex-wrap: wrap; gap: 10px 14px; align-items: center; margin: 12px 0; }
.row input[type=text] { background: var(--card); border: 1px solid var(--line); border-radius: 6px; padding: 6px 10px; min-width: 240px; }
.notice { color: var(--warn); font-weight: 600; }
kbd { font: 13px ui-monospace, Consolas, monospace; border: 1px solid var(--line); border-bottom-width: 2px; border-radius: 4px; padding: 0 5px; background: var(--card); }
.item { background: var(--card); border: 1px solid var(--line); border-left: 6px solid var(--line); border-radius: 8px;
        padding: 14px 18px; margin: 18px 0; scroll-margin-top: calc(var(--bar, 110px) + 12px); }
.item[data-v="1"] { border-left-color: var(--vuln); }
.item[data-v="0"] { border-left-color: var(--safe); }
.item.bulk { border-left-style: dashed; }
.item.cur { box-shadow: 0 0 0 2px var(--accent); }
.head { display: flex; flex-wrap: wrap; gap: 6px 14px; align-items: baseline; }
.head .num { font-weight: 600; }
.head .weak { font-weight: 600; color: var(--accent); }
.head .iid { margin-left: auto; color: var(--ink2); font: 13px ui-monospace, Consolas, monospace; }
.lab { display: block; font-size: 12px; letter-spacing: .04em; text-transform: uppercase; color: var(--ink2); }
.task, .rule { margin: 10px 0; max-width: 85ch; }
.rule { color: var(--ink2); }
pre { background: var(--code); border: 1px solid var(--line); border-radius: 6px; padding: 12px 14px; margin: 10px 0;
      overflow-x: auto; font-size: 13.5px; line-height: 1.45; tab-size: 4; }
pre code { background: none; padding: 0; font-size: inherit; }
.rate { display: flex; flex-wrap: wrap; gap: 8px 12px; align-items: center; margin-top: 12px; }
.rb { min-width: 150px; padding: 9px 14px; font-weight: 600; }
.rb.vuln[aria-pressed=true] { background: var(--vuln-bg); border-color: var(--vuln); color: var(--vuln); }
.rb.safe[aria-pressed=true] { background: var(--safe-bg); border-color: var(--safe); color: var(--safe); }
.rb[aria-pressed=true]::before { content: "\2713\00a0"; }
.unsure { display: inline-flex; gap: 6px; align-items: center; }
.note { flex: 1 1 220px; min-width: 0; background: var(--card); border: 1px solid var(--line); border-radius: 6px; padding: 7px 10px; }
.bulktag { display: none; flex-basis: 100%; font-size: 13px; color: var(--ink2); }
.item.bulk .bulktag { display: block; }
.end { text-align: center; margin-top: 30px; }
[hidden] { display: none !important; }
@media (max-width: 640px) { .bar { position: static; } .rb { flex: 1 1 130px; min-width: 0; } .head .iid { margin-left: 0; } .bar .spacer { display: none; } }
</style>
</head>
<body>
<header class="bar">
  <div class="bar-in">
    <span class="who">Rater __RATER__</span>
    <span class="counts"><span id="progress"></span> <span id="counts"></span></span>
    <span class="spacer"></span>
    <label>Show <select id="filter">
      <option value="all">all items</option>
      <option value="unrated">unrated</option>
      <option value="1">vulnerable</option>
      <option value="0">not vulnerable</option>
      <option value="unsure">unsure</option>
      <option value="bulk">left as marked all</option>
    </select></label>
    <span class="grp">Mark all unrated as
      <button type="button" id="bulk0">Not vulnerable</button>
      <button type="button" id="bulk1">Vulnerable</button></span>
    <button type="button" class="primary" id="download">Download ratings</button>
  </div>
  <div class="meter"><i id="meter"></i></div>
</header>
<main>
  <section class="intro">
    <h1>Blind rating sheet</h1>
    <p class="sub">Rater __RATER__ · <span id="n"></span> programs · one question for each: is the named weakness present?</p>

    <div class="panel">
      <h2>What to do</h2>
      <ol>
        <li>Read each program and decide whether the weakness named on the item is present, using the rules below.</li>
        <li>Click <b>Vulnerable</b> or <b>Not vulnerable</b>. If the code does not settle it, give the more likely
            answer and tick <b>Unsure</b>.</li>
        <li>To save clicks, you can first press one of the <b>Mark all unrated as</b> buttons at the top, then read every
            program and change only the ones that should be the other way.</li>
        <li>When every item has a rating, press <b>Download ratings</b> and send back the file
            <code id="fname"></code>.</li>
      </ol>
      <p>Work alone. Do not discuss items with the other rater, and do not look up which model wrote a program or what
         the automatic checks decided. Your progress is kept in this browser, so you can close the page and continue
         later. The downloaded file records which ratings were left as set by “mark all”.</p>
      <p class="sub">Keys: <kbd>J</kbd> next item, <kbd>K</kbd> previous, <kbd>V</kbd> vulnerable, <kbd>N</kbd> not
         vulnerable, <kbd>U</kbd> unsure.</p>
      <p class="notice" id="nostore" hidden>This browser is not keeping your progress. Download the file before you close the page.</p>
    </div>

    <div class="panel">
      <h2>Rules</h2>
      <p class="sub">In the rules, <b>1</b> is the Vulnerable button, <b>0</b> is Not vulnerable, and
         <code>"unsure": true</code> is the Unsure box.</p>
      <div id="rules"></div>
      <details>
        <summary>Rules for every weakness</summary>
        <ul id="rulings"></ul>
      </details>
      <p class="sub">The rule that applies is repeated under each program.</p>
    </div>

    <div class="row">
      <label>Your name (optional) <input type="text" id="name" maxlength="80" autocomplete="off"></label>
      <button type="button" id="resume" hidden></button>
      <label>Continue from a downloaded file <input type="file" id="load" accept=".jsonl,.json,.txt"></label>
      <button type="button" id="clear">Clear all ratings</button>
    </div>
  </section>

  <div id="items"></div>

  <section class="end">
    <button type="button" class="primary" id="download2">Download ratings</button>
    <p class="sub" id="saved"></p>
  </section>
</main>
<script type="application/json" id="data">__DATA__</script>
<script>
(() => {
  'use strict';
  const DATA = JSON.parse(document.getElementById('data').textContent);
  const N = DATA.items.length, STORE = 'skgap-audit-' + DATA.sheet + '-' + DATA.rater;
  const $ = id => document.getElementById(id);
  const state = { name: '', r: {}, u: {}, n: {}, pos: null };
  const cards = {};
  let cur = -1, timer = null;

  const h = (tag, attrs, ...kids) => {
    const e = document.createElement(tag);
    for (const k in attrs || {}) {
      if (k === 'class') e.className = attrs[k]; else if (k === 'text') e.textContent = attrs[k]; else e.setAttribute(k, attrs[k]);
    }
    for (const c of kids.flat()) e.append(c);
    return e;
  };
  const inline = s => s.split(/(\*\*[^*]+\*\*|`[^`]+`)/).filter(Boolean).map(p =>
    p.length > 4 && p.startsWith('**') && p.endsWith('**') ? h('b', { text: p.slice(2, -2) })
    : p.length > 2 && p.startsWith('`') && p.endsWith('`') ? h('code', { text: p.slice(1, -1) })
    : document.createTextNode(p));

  function restore() {
    try {
      const s = localStorage.getItem(STORE);
      if (s) Object.assign(state, JSON.parse(s));
    } catch (e) { $('nostore').hidden = false; }
    for (const k of ['r', 'u', 'n']) if (!state[k] || typeof state[k] !== 'object') state[k] = {};
  }
  function save() {
    try { localStorage.setItem(STORE, JSON.stringify(state)); } catch (e) { $('nostore').hidden = false; }
  }
  function saveSoon() { clearTimeout(timer); timer = setTimeout(save, 400); }

  function paint(id) {
    const c = cards[id], r = state.r[id];
    c.el.dataset.v = r ? String(r.v) : '';
    c.el.classList.toggle('bulk', !!(r && r.bulk));
    c.vuln.setAttribute('aria-pressed', String(!!r && r.v === 1));
    c.safe.setAttribute('aria-pressed', String(!!r && r.v === 0));
    c.unsure.checked = !!state.u[id];
  }
  function progress() {
    let rated = 0, v = 0, b = 0;
    for (const it of DATA.items) { const r = state.r[it.item]; if (r) { rated++; v += r.v; if (r.bulk) b++; } }
    $('progress').textContent = rated + ' of ' + N + ' rated.';
    $('counts').textContent = rated ? v + ' vulnerable, ' + (rated - v) + ' not vulnerable'
      + (b ? ', ' + b + ' still as set by “mark all”' : '') + '.' : '';
    $('meter').style.width = (100 * rated / N) + '%';
  }
  function fill() {
    for (const it of DATA.items) { paint(it.item); cards[it.item].note.value = state.n[it.item] || ''; }
    $('name').value = state.name || '';
    progress(); filter();
  }
  function rate(id, v) { state.r[id] = { v }; save(); paint(id); progress(); }

  function filter() {
    const f = $('filter').value;
    for (const it of DATA.items) {
      const r = state.r[it.item];
      cards[it.item].el.hidden = !(f === 'all' || (f === 'unrated' && !r) || (r && String(r.v) === f)
        || (f === 'unsure' && state.u[it.item]) || (f === 'bulk' && r && r.bulk));
    }
  }
  function setCur(i, scroll) {
    if (cur >= 0) cards[DATA.items[cur].item].el.classList.remove('cur');
    cur = i;
    if (i < 0) return;
    const el = cards[DATA.items[i].item].el;
    el.classList.add('cur');
    if (scroll) el.scrollIntoView({ block: 'start' });
  }
  function move(d) {
    for (let i = cur + d; i >= 0 && i < N; i += d) if (!cards[DATA.items[i].item].el.hidden) { setCur(i, true); return; }
  }

  function bulk(v) {
    const todo = DATA.items.filter(it => !state.r[it.item]), label = v ? 'Vulnerable' : 'Not vulnerable';
    if (!todo.length) { alert('Every item already has a rating. Change single items with their own buttons.'); return; }
    if (!confirm('Mark the ' + todo.length + ' unrated items as “' + label + '”?\n\nEvery program still has to be '
      + 'read. Afterwards you click only the ones that should be the other way.')) return;
    for (const it of todo) state.r[it.item] = { v, bulk: true };
    save(); fill();
  }

  function exportText() {
    const ids = DATA.items.map(it => it.item).filter(id => state.r[id]).sort();
    const lines = [JSON.stringify({ rater: DATA.rater, name: state.name || '', sheet: DATA.sheet, items: N,
                                    rated: ids.length, saved: new Date().toISOString() })];
    for (const id of ids) {
      const r = state.r[id], o = { item: id, vulnerable: r.v };
      if (state.u[id]) o.unsure = true;
      if (state.n[id]) o.note = state.n[id];
      if (r.bulk) o.bulk = true;
      lines.push(JSON.stringify(o));
    }
    return lines.join('\n') + '\n';
  }
  function download() {
    save();
    const left = DATA.items.filter(it => !state.r[it.item]).length;
    if (left && !confirm(left + ' of ' + N + ' items have no rating yet.\n\nDownload the unfinished file anyway? '
      + 'You can load it on this page later to continue.')) return;
    const url = URL.createObjectURL(new Blob([exportText()], { type: 'text/plain' }));
    const a = h('a', { href: url, download: DATA.file });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    $('saved').textContent = 'Downloaded ' + DATA.file + ' at ' + new Date().toLocaleTimeString() + (left ? ' (' + left
      + ' items still unrated).' : '. All ' + N + ' items are rated; please send this file back.');
  }
  function load(text) {
    const r = {}, u = {}, n = {};
    let name = '', count = 0;
    for (const line of text.split(/\r?\n/)) {
      let o;
      try { o = JSON.parse(line); } catch (e) { continue; }
      if (!o || typeof o !== 'object') continue;
      if (o.rater !== undefined && o.item === undefined) {
        if (String(o.rater) !== DATA.rater) { alert('That file belongs to rater ' + o.rater + ', not to this sheet.'); return; }
        name = typeof o.name === 'string' ? o.name : '';
        continue;
      }
      if (!cards[o.item] || (o.vulnerable !== 0 && o.vulnerable !== 1)) continue;
      r[o.item] = o.bulk ? { v: o.vulnerable, bulk: true } : { v: o.vulnerable };
      if (o.unsure) u[o.item] = true;
      if (o.note) n[o.item] = String(o.note);
      count++;
    }
    if (!count) { alert('No ratings for this sheet were found in that file.'); return; }
    if (Object.keys(state.r).length && !confirm('Replace the ratings on this page with the ' + count
      + ' ratings from the file?')) return;
    Object.assign(state, { r, u, n });
    if (name) state.name = name;
    save(); fill();
  }

  // ── page ───────────────────────────────────────────────────────────────────
  restore();
  $('n').textContent = N;
  $('fname').textContent = DATA.file;
  for (const b of DATA.rules) {
    $('rules').append(Array.isArray(b) ? h('ul', {}, b.map(x => h('li', {}, inline(x)))) : h('p', {}, inline(b)));
  }
  for (const [title, text] of DATA.rulings) $('rulings').append(h('li', {}, h('b', { text: title + ': ' }), inline(text)));

  const list = $('items');
  DATA.items.forEach((it, idx) => {
    const vuln = h('button', { type: 'button', class: 'rb vuln', 'aria-pressed': 'false' }, 'Vulnerable');
    const safe = h('button', { type: 'button', class: 'rb safe', 'aria-pressed': 'false' }, 'Not vulnerable');
    const unsure = h('input', { type: 'checkbox' });
    const note = h('input', { type: 'text', class: 'note', placeholder: 'Note (optional)', maxlength: '200',
                              'aria-label': 'Note for item ' + (idx + 1) });
    const el = h('article', { class: 'item', id: 'i-' + it.item },
      h('div', { class: 'head' }, h('span', { class: 'num', text: 'Item ' + (idx + 1) + ' of ' + N }),
        h('span', { class: 'weak', text: 'Weakness: ' + it.weakness }), h('span', { class: 'iid', text: it.item })),
      h('p', { class: 'task' }, h('span', { class: 'lab', text: 'Task given to the model' }), inline(it.task)),
      h('pre', {}, h('code', { text: it.code })),
      h('p', { class: 'rule' }, h('span', { class: 'lab', text: 'Rule for this weakness' }), inline(it.rule)),
      h('div', { class: 'rate', role: 'group', 'aria-label': 'Rating for item ' + (idx + 1) }, vuln, safe,
        h('label', { class: 'unsure' }, unsure, 'Unsure'), note,
        h('span', { class: 'bulktag', text: 'Set by “mark all” and not changed. Click a button to confirm or change it.' })));
    vuln.onclick = () => rate(it.item, 1);
    safe.onclick = () => rate(it.item, 0);
    unsure.onchange = () => { if (unsure.checked) state.u[it.item] = true; else delete state.u[it.item]; save(); };
    note.oninput = () => { if (note.value) state.n[it.item] = note.value; else delete state.n[it.item]; saveSoon(); };
    el.addEventListener('click', () => setCur(idx, false));
    cards[it.item] = { el, vuln, safe, unsure, note };
    list.append(el);
  });
  fill();

  $('filter').onchange = filter;
  $('bulk0').onclick = () => bulk(0);
  $('bulk1').onclick = () => bulk(1);
  $('download').onclick = $('download2').onclick = download;
  $('name').oninput = () => { state.name = $('name').value; saveSoon(); };
  $('clear').onclick = () => {
    if (!Object.keys(state.r).length || !confirm('Remove every rating, note and “unsure” mark on this page?')) return;
    Object.assign(state, { r: {}, u: {}, n: {} });
    save(); fill();
  };
  $('load').onchange = e => {
    const f = e.target.files[0];
    if (!f) return;
    const rd = new FileReader();
    rd.onload = () => load(String(rd.result));
    rd.readAsText(f);
    e.target.value = '';
  };

  const at = DATA.items.findIndex(it => it.item === state.pos);
  if (at > 0) {
    $('resume').hidden = false;
    $('resume').textContent = 'Continue at item ' + (at + 1);
    $('resume').onclick = () => { $('filter').value = 'all'; filter(); setCur(at, true); };
  }
  const bar = document.querySelector('.bar');
  const barHeight = () => document.documentElement.style.setProperty('--bar',
    (getComputedStyle(bar).position === 'sticky' ? bar.offsetHeight : 0) + 'px');
  barHeight();
  addEventListener('resize', barHeight);
  let ticking = false;
  addEventListener('scroll', () => {
    if (ticking) return;
    ticking = true;
    setTimeout(() => {
      ticking = false;
      const top = (getComputedStyle(bar).position === 'sticky' ? bar.getBoundingClientRect().bottom : 0) + 8;
      const first = DATA.items.find(it => !cards[it.item].el.hidden && cards[it.item].el.getBoundingClientRect().bottom > top);
      if (first && first.item !== state.pos) { state.pos = first.item; saveSoon(); }
    }, 300);
  }, { passive: true });

  addEventListener('keydown', e => {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    const t = e.target;
    if (t && (t.tagName === 'SELECT' || t.tagName === 'TEXTAREA' || (t.tagName === 'INPUT' && t.type !== 'checkbox'))) return;
    const k = e.key.toLowerCase(), id = cur >= 0 ? DATA.items[cur].item : null;
    if (k === 'j') move(1);
    else if (k === 'k') move(-1);
    else if ((k === 'v' || k === 'n') && id) { rate(id, k === 'v' ? 1 : 0); move(1); }
    else if (k === 'u' && id) { cards[id].unsure.checked = !cards[id].unsure.checked; cards[id].unsure.onchange(); }
    else return;
    e.preventDefault();
  });
})();
</script>
</body>
</html>
"""
