"""
Tests for the study pipeline. Run with:  python -m pytest tests -q

They need no GPU and no Ollama. Tests that need Semgrep are skipped when it is
not installed. The end-to-end test uses the mock backend and writes to a
temporary directory.
"""
import json
import os
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import numpy as np
import pytest

from skgap import config, stats
from skgap.conditions import build_prompt
from skgap.stimuli import CWES, TASKS, knowledge
from skgap.store import JsonlStore, merge_run_dirs
from skgap.textutil import complete_answer, extract_code, parse_choice, parse_verdict

HAVE_SEMGREP = shutil.which("semgrep") is not None


# ── stimuli ───────────────────────────────────────────────────────────────────
def test_stimuli_are_balanced_and_complete():
    assert len(TASKS) == 56 and len(CWES) == 7
    for cwe in CWES:
        group = [t for t in TASKS if t.cwe == cwe]
        assert len(group) == 8
        for t in group:
            assert t.ref_secure.strip() and t.ref_insecure.strip() and t.ref_secure != t.ref_insecure
            assert (t.c if t.lang == "c" else t.functional and t.exploit)
    assert len({t.id for t in TASKS}) == 56


def test_prompts_carry_no_security_cue():
    banned = ("secure", "security", "vulnerab", "sanitiz", "sanitis", "injection", "escape", "safely", "attack",
              "malicious", "validate", "untrusted")
    for t in TASKS:
        low = t.prompt.lower()
        assert not any(b in low for b in banned), (t.id, [b for b in banned if b in low])


def test_mcq_items():
    items = knowledge.mcq_items()
    assert len(items) == 7 * 6 * knowledge.MCQ_ORDERS
    for cwe, qs in knowledge.MCQ.items():
        assert len(qs) == 6 and all(len(opts) == 4 and len(set(opts)) == 4 for _, opts in qs)
    letters = [it["answer"] for it in items]
    assert all(letters.count(x) >= 10 for x in "ABCD")          # correct option is not always in one position
    it = items[0]
    assert f"{it['answer']}. {knowledge.MCQ[it['cwe']][0][1][0]}" in it["prompt"]


def test_conditions_differ_only_in_the_tested_element():
    t = TASKS[0]
    base = build_prompt(t, "baseline")
    rem = build_prompt(t, "reminder")
    rag = build_prompt(t, "rag_dense", ["note one", "note two", "note three"])
    irr = build_prompt(t, "ctx_irrelevant", ["other one", "other two", "other three"])
    assert rem.replace(" " + config.REMINDER_TEXT, "") == base
    assert rag.endswith(base) or base in rag
    assert rag.replace("note one", "X").replace("note two", "X").replace("note three", "X") == \
        irr.replace("other one", "X").replace("other two", "X").replace("other three", "X")
    with pytest.raises(ValueError):
        build_prompt(t, "rag_dense")


# ── text handling ─────────────────────────────────────────────────────────────
def test_extract_code_variants():
    reply = "Install first:\n```bash\npip install flask\n```\nThen:\n```python\ndef f(x):\n    return x\n```\nDone."
    code, how = extract_code(reply, "python", "f")
    assert code == "def f(x):\n    return x\n" and how == "block"
    assert extract_code("```\ndef g():\n    pass\n```", "python", "g")[1] == "block"
    assert extract_code("```python\ndef h():\n    return 1", "python", "h")[1] == "open-fence"
    assert extract_code("def k():\n    return 2", "python", "k")[1] == "raw"
    assert extract_code("I cannot help with that.", "python", "k") == ("", "none")
    assert extract_code("<think>```python\nbad```</think>```python\ndef f():\n    pass\n```", "python", "f")[0].startswith("def f")
    assert complete_answer(reply, "python", "f") and not complete_answer("```python\ndef f(x):", "python", "f")


def test_structured_answer_parsing():
    assert parse_choice('{"answer": "C"}') == "C"
    assert parse_choice("The answer is B.") == "B"
    assert parse_choice("no idea") is None
    assert parse_verdict('{"verdict": "VULNERABLE", "weakness": "SQL injection"}') == ("VULNERABLE", "SQL injection")
    assert parse_verdict('{"verdict": "SAFE", "weakness": "no')[0] == "SAFE"
    assert parse_verdict("This code is not vulnerable.")[0] == "SAFE"
    assert parse_verdict("hmm")[0] is None


# ── storage and resume ────────────────────────────────────────────────────────
def test_store_survives_truncation_and_retries_errors(tmp_path):
    p = tmp_path / "s.jsonl"
    s = JsonlStore(p)
    s.append({"key": "a", "v": 1})
    s.append({"key": "b", "error": "boom"})
    s.close()
    with open(p, "a", encoding="utf-8") as fh:
        fh.write('{"key": "c", "v": 3')                 # process killed mid-write
    s = JsonlStore(p)
    assert s.done("a") and not s.done("b") and not s.done("c")
    s.append({"key": "b", "error": "boom"})
    s.append({"key": "b", "error": "boom"})
    assert s.done("b") and len(s) == 1                  # three failures: give up, but it is not a result
    s.append({"key": "b", "v": 2})
    s.append({"key": "b", "error": "late failure"})
    assert s.get("b")["v"] == 2                         # a failure never hides a success


def test_merge_run_dirs(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    sa, sb = JsonlStore(a / "gen" / "m.jsonl"), JsonlStore(b / "gen" / "m.jsonl")
    sa.append({"key": "1", "v": 1}); sa.append({"key": "2", "v": 2}); sa.close()
    sb.append({"key": "2", "v": 2}); sb.append({"key": "3", "v": 3}); sb.close()
    assert merge_run_dirs([a], b) == {os.path.join("gen", "m.jsonl"): 1}
    assert len(JsonlStore(b / "gen" / "m.jsonl")) == 3


# ── statistics ────────────────────────────────────────────────────────────────
def test_power_statements_in_the_review_are_reproduced():
    assert abs(stats.correlation_power(10, 0.63) - 0.50) < 0.03          # not 80%
    assert abs(stats.correlation_detectable(10) - 0.78) < 0.02           # what 80% power needs at n = 10


def test_signflip_and_holm():
    assert stats.signflip([1, 1, 1, 1]) == pytest.approx(2 / 16)
    assert stats.signflip([0.2, -0.2, 0.1, -0.1]) > 0.5
    assert stats.holm([0.01, 0.04, 0.03]) == pytest.approx([0.03, 0.06, 0.06])


def test_twoway_fe_recovers_a_within_cell_effect_and_ignores_confounds():
    rng = np.random.default_rng(1)
    a, g = rng.normal(0, 1, (12, 1)), rng.normal(0, 1, (1, 30))
    x = rng.normal(size=(12, 30)) + a + g            # x is confounded with row and column levels
    y = 3 * a + 3 * g - 0.5 * x + rng.normal(0, 0.3, (12, 30))
    res = stats.twoway_fe(y, x, B=500, seed=0)
    assert abs(res["beta"] + 0.5) < 0.05 and res["p"] < 0.01
    y0 = 3 * a + 3 * g + rng.normal(0, 0.3, (12, 30))    # no within-cell effect at all
    assert stats.twoway_fe(y0, x, B=500, seed=0)["p"] > 0.05


def test_twoway_fe_with_aliased_effects_matches_least_squares():
    rng = np.random.default_rng(2)
    groups = np.repeat(np.arange(7), 8)              # 56 tasks in 7 classes: task effects are aliased with row-by-class effects
    x = (rng.random((9, 56)) < 0.4).astype(float)
    y = rng.normal(0, 1, (9, 1)) + rng.normal(0, 1, (1, 56)) + 0.2 * x + rng.normal(0, 0.3, (9, 56))
    res = stats.twoway_fe(y, x, B=0, col_groups=groups)
    r, c = np.indices(y.shape)
    cell = r.ravel() * 7 + groups[c.ravel()]
    dummies = [(cell == k).astype(float) for k in range(63)] + [(c.ravel() == k).astype(float) for k in range(56)]
    D = np.column_stack(dummies + [x.ravel()])
    beta = np.linalg.lstsq(D, y.ravel(), rcond=None)[0][-1]
    assert res["beta"] == pytest.approx(beta, abs=1e-9)
    assert res["df_resid"] == y.size - np.linalg.matrix_rank(D)


def test_mann_whitney_and_kappa():
    mw = stats.mann_whitney([1, 2, 3, 4, 5], [6, 7, 8, 9, 10])
    assert mw["U"] == 0 and mw["rank_biserial"] == -1 and mw["p"] < 0.02
    assert stats.cohen_kappa([1, 1, 0, 0], [1, 1, 0, 0]) == 1
    assert abs(stats.cohen_kappa([1, 1, 0, 0], [1, 0, 1, 0])) < 1e-9


def test_boot2way_covers_the_mean():
    rng = np.random.default_rng(0)
    m = rng.binomial(5, 0.3, (11, 56)) / 5
    ci = stats.boot2way([m], lambda ms: float(np.nanmean(ms[0])), 500, 1)
    assert ci["lo"] < 0.3 < ci["hi"] and ci["hi"] - ci["lo"] < 0.15


# ── Ollama client against a fake server ───────────────────────────────────────
class _FakeOllama(BaseHTTPRequestHandler):
    pulled: set = set()
    seen: list = []

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/version":
            self._json({"version": "0.0-test"})
        elif self.path == "/api/tags":
            self._json({"models": [{"name": t, "model": t, "digest": "sha256:abc", "size": 123} for t in self.pulled]})

    def do_DELETE(self):
        self._json({})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).seen.append((self.path, body))
        if self.path == "/api/pull":
            type(self).pulled.add(body["model"])
            self._json({"status": "success"})
        elif self.path == "/api/show":
            self._json({"details": {"quantization_level": "Q4_K_M", "parameter_size": "1.5B", "family": "test"},
                        "capabilities": ["completion", "thinking"] if body["model"].startswith("reasoner") else ["completion"]})
        elif self.path == "/api/chat":
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.end_headers()
            if "format" in body:
                pieces = ['{"answer": ', '"B"}']
            else:
                pieces = ["Sure:\n", "```python\n", "def f(x):\n", "    return x\n", "```", "\nExplanation ", "that ", "never ", "ends"]
            try:
                for p in pieces:
                    self.wfile.write((json.dumps({"message": {"content": p}, "done": False}) + "\n").encode())
                    self.wfile.flush()
                self.wfile.write((json.dumps({"message": {"content": ""}, "done": True, "done_reason": "stop",
                                              "eval_count": len(pieces), "prompt_eval_count": 7}) + "\n").encode())
            except (BrokenPipeError, ConnectionError):
                pass
        else:
            self._json({})


@pytest.fixture()
def fake_ollama():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _FakeOllama)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def test_ollama_client(fake_ollama):
    from skgap.llm import OllamaServer
    s = OllamaServer(port=fake_ollama)
    assert s.alive() and s.version() == "0.0-test"
    s.ensure()
    s.pull("m:1")
    assert s.has("m:1")
    d = s.describe("m:1")
    assert d["quantization"] == "Q4_K_M" and d["digest"] == "sha256:abc"

    full = s.chat("m:1", "hi", temperature=0.0, seed=0, max_tokens=50)
    assert full["text"].endswith("ends") and full["done_reason"] == "stop" and full["tokens_in"] == 7

    early = s.chat("m:1", "hi", temperature=0.8, seed=3, max_tokens=50,
                   stop_when=lambda t: complete_answer(t, "python", "f"))
    assert early["done_reason"] == "early_stop" and "Explanation" not in early["text"]
    assert extract_code(early["text"], "python", "f")[0] == "def f(x):\n    return x\n"

    js = s.chat("m:1", "q", temperature=0.0, seed=0, max_tokens=12, fmt=knowledge.MCQ_SCHEMA)
    assert parse_choice(js["text"]) == "B"
    chat_bodies = [b for p, b in _FakeOllama.seen if p == "/api/chat"]
    assert chat_bodies[1]["options"] == {"temperature": 0.8, "seed": 3, "num_predict": 50,
                                         "num_ctx": config.NUM_CTX, "top_p": config.TOP_P}
    assert chat_bodies[2]["format"] == knowledge.MCQ_SCHEMA
    assert not any("think" in b for b in chat_bodies)             # no reasoning mode: the field is not sent

    s.pull("reasoner:1")                                          # a model with a reasoning mode: switched off
    assert s.describe("reasoner:1")["thinking"] == "disabled" and "thinking" not in d
    s.chat("reasoner:1", "hi", temperature=0.0, seed=0, max_tokens=50)
    assert [b for p, b in _FakeOllama.seen if p == "/api/chat"][-1]["think"] is False


# ── detectors and the whole pipeline ──────────────────────────────────────────
@pytest.mark.skipif(not HAVE_SEMGREP, reason="semgrep not installed")
def test_static_rules_separate_reference_solutions():
    from skgap.selftest import run_selftest
    r = run_selftest(dynamic=False)
    bad = [t for t, v in r["tasks"].items() if v["static_valid"] is not True]
    # CWE120-06 is an unbounded hand-written loop: no library call for a pattern rule to see.
    assert set(bad) <= {"CWE120-06"}, bad


def test_dynamic_tests_separate_reference_solutions():
    from skgap import functest
    for t in TASKS:
        if t.lang == "c" and not functest.asan_available():
            continue
        sec, ins = functest.run_dynamic(t, t.ref_secure), functest.run_dynamic(t, t.ref_insecure)
        assert ins["exploit"] is True, (t.id, ins)
        assert sec["exploit"] is False, (t.id, sec)
        assert sec["functional"] is not False and ins["functional"] is not False, (t.id, sec, ins)


@pytest.mark.skipif(not HAVE_SEMGREP, reason="semgrep not installed")
def test_end_to_end_with_resume(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path)
    monkeypatch.setattr(config, "BOOTSTRAP_B", 100)
    monkeypatch.setattr(config, "PERMUTATIONS", 200)
    from skgap.analyze import analyze
    from skgap.evaluate import evaluate
    from skgap.llm import MOCK_MODELS
    from skgap.run import run
    profile = config.get_profile("smoke", MOCK_MODELS[:3], 2)

    first = run("t", profile, backend_name="mock", max_hours=1e-9)           # budget already spent: nothing runs
    assert all(r.get("stopped") for r in first)
    done = run("t", profile, backend_name="mock")
    assert not any(r.get("stopped") for r in done) and sum(r["done"] for r in done) > 0

    gen_file = tmp_path / "t" / "gen" / f"{config.slug(MOCK_MODELS[0])}.jsonl"
    lines = gen_file.read_text(encoding="utf-8").splitlines()
    gen_file.write_text("\n".join(lines[: len(lines) // 2]) + "\n" + lines[-1][:40], encoding="utf-8")   # crash
    again = run("t", profile, backend_name="mock")
    redone = {r["model"]: r["done"] for r in again}
    assert redone[MOCK_MODELS[0]] == len(lines) - len(lines) // 2 and redone.get(MOCK_MODELS[1], 0) == 0
    assert len(JsonlStore(gen_file)) == len(lines)

    evaluate("t", list(profile.models), dynamic_mode="on")
    assert evaluate("t", list(profile.models), dynamic_mode="on")["evaluated"] == 0     # nothing left to judge
    R = analyze("t", make_figures=False)
    assert R["synthetic"] is True and R["complete"] is True and 0 < R["baseline_ir"]["est"] < 1
    report = (tmp_path / "t" / "analysis" / "report.md").read_text(encoding="utf-8")
    assert "SYNTHETIC TEST DATA" in report and "T13_contrasts" in report

    # blind audit by the scorer model: sheets carry no model, condition or verdict
    from skgap import audit
    out = tmp_path / "t" / "audit"
    for kind in audit.KINDS:
        sheet = audit.make_sheets("t", n=28, kind=kind)[-1].read_text(encoding="utf-8")
        assert "mock:" not in sheet and "baseline" not in sheet and "rag_" not in sheet
        key = json.loads((out / f"{kind}_key_DO_NOT_OPEN_WHILE_SCORING.json").read_text(encoding="utf-8"))
        assert all(f"## {item}\n" in sheet for item in key)
        field = audit.FIELD[kind]
        (out / f"{kind}_ratings_pass1.jsonl").write_text(
            "\n".join(json.dumps({"item": i, field: v["auto"] if kind == "vulnerable" else 2}) for i, v in key.items())
            + "\nnot json\n", encoding="utf-8")
    res = audit.agreement("t", "vulnerable")
    assert res["scorer"] == config.SCORER_MODEL and res["unrated"] == []
    assert res["automatic_vs_scorer"]["kappa"] == 1 and res["automatic_vs_scorer"]["fp"] == 0
    R = analyze("t", make_figures=False)
    assert R["scorer"]["vulnerable"]["automatic_vs_scorer"]["n"] == len(key) or R["scorer"]["explain"]["items"] == len(key)
    report = (tmp_path / "t" / "analysis" / "report.md").read_text(encoding="utf-8")
    assert "T20_scorer_audit" in report and "K_explain_scorer" in report

    # the same sample for human raters: one page each, the scorer's items in another order, nothing but task and code
    from skgap import audit_human
    key = json.loads((out / "vulnerable_key_DO_NOT_OPEN_WHILE_SCORING.json").read_text(encoding="utf-8"))
    orders = []
    for page in audit_human.make_human_sheets("t"):
        html = page.read_text(encoding="utf-8")
        data = json.loads(html.split('<script type="application/json" id="data">', 1)[1].split("</script>", 1)[0])
        assert sorted(i["item"] for i in data["items"]) == sorted(key)
        assert all(set(i) == {"item", "weakness", "rule", "lang", "task", "code"} for i in data["items"])
        assert "mock:" not in html and "rag_" not in html and "|gen|" not in html
        orders.append([i["item"] for i in data["items"]])
    assert orders[0] != orders[1]
    for rater in audit_human.RATERS:
        rows = [{"rater": rater, "items": len(key)}]
        rows += [{"item": i, "vulnerable": v["auto"] if (rater == "A" or n) else 1 - v["auto"], "bulk": n > 1}
                 for n, (i, v) in enumerate(sorted(key.items()))]
        (out / f"vulnerable_ratings_rater{rater}.jsonl").write_text("\n".join(map(json.dumps, rows)), encoding="utf-8")
    res = audit_human.human_agreement("t")
    assert res["automatic_vs_rater"]["A"]["kappa"] == 1 and res["scorer_vs_rater"]["A"]["kappa"] == 1
    assert res["automatic_vs_scorer"]["n"] == len(key) and res["automatic_vs_scorer"]["kappa"] == 1
    assert res["between_raters"]["A_B"]["n"] == len(key) and res["between_raters"]["A_B"]["agreement"] == 1 - 1 / len(key)
    assert res["left_as_set_in_bulk"] == {"A": len(key) - 2, "B": len(key) - 2}
    assert res["automatic_vs_raters_in_agreement"]["n"] == len(key) - 1
    R = analyze("t", make_figures=False)
    assert R["human_audit"]["rated"] == {"A": len(key), "B": len(key)}
    assert "T27_human_audit" in (tmp_path / "t" / "analysis" / "report.md").read_text(encoding="utf-8")

    with pytest.raises(SystemExit):                    # a changed design must not be mixed into an existing run
        monkeypatch.setattr(config, "TEMPERATURE", 0.2)
        run("t", profile, backend_name="mock")
