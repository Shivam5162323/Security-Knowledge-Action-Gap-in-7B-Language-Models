"""
Command line for the study.   python -m skgap <command> --help

Typical session (Kaggle / Colab):
    python -m skgap setup                      # install Ollama (Linux)
    python -m skgap doctor                     # check the environment
    python -m skgap all --run paper --profile paper --max-hours 11
Re-run the last command in a new session to continue; finished work is skipped.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import sys

from . import __version__, config


def _profile(args) -> config.Profile:
    return config.get_profile(args.profile, args.models, args.samples)


def _add_run_args(p, profile_default="paper"):
    p.add_argument("--run", default="paper", help="run name (folder under runs/)")
    p.add_argument("--profile", default=profile_default, choices=sorted(config.PROFILES))
    p.add_argument("--models", nargs="+", help="override the profile's model list (Ollama tags)")
    p.add_argument("--samples", type=int, help="override samples per (task, condition)")


def cmd_setup(args):
    from .llm import install_ollama
    install_ollama()


def cmd_doctor(args):
    from . import detect, functest
    from .llm import OllamaServer, gpu_count
    ok = True
    print(f"skgap {__version__}   python {sys.version.split()[0]}   platform {sys.platform}")
    for mod, need in [("numpy", True), ("pandas", True), ("requests", True), ("matplotlib", True), ("flask", True),
                      ("yaml", True), ("statsmodels", False), ("sentence_transformers", False), ("huggingface_hub", False)]:
        found = importlib.util.find_spec(mod) is not None
        ok &= found or not need
        print(f"  {'ok ' if found else ('MISSING' if need else 'absent ')} {mod}{'' if need or found else '  (optional)'}")
    sg = detect.semgrep_version()
    ok &= sg is not None
    print(f"  {'ok ' if sg else 'MISSING'} semgrep {sg or '(pip install semgrep)'}")
    cc = functest.c_compiler()
    print(f"  {'ok ' if cc else 'absent '} C compiler {cc or '(CWE-120 dynamic tests need gcc)'}"
          f"{'  AddressSanitizer: ' + ('yes' if functest.asan_available() else 'no') if cc else ''}")
    exe = shutil.which("ollama")
    srv = OllamaServer()
    print(f"  {'ok ' if exe else 'MISSING'} ollama binary {exe or '(python -m skgap setup)'}"
          f"   server: {'running ' + str(srv.version()) if srv.alive() else 'not running (started on demand)'}")
    print(f"  GPUs: {gpu_count()}")
    free = shutil.disk_usage(os.path.expanduser("~")).free / 1e9
    print(f"  free disk in home: {free:.0f} GB (largest model ~5.5 GB; models are removed after use)")
    from .retrieval import SHIPPED_CORPUS, SHIPPED_RETRIEVAL
    print(f"  {'ok ' if SHIPPED_CORPUS.exists() and SHIPPED_RETRIEVAL.exists() else 'absent '} shipped corpus and retrieval cache")
    print("environment OK" if ok else "environment has problems (see MISSING above)")
    return 0 if ok else 1


def cmd_plan(args):
    from .run import generation_jobs, knowledge_jobs
    from .stimuli import tasks_for
    p = _profile(args)
    tasks = tasks_for(p.cwes, p.tasks_per_cwe)
    nk = len(knowledge_jobs("x", tasks))
    ng = len(tasks) * len(p.conditions) * p.n_samples
    print(f"profile '{p.name}': {len(p.models)} models x {len(tasks)} tasks x {len(p.conditions)} conditions x {p.n_samples} samples")
    print(f"  per model: {nk} knowledge requests + {ng} generations")
    print(f"  total:     {len(p.models) * (nk + ng)} requests")
    hours = 0.0
    for tag in p.models:
        spec = config.MODEL_BY_TAG.get(tag)
        per = 1.6 + 0.42 * (spec.params_b if spec else 4)      # s per generation at 4 parallel slots on a T4, rough
        hours += (ng * per + nk * 0.6) / 3600
    print(f"  rough GPU time on one T4 with 4 parallel slots: ~{hours:.0f} h "
          f"(~{hours / 2:.0f} h wall-clock on Kaggle's two T4s)")


def cmd_selftest(args):
    from .selftest import print_report, run_selftest, save_report
    report = run_selftest(workers=args.workers, dynamic=not args.static_only)
    print_report(report)
    if args.run:
        save_report(report, config.run_paths(args.run).run / "validation.json")
    s = report["summary"]
    return 0 if s["static_valid"] >= s["n_tasks"] - 4 else 1


def cmd_run(args):
    from . import sync
    from .run import run, say
    profile = _profile(args)
    if args.backend == "mock" and not args.models:
        from .llm import MOCK_MODELS
        profile = config.get_profile(args.profile, MOCK_MODELS, args.samples)
    paths = config.run_paths(args.run)
    sync.hf_pull(paths, args.run, say)
    sync.restore_from_inputs(paths, args.run, args.resume_from, say)
    with sync.PeriodicPush(paths, args.run, say=say):
        results = run(args.run, profile, backend_name=args.backend, max_hours=args.max_hours, parallel=args.parallel,
                      servers=args.servers, keep_models=args.keep_models, encoder=args.encoder, force=args.force,
                      stages=tuple(args.stages))
    stopped = [r for r in results if r.get("stopped")]
    if stopped:
        say(f"NOT FINISHED: {len(stopped)} model(s) still have work left "
            f"({', '.join(sorted({str(r['stopped']) for r in stopped}))}). Re-run the same command to continue.")
        return 3
    say("generation complete for every model")
    return 0


def cmd_status(args):
    from .run import progress_table
    profile = _profile(args)
    manifest_path = config.run_paths(args.run).manifest
    if manifest_path.exists():
        m = json.loads(manifest_path.read_text(encoding="utf-8"))
        prof = m.get("profile", {})
        profile = config.Profile(prof.get("name", "?"), tuple(prof.get("models", profile.models)),
                                 tuple(prof.get("conditions", profile.conditions)), prof.get("n_samples", profile.n_samples),
                                 prof.get("tasks_per_cwe"), tuple(prof["cwes"]) if prof.get("cwes") else None)
    rows = progress_table(args.run, profile)
    print(f"{'model':<44} {'knowledge':>10} {'generation':>12} {'evaluated':>12}  done")
    for r in rows:
        print(f"{r['model']:<44} {r['knowledge']:>10} {r['generation']:>12} {r['evaluated']:>12}  {'yes' if r['complete'] else 'no'}")
    return 0 if all(r["complete"] for r in rows) else 3


def _run_models(run_name: str) -> list[str]:
    paths = config.run_paths(run_name)
    if paths.manifest.exists():
        return json.loads(paths.manifest.read_text(encoding="utf-8")).get("profile", {}).get("models", [])
    return [m.tag for m in config.MODELS]


def cmd_evaluate(args):
    from . import sync
    from .evaluate import evaluate
    from .run import say
    paths = config.run_paths(args.run)
    evaluate(args.run, _run_models(args.run), dynamic_mode=args.dynamic, workers=args.workers, force=args.force)
    sync.hf_push(paths, args.run, say)


def cmd_analyze(args):
    from .analyze import analyze
    R = analyze(args.run, make_figures=not args.no_figures)
    out = config.run_paths(args.run).analysis
    print(f"report:  {out / 'report.md'}\ntables:  {out / 'tables'}\nfigures: {out / 'figures'}")
    if R.get("synthetic"):
        print("NOTE: synthetic (mock) data - not results.")
    if not R.get("complete", True):
        print("NOTE: the run is incomplete; see section 0 of the report.")


def cmd_all(args):
    rc = cmd_run(args)
    cmd_evaluate(argparse.Namespace(run=args.run, dynamic="auto", workers=None, force=False))
    cmd_analyze(argparse.Namespace(run=args.run, no_figures=False))
    from . import sync
    z = sync.export_run(config.run_paths(args.run))
    print(f"archive: {z}")
    return rc


def cmd_corpus(args):
    from pathlib import Path
    from . import retrieval
    from .stimuli import TASKS
    retrieval.DATA_DIR.mkdir(exist_ok=True)
    docs = retrieval.load_corpus(retrieval.SHIPPED_CORPUS) if (retrieval.SHIPPED_CORPUS.exists() and not args.refetch) \
        else retrieval.build_corpus(retrieval.SHIPPED_CORPUS)
    retr = retrieval.build_retrieval(TASKS, docs, args.encoder)
    Path(retrieval.SHIPPED_RETRIEVAL).write_text(json.dumps(retr, indent=1), encoding="utf-8")
    print(f"{len(docs)} notes, corpus sha {retr['corpus_sha'][:16]}")
    print(json.dumps(retrieval.retrieval_quality(retr), indent=1))


def cmd_power(args):
    from . import stats
    print("Correlation tests (two-sided, alpha 0.05, Fisher z approximation)")
    for n in (10, 20, 35, 49, 77):
        print(f"  n = {n:>3}: power at |rho| = 0.30 / 0.50 / 0.63 = "
              f"{stats.correlation_power(n, .30):.2f} / {stats.correlation_power(n, .50):.2f} / "
              f"{stats.correlation_power(n, .63):.2f};  80% power needs |rho| >= {stats.correlation_detectable(n):.2f}")
    p = config.get_profile(args.profile)
    from .stimuli import tasks_for, CWES
    tasks = tasks_for(p.cwes, p.tasks_per_cwe)
    n_c = len({t.cwe for t in tasks})
    print(f"\nFixed-effects slope test, planned design ({len(p.models)} models x {n_c} classes x "
          f"{len(tasks) // n_c} tasks x {p.n_samples} samples), simulated")
    for beta in (0.0, 0.2, 0.35, 0.5, 0.75):
        pw, slope = stats.simulate_design_power(len(p.models), n_c, len(tasks) // n_c, p.n_samples, beta=beta,
                                                sims=args.sims, seed=1, with_slope=True)
        print(f"  log-odds change per SD of knowledge = {beta:.2f} (odds ratio {2.718281828 ** -beta:.2f}; "
              f"slope of the introduction rate {100 * slope:+.1f} points per SD): "
              f"{'false-positive rate' if beta == 0 else 'power'} {pw:.2f}")


def _kinds(args) -> tuple[str, ...]:
    from .audit import KINDS
    return KINDS if args.kind == "both" else (args.kind,)


def cmd_sheets(args):
    from .audit import make_sheets
    if args.human:
        from .audit_human import make_human_sheets
        for p in make_human_sheets(args.run):
            print("wrote", p)
        print("One page per rater, for the sample the scorer judged. Nothing in a page reveals a verdict.")
        return
    for kind in _kinds(args):
        for p in make_sheets(args.run, n=args.n, passes=args.passes, kind=kind):
            print("wrote", p)
    print(f"scorer: {config.SCORER_NAME} ({config.SCORER_MODEL}). Nothing printed here reveals a verdict.")


def cmd_agreement(args):
    from .audit import agreement, scorer_results
    if args.human:
        from .audit_human import human_agreement
        print(json.dumps(human_agreement(args.run), indent=1))
        return
    res = scorer_results(args.run) if args.kind == "both" else {args.kind: agreement(args.run, args.kind)}
    if not res:
        raise SystemExit("Nothing scored yet for this run.")
    for r in res.values():
        r.pop("scores", None)
    print(json.dumps(res, indent=1))


def cmd_merge(args):
    from pathlib import Path
    from .store import merge_run_dirs
    added = merge_run_dirs([Path(s) for s in args.sources], config.run_paths(args.run).run)
    print(f"merged {sum(added.values())} records into run '{args.run}'")


def cmd_fingerprint(args):
    from .run import design_fingerprint
    print(json.dumps(design_fingerprint(), indent=1))


def cmd_bundle(args):
    from . import sync
    print("wrote", sync.bundle_project())


def cmd_export(args):
    from . import sync
    print("wrote", sync.export_run(config.run_paths(args.run)))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="skgap", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("setup", help="install Ollama (Linux: Kaggle, Colab)").set_defaults(fn=cmd_setup)
    sub.add_parser("doctor", help="check the environment").set_defaults(fn=cmd_doctor)

    p = sub.add_parser("plan", help="size of a profile and a rough time estimate")
    _add_run_args(p)
    p.set_defaults(fn=cmd_plan)

    p = sub.add_parser("selftest", help="validate rules and attack tests on the reference solutions")
    p.add_argument("--run", help="also save the result as this run's validation.json")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--static-only", action="store_true", help="do not execute any code")
    p.set_defaults(fn=cmd_selftest)

    for cmd, fn, helptext in (("run", cmd_run, "GPU stage: knowledge battery + generation (resumable)"),
                              ("all", cmd_all, "run + evaluate + analyze + export, in one go")):
        p = sub.add_parser(cmd, help=helptext)
        _add_run_args(p)
        p.add_argument("--backend", default="ollama", choices=["ollama", "mock"])
        p.add_argument("--max-hours", type=float, help="stop cleanly after this many hours (Kaggle: 11)")
        p.add_argument("--parallel", type=int, default=4, help="concurrent requests per server")
        p.add_argument("--servers", type=int, help="Ollama servers to run (default: one per GPU)")
        p.add_argument("--keep-models", action="store_true", help="do not delete model files after use")
        p.add_argument("--stages", nargs="+", default=["knowledge", "generate"], choices=["knowledge", "generate"])
        p.add_argument("--resume-from", nargs="+", help="folders with earlier copies of this run to merge in first")
        p.add_argument("--encoder", default=config.RAG_ENCODER, help=argparse.SUPPRESS)
        p.add_argument("--force", action="store_true", help="continue although the design changed (must be documented)")
        p.set_defaults(fn=fn)

    p = sub.add_parser("status", help="how much of a run exists")
    _add_run_args(p)
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("evaluate", help="CPU stage: static scan + functional and attack tests (resumable)")
    p.add_argument("--run", default="paper")
    p.add_argument("--dynamic", default="auto", choices=["auto", "on", "off"],
                   help="execute generated code? auto = only on Kaggle/Colab or with SKGAP_ALLOW_EXEC=1")
    p.add_argument("--workers", type=int)
    p.add_argument("--force", action="store_true", help="re-judge everything")
    p.set_defaults(fn=cmd_evaluate)

    p = sub.add_parser("analyze", help="statistics, tables, figures, report.md")
    p.add_argument("--run", default="paper")
    p.add_argument("--no-figures", action="store_true")
    p.set_defaults(fn=cmd_analyze)

    p = sub.add_parser("corpus", help="rebuild the retrieval cache in data/ (optionally refetch the corpus)")
    p.add_argument("--refetch", action="store_true", help="download CWE and NVD again")
    p.add_argument("--encoder", default=config.RAG_ENCODER)
    p.set_defaults(fn=cmd_corpus)

    p = sub.add_parser("power", help="power of the planned analyses")
    p.add_argument("--profile", default="paper", choices=sorted(config.PROFILES))
    p.add_argument("--sims", type=int, default=300)
    p.set_defaults(fn=cmd_power)

    p = sub.add_parser("sheets", help=f"write blind sheets for the scorer model ({config.SCORER_NAME})")
    p.add_argument("--run", default="paper")
    p.add_argument("--kind", default="both", choices=["both", "vulnerable", "explain"])
    p.add_argument("--n", type=int, default=140, help="generated answers to audit (explanations are all scored)")
    p.add_argument("--passes", type=int, default=1, help="2 adds a reshuffled sheet for test-retest agreement")
    p.add_argument("--human", action="store_true",
                   help="write one HTML rating page per human rater for the sample the scorer judged")
    p.set_defaults(fn=cmd_sheets)

    p = sub.add_parser("agreement", help="automatic verdicts and rubric against the scorer's ratings")
    p.add_argument("--run", default="paper")
    p.add_argument("--kind", default="both", choices=["both", "vulnerable", "explain"])
    p.add_argument("--human", action="store_true", help="agreement of the human raters instead of the scorer")
    p.set_defaults(fn=cmd_agreement)

    p = sub.add_parser("merge", help="merge earlier copies of a run into the current one")
    p.add_argument("--run", default="paper")
    p.add_argument("sources", nargs="+")
    p.set_defaults(fn=cmd_merge)

    sub.add_parser("bundle", help="zip code + data for upload to Kaggle/Colab").set_defaults(fn=cmd_bundle)
    sub.add_parser("fingerprint", help="hashes of stimuli, rules and settings (record these when pre-registering)"
                   ).set_defaults(fn=cmd_fingerprint)
    p = sub.add_parser("export", help="zip a run folder")
    p.add_argument("--run", default="paper")
    p.set_defaults(fn=cmd_export)

    args = ap.parse_args(argv)
    return int(args.fn(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
