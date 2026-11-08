#!/usr/bin/env python3
"""Teste do pibit/aggregate_bateria.py (sem laboratorio). Roda com pytest ou direto."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import aggregate_bateria as agg  # noqa: E402


def _mk_run(root: Path, H: str, s: str, ts0: float, tid: str, tname: str, cost: float) -> None:
    leaf = root / H / s / "llm_web_postexploit" / H / "run01"
    (leaf / "hbgpt-trace").mkdir(parents=True, exist_ok=True)
    # labeled.csv: 1 linha de acao + 1 benigna
    lines = [
        "ts,frame.len,scenario,attack,mitre_technique_id,mitre_technique_name",
        f"{ts0},100,{H},1,{tid},{tname}",
        f"{ts0+50},60,{H},0,none,benign/background",
    ]
    (leaf / "labeled.csv").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (root / H / s / ".status").write_text("ok", encoding="utf-8")
    span = {"start_time": "2026-11-09T10:00:00+00:00", "end_time": "2026-11-09T10:05:00+00:00",
            "attributes": {"hackingbuddygpt.cost.usd": cost}}
    (leaf / "hbgpt-trace" / "log-x.jsonl").write_text(json.dumps(span) + "\n", encoding="utf-8")


def test_aggregate(tmp_path: Path):
    root = tmp_path / "bateria_x"
    _mk_run(root, "H0", "s001", 1000.0, "T1078.001", "Default Accounts", 0.50)
    _mk_run(root, "H1", "s001", 2000.0, "T1190", "Exploit Public-Facing Application", 0.30)
    out = tmp_path / "agg.csv"
    summ = root / "summary.md"
    rc = agg.main(["--root", str(root), "--out", str(out), "--summary", str(summ)])
    assert rc == 0

    import pandas as pd
    df = pd.read_csv(out)
    assert len(df) == 4                      # 2 runs x 2 linhas
    assert set(df["scenario"]) == {"H0", "H1"}
    assert int((df["attack"] == 1).sum()) == 2

    text = summ.read_text(encoding="utf-8")
    assert "Resumo da bateria" in text
    assert "T1078.001" in text and "T1190" in text
    # custo estimado = 0.50 + 0.30
    assert "US$ 0.8000" in text


def test_empty_root_errs(tmp_path: Path):
    import pytest  # type: ignore
    with pytest.raises(SystemExit):
        agg.main(["--root", str(tmp_path), "--out", str(tmp_path / "x.csv")])


def _run_all():
    import tempfile, traceback
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            if name == "test_empty_root_errs":
                continue  # precisa de pytest; pulado no modo direto
            with tempfile.TemporaryDirectory() as d:
                try:
                    fn(Path(d)); print(f"  PASS {name}")
                except Exception:  # noqa: BLE001
                    fails += 1; print(f"  FAIL {name}"); traceback.print_exc()
    print(f"\n{'OK' if fails == 0 else 'FALHOU'}: {fails} falha(s).")
    return fails


if __name__ == "__main__":
    raise SystemExit(1 if _run_all() else 0)
