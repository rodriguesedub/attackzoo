#!/usr/bin/env python3
"""
Teste do pibit/label_mitre.py com dados sinteticos (sem laboratorio, sem motor).

Roda tanto com pytest quanto diretamente:
    python3 pibit/tests/test_label_mitre.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# importa o modulo irmao (pibit/label_mitre.py)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import label_mitre as lm  # noqa: E402


def _iso(sec: int) -> str:
    """ISO UTC a partir de um offset em segundos sobre uma base fixa."""
    base = datetime(2026, 11, 2, 14, 0, 0, tzinfo=timezone.utc)
    return base.replace(second=sec).isoformat()


def _epoch(sec: int) -> float:
    base = datetime(2026, 11, 2, 14, 0, 0, tzinfo=timezone.utc)
    return base.replace(second=sec).timestamp()


def _chat_span(sec_start: int, sec_end: int, text: str) -> dict:
    return {
        "trace_id": "t", "span_id": f"c{sec_start}", "parent_span_id": None,
        "name": "chat", "kind": "CLIENT",
        "start_time": _iso(sec_start), "end_time": _iso(sec_end),
        "attributes": {
            "gen_ai.operation.name": "chat",
            "gen_ai.output.messages": [
                {"role": "assistant", "parts": [{"type": "text", "content": text}]}
            ],
        },
        "status": {"code": "OK", "message": ""},
    }


def _tool_span(sec_start: int, sec_end: int, tool: str) -> dict:
    return {
        "trace_id": "t", "span_id": f"x{sec_start}", "parent_span_id": None,
        "name": "execute_tool", "kind": "INTERNAL",
        "start_time": _iso(sec_start), "end_time": _iso(sec_end),
        "attributes": {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": tool},
        "status": {"code": "OK", "message": ""},
    }


def _write_trace(tmp: Path) -> Path:
    spans = [
        _chat_span(0, 2, "Primeiro vou autenticar.\nMITRE: T1078.001 Default Accounts\nEnviando login."),
        _tool_span(3, 5, "HTTPRequest"),                         # janela 1 -> T1078.001
        _tool_span(5, 5, "PentestPlaybook"),                     # nao on-wire -> ignorado
        _chat_span(6, 7, "Agora enumerar servicos.\nMITRE: T1046 Network Service Discovery"),
        _tool_span(8, 10, "HTTPRequest"),                        # janela 2 -> T1046
    ]
    p = tmp / "log-20261102-140000.jsonl"
    p.write_text("\n".join(json.dumps(s) for s in spans), encoding="utf-8")
    return p


def test_extract_timeline(tmp_path: Path):
    tl = lm.extract_mitre_timeline(_write_trace(tmp_path), assume_tz="utc")
    assert len(tl) == 2, "deve emitir 1 janela por acao HTTPRequest (PentestPlaybook ignorado)"
    assert (tl[0].mitre_id, tl[0].seq, tl[0].tool) == ("T1078.001", 1, "HTTPRequest")
    assert tl[1].mitre_id == "T1046" and tl[1].mitre_name == "Network Service Discovery"
    assert tl[0].t_start == _epoch(3) and tl[0].t_end == _epoch(5)


def test_label_dataframe(tmp_path: Path):
    import pandas as pd
    tl = lm.extract_mitre_timeline(_write_trace(tmp_path), assume_tz="utc")
    df = pd.DataFrame({
        "ts": [_epoch(4), _epoch(9), _epoch(20)],   # dentro j1, dentro j2, fora
        "frame.len": [100, 200, 60],
        "ip.src": ["10.0.0.9", "10.0.0.9", "10.0.0.5"],
    })
    out = lm.label_dataframe(df, tl, scenario="H0")
    assert list(out["attack"]) == [1, 1, 0]
    assert list(out["mitre_technique_id"]) == ["T1078.001", "T1046", "none"]
    assert list(out["action_seq"]) == [1, 2, 0]
    assert set(out["scenario"]) == {"H0"} and set(out["hardening_level"]) == {"H0"}
    # colunas originais preservadas
    assert "frame.len" in out.columns and "ip.src" in out.columns


def test_empty_trace_labels_all_benign(tmp_path: Path):
    import pandas as pd
    p = tmp_path / "log-empty.jsonl"
    p.write_text("", encoding="utf-8")
    tl = lm.extract_mitre_timeline(p, assume_tz="utc")
    assert tl == []
    df = pd.DataFrame({"ts": [_epoch(4), _epoch(9)]})
    out = lm.label_dataframe(df, tl, scenario="H3")
    assert list(out["attack"]) == [0, 0]
    assert set(out["mitre_technique_id"]) == {"none"}


def _run_all():
    import tempfile
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            with tempfile.TemporaryDirectory() as d:
                try:
                    fn(Path(d))
                    print(f"  PASS {name}")
                except AssertionError as e:
                    failures += 1
                    print(f"  FAIL {name}: {e}")
                except Exception as e:  # noqa: BLE001
                    failures += 1
                    print(f"  ERROR {name}: {type(e).__name__}: {e}")
    print(f"\n{'OK' if failures == 0 else 'FALHOU'}: {failures} falha(s).")
    return failures


if __name__ == "__main__":
    raise SystemExit(1 if _run_all() else 0)
