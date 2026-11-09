#!/usr/bin/env python3
"""
Teste do pibit/analyze_telemetry.py com um trace sintetico (sem laboratorio, sem motor).

Roda tanto com pytest quanto diretamente:
    python3 pibit/tests/test_analyze_telemetry.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# importa os modulos irmaos (pibit/analyze_telemetry.py, pibit/label_mitre.py)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import analyze_telemetry as at  # noqa: E402


def _iso(sec: int) -> str:
    base = datetime(2026, 11, 2, 14, 0, 0, tzinfo=timezone.utc)
    return base.replace(second=sec).isoformat()


def _msg_span(sec: int, *, op=None, role=None, text=None, in_tok=0, out_tok=0, cost=0.0) -> dict:
    attrs: dict = {}
    if op:
        attrs["gen_ai.operation.name"] = op
    if role:
        attrs["hackingbuddygpt.message.role"] = role
    if text is not None:
        attrs["gen_ai.output.messages"] = [{"role": role or "assistant", "parts": [{"type": "text", "content": text}]}]
    if in_tok:
        attrs["gen_ai.usage.input_tokens"] = in_tok
    if out_tok:
        attrs["gen_ai.usage.output_tokens"] = out_tok
    if cost:
        attrs["hackingbuddygpt.cost.usd"] = cost
    return {
        "trace_id": "t", "span_id": f"m{sec}", "parent_span_id": "run", "name": "message", "kind": "INTERNAL",
        "start_time": _iso(sec), "end_time": _iso(sec), "attributes": attrs, "status": {"code": "OK", "message": ""},
    }


def _tool_span(sec: int, tool: str, args: dict | None = None) -> dict:
    attrs = {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": tool}
    if args is not None:
        attrs["gen_ai.tool.call.arguments"] = json.dumps(args)
    return {
        "trace_id": "t", "span_id": f"x{sec}", "parent_span_id": "run", "name": "execute_tool", "kind": "INTERNAL",
        "start_time": _iso(sec), "end_time": _iso(sec), "attributes": attrs, "status": {"code": "OK", "message": ""},
    }


def _run_span(sec: int, state: str | None = None) -> dict:
    attrs: dict = {"hackingbuddygpt.run.name": "WebPostExploit"}
    status = {"code": "UNSET", "message": ""}
    if state:
        attrs["hackingbuddygpt.run.state"] = state
        status = {"code": "OK", "message": state}
    return {
        "trace_id": "t", "span_id": "run", "parent_span_id": None, "name": "WebPostExploit", "kind": "INTERNAL",
        "start_time": _iso(sec), "end_time": (_iso(sec) if state else None), "attributes": attrs, "status": status,
    }


def _write(tmp: Path, spans: list[dict], name: str = "log-20261102-140000.jsonl") -> Path:
    p = tmp / name
    p.write_text("\n".join(json.dumps(s) for s in spans), encoding="utf-8")
    return p


def test_analyze_full_trace(tmp_path: Path):
    spans = [
        _run_span(0),
        _msg_span(1, op="chat", text="Plano.\nMITRE: T1046 Network Service Discovery\nvou agir.",
                  in_tok=100, out_tok=20, cost=0.001),
        _msg_span(2, role="status", text="HEALTHCHECK round=1 alive=1 status=200 latency_ms=5"),
        _tool_span(3, "HTTPRequest",
                   args={"method": "GET", "path": "/", "mitre_technique": "T1078.001 Valid Accounts: Default Accounts"}),
        _msg_span(4, op="chat", text="Continuo.", in_tok=50, out_tok=10, cost=0.004),
        _msg_span(5, role="status", text="HEALTHCHECK round=2 alive=0 down error=ConnectionError latency_ms=5000"),
        _tool_span(6, "HTTPRequest", args={"method": "GET", "path": "/x"}),  # sem campo -> fallback T1046
        _msg_span(7, role="status", text="HEALTHCHECK round=3 alive=1 status=200 latency_ms=4"),
        _msg_span(8, role="status", text="HEALTHCHECK ending_run reason=target_unresponsive consecutive_down=3 threshold=3"),
        _run_span(0, state="got root"),
    ]
    r = at.analyze_trace(_write(tmp_path, spans))

    # rounds: HEALTHCHECK (max=3) vence a contagem de spans 'chat' (=2)
    assert r["rounds"] == 3
    # tokens somados; custo e o MAIOR (0.004), nao a soma (0.005)
    assert r["input_tokens"] == 150
    assert r["output_tokens"] == 30
    assert r["cost_usd"] == 0.004
    # aderencia MITRE: 1 das 2 tool calls HTTPRequest traz o campo estrutural
    assert r["http_tool_calls"] == 2
    assert r["mitre_adherence"] == 0.5
    # disponibilidade
    assert r["alive_1"] == 2 and r["alive_0"] == 1
    assert r["healthcheck_ending_run"] == 1
    # tecnica estrutural (tool 1) + fallback de chat (tool 2)
    assert "T1078.001 Valid Accounts: Default Accounts" in r["mitre_techniques"]
    assert "T1046 Network Service Discovery" in r["mitre_techniques"]
    assert r["n_techniques"] == 2
    # fim da run
    assert r["end_reason"] == "got root"


def test_rounds_fall_back_to_chat_count_without_healthcheck(tmp_path: Path):
    # Sem linhas HEALTHCHECK (ex.: health_check desligado): rounds = nº de spans 'chat'.
    spans = [
        _run_span(0),
        _msg_span(1, op="chat", text="um", in_tok=10, out_tok=2, cost=0.0),
        _msg_span(2, op="chat", text="dois", in_tok=10, out_tok=2, cost=0.0),
        _tool_span(3, "HTTPRequest", args={"method": "GET", "path": "/", "mitre_technique": "T1190 Exploit Public-Facing Application"}),
    ]
    r = at.analyze_trace(_write(tmp_path, spans))
    assert r["rounds"] == 2            # dois spans chat, nenhum HEALTHCHECK
    assert r["alive_1"] == 0 and r["alive_0"] == 0
    assert r["healthcheck_ending_run"] == 0
    assert r["mitre_adherence"] == 1.0  # unica tool call tem campo estrutural
    assert r["end_reason"] == "unknown"  # sem run.state


def test_infer_scenario_from_path(tmp_path: Path):
    leaf = tmp_path / "bateria_x" / "H2" / "run01" / "hbgpt-trace"
    leaf.mkdir(parents=True)
    p = _write(leaf, [_run_span(0, state="maxed out")], name="log-1.jsonl")
    r = at.analyze_trace(p)
    assert r["scenario"] == "H2"
    assert r["end_reason"] == "maxed out"


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
