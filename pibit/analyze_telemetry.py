#!/usr/bin/env python3
"""
pibit/analyze_telemetry.py -- telemetria POR RUN a partir do trace OTel (JSONL)
do WebPostExploit (hackingBuddyGPT). NAO sobe o lab, NAO roda o motor, NAO
captura pacote: opera apenas sobre os `log-*.jsonl` ja existentes no disco.

Metricas por run (uma linha de CSV cada):
    rounds                 : maior 'HEALTHCHECK round=' do trace; se nao houver, nº de spans 'chat'.
    input_tokens           : soma de gen_ai.usage.input_tokens.
    output_tokens          : soma de gen_ai.usage.output_tokens.
    cost_usd               : MAIOR hackingbuddygpt.cost.usd do trace (ESTIMATIVA; confirmar a semantica).
    mitre_techniques       : tecnicas usadas -- prefere o campo estrutural `mitre_technique` da tool
                             HTTPRequest; cai para a linha 'MITRE:' do chat (mesma logica de label_mitre.py).
    mitre_adherence        : fracao das tool calls HTTPRequest com `mitre_technique` parseavel (vazio se 0).
    alive_1 / alive_0      : probes de disponibilidade up/down (linhas HEALTHCHECK do motor).
    healthcheck_ending_run : 1 se o motor encerrou a run por alvo indisponivel.
    end_reason             : hackingbuddygpt.run.state (ou status.message do run span); senao 'unknown'.

Reutiliza os helpers de pibit/label_mitre.py (mesmas chaves GenAI) para manter rotulacao e
telemetria consistentes. Stdlib apenas (SEM pandas).

CLI:
    python3 pibit/analyze_telemetry.py --trace <log.jsonl> [--out tele.csv] [--summary tele.md]
    python3 pibit/analyze_telemetry.py --root experiments/bateria_<stamp> --out tele.csv --summary tele.md
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))  # importa o modulo irmao pibit/label_mitre.py
import label_mitre as lm  # noqa: E402

# Chaves GenAI/projeto adicionais (ver utils/log_storage.py do hbgpt).
K_IN_TOK = "gen_ai.usage.input_tokens"
K_OUT_TOK = "gen_ai.usage.output_tokens"
K_COST = "hackingbuddygpt.cost.usd"
K_ROLE = "hackingbuddygpt.message.role"
K_RUN_STATE = "hackingbuddygpt.run.state"

TOOL_HTTP = "HTTPRequest"
HEALTHCHECK_PREFIX = "HEALTHCHECK"  # ver o healthcheck por round do motor (postexploit.py)

_HC_ROUND = re.compile(r"\bround=(\d+)")
_HC_ALIVE = re.compile(r"\balive=([01])\b")

CSV_FIELDS = [
    "trace", "scenario", "rounds", "input_tokens", "output_tokens", "cost_usd",
    "n_techniques", "mitre_techniques", "http_tool_calls", "mitre_adherence",
    "alive_1", "alive_0", "healthcheck_ending_run", "end_reason",
]
_MEAN_FIELDS = ["rounds", "input_tokens", "output_tokens", "cost_usd", "mitre_adherence", "alive_1", "alive_0"]


def _num(v: Any) -> Optional[float]:
    """Numero (int/float, excluindo bool) ou None."""
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def infer_scenario(trace_path: Path) -> str:
    """Cenario (H0..H3): 1) scenario.json irmao (sobe ate 6 niveis); 2) heuristica de caminho
    (parte H<digito>, como aggregate_bateria.scenario_from_path); 3) '?'."""
    resolved = trace_path.resolve()
    for parent in list(resolved.parents)[:6]:
        sj = parent / "scenario.json"
        if sj.is_file():
            try:
                data = json.loads(sj.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = {}
            if isinstance(data, dict):
                for k in ("scenario", "level", "hardening_level", "H"):
                    v = data.get(k)
                    if isinstance(v, str) and v:
                        return v
    for part in trace_path.parts:
        if len(part) == 2 and part[0] == "H" and part[1:].isdigit():
            return part
    return "?"


def analyze_trace(jsonl_path: str | Path) -> Dict[str, Any]:
    """Telemetria de UMA run a partir do seu trace JSONL. Nunca executa nada (so le o arquivo)."""
    jsonl_path = Path(jsonl_path)

    spans = []
    for span in lm._iter_spans(jsonl_path):
        t0 = lm._iso_to_epoch(span.get("start_time", "") or "", "utc")
        span["_t0"] = t0 if t0 is not None else 0.0
        spans.append(span)
    spans.sort(key=lambda s: s["_t0"])  # ordem cronologica p/ a tecnica "vigente" do fallback

    chat_count = 0
    in_tok = 0
    out_tok = 0
    cost = 0.0
    hc_round_max = 0
    hc_round_seen = False
    alive_1 = 0
    alive_0 = 0
    ending_run = False
    end_reason: Optional[str] = None

    techniques: set[str] = set()
    tool_total = 0
    tool_with_field = 0
    current_id, current_name = lm.NO_TECH_ID, lm.NO_TECH_NAME

    for span in spans:
        attrs = span.get("attributes", {}) or {}
        op = attrs.get(lm.K_OP, "")
        role = attrs.get(K_ROLE, "")

        itok = _num(attrs.get(K_IN_TOK))
        if itok is not None:
            in_tok += int(itok)
        otok = _num(attrs.get(K_OUT_TOK))
        if otok is not None:
            out_tok += int(otok)
        c = _num(attrs.get(K_COST))
        if c is not None:
            cost = max(cost, c)

        rs = attrs.get(K_RUN_STATE)
        if isinstance(rs, str) and rs:
            end_reason = rs
        elif end_reason is None and span.get("parent_span_id") is None:
            st = span.get("status") or {}
            if isinstance(st.get("message"), str) and st["message"]:
                end_reason = st["message"]

        text = lm._message_text(attrs.get(lm.K_OUT, "")) if (op == lm.OP_CHAT or lm.K_OUT in attrs) else ""

        if op == lm.OP_CHAT:
            chat_count += 1
            matches = lm.MITRE_RE.findall(text)
            if matches:
                current_id, current_name = matches[-1][0], matches[-1][1].strip()

        if role == "status" and HEALTHCHECK_PREFIX in text:
            if "ending_run" in text:
                ending_run = True
            mr = _HC_ROUND.search(text)
            if mr:
                hc_round_seen = True
                hc_round_max = max(hc_round_max, int(mr.group(1)))
            ma = _HC_ALIVE.search(text)
            if ma:
                if ma.group(1) == "1":
                    alive_1 += 1
                else:
                    alive_0 += 1

        if op == lm.OP_TOOL and attrs.get(lm.K_TOOL, "") == TOOL_HTTP:
            tool_total += 1
            raw = attrs.get(lm.K_ARGS, "")
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    raw = {}
            parsed = lm._parse_mitre_field(raw.get("mitre_technique", "")) if isinstance(raw, dict) else None
            if parsed is not None:
                tool_with_field += 1
                techniques.add(f"{parsed[0]} {parsed[1]}")
            elif current_id != lm.NO_TECH_ID:
                techniques.add(f"{current_id} {current_name}")

    rounds = hc_round_max if hc_round_seen else chat_count
    adherence: Optional[float] = round(tool_with_field / tool_total, 4) if tool_total else None

    return {
        "trace": str(jsonl_path),
        "scenario": infer_scenario(jsonl_path),
        "rounds": rounds,
        "input_tokens": in_tok,
        "output_tokens": out_tok,
        "cost_usd": round(cost, 6),
        "n_techniques": len(techniques),
        "mitre_techniques": "; ".join(sorted(techniques)),
        "http_tool_calls": tool_total,
        "mitre_adherence": adherence,
        "alive_1": alive_1,
        "alive_0": alive_0,
        "healthcheck_ending_run": int(ending_run),
        "end_reason": end_reason or "unknown",
    }


def find_traces(root: Path) -> List[Path]:
    """Traces sob root: **/hbgpt-trace/log-*.jsonl e tambem **/log-*.jsonl (uniao, sem duplicatas)."""
    seen: Dict[str, Path] = {}
    for pat in ("**/hbgpt-trace/log-*.jsonl", "**/log-*.jsonl"):
        for p in root.glob(pat):
            seen[str(p.resolve())] = p
    return [seen[k] for k in sorted(seen)]


def _mean(rows: List[Dict[str, Any]], field: str) -> str:
    vals = [r[field] for r in rows if isinstance(r[field], (int, float)) and not isinstance(r[field], bool)]
    return f"{sum(vals) / len(vals):.3f}" if vals else "—"


def write_summary(rows: List[Dict[str, Any]], path: Path) -> None:
    by_scn: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        by_scn.setdefault(r["scenario"], []).append(r)

    lines: List[str] = [
        f"# Telemetria por cenario — {len(rows)} run(s)\n",
        "> Medias por cenario. Custo e ESTIMATIVA (maior `hackingbuddygpt.cost.usd` por run; "
        "confirmar a semantica no trace). n=1 nao e lei.\n",
        "| Cenario | Runs | Rounds | In tok | Out tok | Custo US$ | Aderencia MITRE | alive=1 | alive=0 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for scn in sorted(by_scn):
        rs = by_scn[scn]
        lines.append(
            f"| {scn} | {len(rs)} | {_mean(rs, 'rounds')} | {_mean(rs, 'input_tokens')} | "
            f"{_mean(rs, 'output_tokens')} | {_mean(rs, 'cost_usd')} | {_mean(rs, 'mitre_adherence')} | "
            f"{_mean(rs, 'alive_1')} | {_mean(rs, 'alive_0')} |"
        )
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_csv(rows: List[Dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: ("" if r.get(k) is None else r.get(k)) for k in CSV_FIELDS})


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="analyze_telemetry.py",
        description="Telemetria por run a partir do trace OTel do WebPostExploit (NAO executa nada).",
    )
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--trace", help="Trace JSONL de UMA run (log-*.jsonl).")
    g.add_argument("--root", help="Diretorio: varre **/hbgpt-trace/log-*.jsonl e **/log-*.jsonl.")
    ap.add_argument("--out", default="", help="CSV de saida (uma linha por run).")
    ap.add_argument("--summary", default="", help="(Opcional) resumo markdown com medias por cenario.")
    args = ap.parse_args(argv)

    if args.trace:
        traces = [Path(args.trace)]
        if not traces[0].exists():
            sys.exit(f"[ERRO] trace nao encontrado: {traces[0]}")
    else:
        root = Path(args.root)
        if not root.is_dir():
            sys.exit(f"[ERRO] diretorio nao encontrado: {root}")
        traces = find_traces(root)
        if not traces:
            sys.exit(f"[ERRO] nenhum log-*.jsonl sob {root}")

    rows = [analyze_trace(t) for t in traces]

    if args.out:
        write_csv(rows, Path(args.out))
    if args.summary:
        write_summary(rows, Path(args.summary))

    print(f"[OK] {len(rows)} run(s) analisada(s).")
    for r in rows:
        adh = "NA" if r["mitre_adherence"] is None else f"{r['mitre_adherence']:.2f}"
        print(f"  {r['scenario']:>3} rounds={r['rounds']:>3} in={r['input_tokens']:>7} "
              f"out={r['output_tokens']:>6} cost={r['cost_usd']:.4f} aderencia={adh} "
              f"alive(1/0)={r['alive_1']}/{r['alive_0']} end={r['end_reason']} :: {Path(r['trace']).name}")
    if args.out:
        print(f"     CSV -> {args.out}")
    if args.summary:
        print(f"     resumo -> {args.summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
