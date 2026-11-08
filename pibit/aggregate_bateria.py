#!/usr/bin/env python3
"""
pibit/aggregate_bateria.py -- agrega os `labeled.csv` de uma bateria num dataset
unico e escreve um resumo (contagens por cenario e por tecnica MITRE, runs
ok/falhas, custo estimado). NAO executa nada do laboratorio.

Uso:
    python3 pibit/aggregate_bateria.py \
        --root experiments/bateria_<stamp> \
        --out  datasets/bateria_<stamp>.csv \
        --summary experiments/bateria_<stamp>/summary.md

Entradas (produzidas por pibit/run_bateria.sh):
    <root>/**/labeled.csv        -> um por run (ja com scenario/attack/mitre_*)
    <root>/**/.status            -> 'ok' | 'fail' por run
    <root>/**/hbgpt-trace/log-*.jsonl  -> custo (hackingbuddygpt.cost.usd), best-effort
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

COST_KEY = "hackingbuddygpt.cost.usd"


def find_labeled(root: Path) -> List[Path]:
    return sorted(root.glob("**/labeled.csv"))


def scenario_from_path(p: Path) -> str:
    # .../<OUT>/<H>/s<NNN>/<attack_id>/<H>/run01/labeled.csv  -> primeiro H depois do batch dir
    for part in p.parts:
        if len(part) == 2 and part[0] == "H" and part[1].isdigit():
            return part
    return "?"


def status_counts(root: Path) -> Dict[str, Dict[str, int]]:
    """Por cenario: {'ok': x, 'fail': y} lendo os arquivos .status."""
    out: Dict[str, Dict[str, int]] = {}
    for s in root.glob("**/.status"):
        H = scenario_from_path(s)
        val = s.read_text(encoding="utf-8").strip() or "fail"
        out.setdefault(H, {"ok": 0, "fail": 0})
        out[H][val] = out[H].get(val, 0) + 1
    return out


def trace_cost_usd(root: Path) -> Optional[float]:
    """Soma, por run, o maior hackingbuddygpt.cost.usd do trace; soma as runs.
    Best-effort: se a semantica do custo diferir, tratar como ESTIMATIVA."""
    total = 0.0
    found = False
    for tr in root.glob("**/hbgpt-trace/log-*.jsonl"):
        run_max = 0.0
        try:
            for line in tr.open(encoding="utf-8"):
                line = line.strip()
                if not line or COST_KEY not in line:
                    continue
                try:
                    span = json.loads(line)
                except json.JSONDecodeError:
                    continue
                c = (span.get("attributes") or {}).get(COST_KEY)
                if isinstance(c, (int, float)):
                    found = True
                    run_max = max(run_max, float(c))
        except OSError:
            continue
        total += run_max
    return total if found else None


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="aggregate_bateria.py")
    ap.add_argument("--root", required=True, help="Diretorio da bateria (experiments/bateria_<stamp>).")
    ap.add_argument("--out", required=True, help="CSV agregado de saida.")
    ap.add_argument("--summary", default="", help="Arquivo markdown de resumo (opcional).")
    args = ap.parse_args(argv)

    try:
        import pandas as pd
    except ImportError:  # pragma: no cover
        sys.exit("[ERRO] pandas e necessario.")

    root = Path(args.root)
    files = find_labeled(root)
    if not files:
        sys.exit(f"[ERRO] nenhum labeled.csv sob {root}")

    frames = []
    for f in files:
        try:
            df = pd.read_csv(f)
        except Exception as e:  # noqa: BLE001
            print(f"[AVISO] pulando {f}: {e}", file=sys.stderr)
            continue
        df["__source"] = str(f)
        if "scenario" not in df.columns:
            df["scenario"] = scenario_from_path(f)
        frames.append(df)

    combined = pd.concat(frames, ignore_index=True)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(args.out, index=False)

    # --- resumo ---
    runs_por_cenario = combined.groupby("scenario")["__source"].nunique().to_dict()
    linhas_por_cenario = combined.groupby("scenario").size().to_dict()
    attack_por_cenario = combined[combined.get("attack", 0) == 1].groupby("scenario").size().to_dict()
    st = status_counts(root)
    cost = trace_cost_usd(root)

    lines: List[str] = []
    lines.append(f"# Resumo da bateria — {root.name}\n")
    lines.append(f"- Runs com dataset rotulado: **{len(files)}**")
    lines.append(f"- Linhas (pacotes/fluxos) no dataset agregado: **{len(combined)}**")
    if cost is not None:
        lines.append(f"- Custo de API (ESTIMATIVA, soma por run do maior `{COST_KEY}`): **US$ {cost:.4f}**")
    lines.append("")
    lines.append("## Por cenario")
    lines.append("")
    lines.append("| Cenario | Runs | Linhas | Linhas de acao (attack=1) | ok | fail |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for H in sorted(set(list(runs_por_cenario) + list(st))):
        lines.append(
            f"| {H} | {runs_por_cenario.get(H,0)} | {linhas_por_cenario.get(H,0)} | "
            f"{attack_por_cenario.get(H,0)} | {st.get(H,{}).get('ok',0)} | {st.get(H,{}).get('fail',0)} |"
        )
    lines.append("")
    lines.append("## Distribuicao por tecnica MITRE (linhas de acao)")
    lines.append("")
    if "mitre_technique_id" in combined.columns:
        acao = combined[combined.get("attack", 0) == 1]
        tech = acao.groupby(["scenario", "mitre_technique_id", "mitre_technique_name"]).size()
        lines.append("| Cenario | Tecnica | Nome | Linhas |")
        lines.append("|---|---|---|---:|")
        for (H, tid, tname), cnt in tech.sort_index().items():
            lines.append(f"| {H} | {tid} | {tname} | {cnt} |")
    lines.append("")
    lines.append("> ⚠️ n por cenario e **distribuicao**, nao binaria (C1). Custo e estimativa; "
                 "confirmar a semantica de `hackingbuddygpt.cost.usd` no trace.")
    summary_text = "\n".join(lines) + "\n"

    if args.summary:
        Path(args.summary).parent.mkdir(parents=True, exist_ok=True)
        Path(args.summary).write_text(summary_text, encoding="utf-8")

    print(f"[OK] agregado {len(files)} runs -> {args.out} ({len(combined)} linhas).")
    for H in sorted(runs_por_cenario):
        print(f"     {H}: {runs_por_cenario[H]} runs, {linhas_por_cenario.get(H,0)} linhas, "
              f"{attack_por_cenario.get(H,0)} de acao.")
    if cost is not None:
        print(f"     custo estimado: US$ {cost:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
