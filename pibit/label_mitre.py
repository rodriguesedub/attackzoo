#!/usr/bin/env python3
"""
pibit/label_mitre.py -- Rotulacao do dataset do AttackZoo por cenario de
hardening (H0..H3) e por tecnica MITRE ATT&CK *declarada pelo proprio agente*,
usando o trace OpenTelemetry (JSONL) de uma run do WebPostExploit
(hackingBuddyGPT).

Por que isto existe (contribuicao C4 -- linhagem LLM -> evidencia):
    O WebPostExploit declara, ANTES de cada acao, uma linha
    'MITRE: <technique_id> <technique_name>' (ver POST_EXPLOIT_MITRE no motor).
    A acao de fato (tool HTTPRequest) ocorre numa janela temporal [start,end]
    registrada como um span OTel. Os pacotes capturados nessa janela recebem a
    tecnica como rotulo ground-truth. O delta frente ao FORGE e justamente este:
    o rotulo vem da *intencao declarada por passo*, nao de uma inferencia
    posterior sobre o trace.

O que este script NAO faz:
    - NAO sobe o laboratorio, NAO roda o motor, NAO captura pacote.
    - Opera apenas sobre artefatos ja existentes no disco:
        * trace JSONL do hbgpt  -> logs/log-*.jsonl (spans OTel)
        * dataset do attackzoo  -> datasets/unsupervised-*.csv (coluna 'ts' = frame.time_epoch)

API reutilizavel (tambem coberta por pibit/tests/test_label_mitre.py):
    extract_mitre_timeline(jsonl_path, tool_names=..., assume_tz=..., clock_offset_s=...) -> list[Window]
    label_dataframe(df, timeline, scenario, ts_col='ts') -> DataFrame

CLI:
    python3 pibit/label_mitre.py \
        --trace   experiments/<out>/<attack_id>/H0/run01/hbgpt-trace/log-YYYYMMDD-HHMMSS.jsonl \
        --dataset datasets/unsupervised-<base>.csv \
        --scenario H0 \
        --out     datasets/labeled-<base>.csv

Caveats honestos (ver pibit/README.md, secao "Limitacoes da rotulacao"):
    * Relogio: os spans do hbgpt sao ISO; o frame.time_epoch do pcap e Unix/UTC.
      Alinhe o relogio do host de captura com o do host do motor, ou informe o
      desvio via --clock-offset-s. Use --assume-tz para dizer como interpretar
      timestamps ISO *sem* fuso.
    * Trafego do probe de disponibilidade tambem cai na janela: refine por IP de
      origem (agente vs. probe) quando precisar separar (--attacker-ip).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

# Linha declarada pelo agente: "MITRE: T1078 Valid Accounts" / "MITRE: T1078.001 Default Accounts"
MITRE_RE = re.compile(r"MITRE:\s*(T\d{4}(?:\.\d{3})?)\s+([^\n\r]+)")
# Campo estrutural `mitre_technique` de uma tool call: aceita "MITRE: <id> <nome>" ou "<id> <nome>" nu.
MITRE_FIELD_RE = re.compile(r"^\s*(?:MITRE:\s*)?(T\d{4}(?:\.\d{3})?)\s+([^\n\r]+?)\s*$")

# Chaves das convencoes GenAI usadas pelo motor (ver utils/log_storage.py do hbgpt).
K_OP = "gen_ai.operation.name"          # "chat" | "execute_tool"
K_OUT = "gen_ai.output.messages"        # lista de mensagens {role, parts:[{type,content}]}
K_TOOL = "gen_ai.tool.name"             # ex.: "HTTPRequest"
K_ARGS = "gen_ai.tool.call.arguments"   # argumentos da tool call (JSON str ou dict): traz o campo mitre_technique
OP_CHAT = "chat"
OP_TOOL = "execute_tool"

NO_TECH_ID = "none"
NO_TECH_NAME = "benign/background"


@dataclass
class Window:
    """Janela de uma acao do agente, com a tecnica MITRE vigente no momento."""
    seq: int
    t_start: float          # epoch (s)
    t_end: float            # epoch (s)
    mitre_id: str
    mitre_name: str
    tool: str

    def contains(self, ts: float) -> bool:
        return self.t_start <= ts <= self.t_end


# --------------------------------------------------------------------------- #
# Leitura do trace OTel do motor
# --------------------------------------------------------------------------- #
def _iso_to_epoch(iso: str, assume_tz: str = "utc") -> Optional[float]:
    """Converte um timestamp ISO (possivelmente sem fuso) para epoch (s)."""
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        # tolera 'Z' e microsegundos extensos
        try:
            dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        if assume_tz == "utc":
            dt = dt.replace(tzinfo=timezone.utc)
        elif assume_tz == "local":
            dt = dt.astimezone()  # assume horario local do host que roda este script
        else:
            raise ValueError(f"--assume-tz invalido: {assume_tz!r} (use 'utc' ou 'local')")
    return dt.timestamp()


def _message_text(messages: Any) -> str:
    """Concatena o texto de uma lista de mensagens OTel/AOS {role, parts:[{type,content}]}."""
    out: List[str] = []
    if isinstance(messages, str):
        return messages
    if not isinstance(messages, Iterable):
        return ""
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        parts = msg.get("parts")
        if isinstance(parts, list):
            for part in parts:
                if isinstance(part, dict) and part.get("type") == "text":
                    out.append(str(part.get("content", "")))
                elif isinstance(part, str):
                    out.append(part)
        elif isinstance(msg.get("content"), str):
            out.append(msg["content"])
    return "\n".join(out)


def _parse_mitre_field(val: str) -> tuple[str, str] | None:
    """Extrai (id, nome) do campo estrutural `mitre_technique` de uma tool call.

    Aceita tanto 'MITRE: <id> <nome>' quanto um '<id> <nome>' nu (id no formato Tdddd ou
    Tdddd.ddd). Devolve None quando o valor nao esta nesse formato (ex.: vazio ou nao-str),
    para que a chamada volte ao fallback da tecnica declarada no texto do chat.
    """
    if not isinstance(val, str):
        return None
    m = MITRE_FIELD_RE.match(val)
    if not m:
        return None
    return m.group(1), m.group(2).strip()


def _iter_spans(jsonl_path: Path) -> Iterable[Dict[str, Any]]:
    with open(jsonl_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                # uma linha corrompida nao deve abortar a rotulacao da campanha inteira
                continue


def extract_mitre_timeline(
    jsonl_path: str | Path,
    tool_names: Iterable[str] = ("HTTPRequest",),
    assume_tz: str = "utc",
    clock_offset_s: float = 0.0,
) -> List[Window]:
    """
    Le o trace JSONL do hbgpt e devolve a sequencia ordenada de janelas de acao.

    Modelo: percorre os spans em ordem de start_time; mantem a "tecnica vigente"
    = ultima linha 'MITRE: <id> <nome>' vista num span de chat; a cada span de
    tool on-wire (default: HTTPRequest) emite uma janela com essa tecnica.
    """
    jsonl_path = Path(jsonl_path)
    tool_set = {t.strip() for t in tool_names if t.strip()}

    spans: List[Dict[str, Any]] = []
    for span in _iter_spans(jsonl_path):
        t0 = _iso_to_epoch(span.get("start_time", ""), assume_tz)
        if t0 is None:
            continue
        span["_t0"] = t0
        span["_t1"] = _iso_to_epoch(span.get("end_time", ""), assume_tz) or t0
        spans.append(span)
    spans.sort(key=lambda s: s["_t0"])

    timeline: List[Window] = []
    current_id, current_name = NO_TECH_ID, NO_TECH_NAME
    seq = 0
    for span in spans:
        attrs = span.get("attributes", {}) or {}
        op = attrs.get(K_OP, "")
        # Atualiza a tecnica vigente a partir da saida do chat
        if op == OP_CHAT or K_OUT in attrs:
            text = _message_text(attrs.get(K_OUT, ""))
            matches = MITRE_RE.findall(text)
            if matches:
                current_id, current_name = matches[-1][0], matches[-1][1].strip()
        # Emite janela para toda acao on-wire
        if op == OP_TOOL and attrs.get(K_TOOL, "") in tool_set:
            # Prefere o campo estrutural `mitre_technique` da tool call (capturado nativamente no
            # trace, sobrevive a poda da janela de contexto) sobre a tecnica declarada no texto do
            # chat; cai para current_id/current_name (texto do chat) quando o campo esta ausente,
            # mantendo compatibilidade com os traces do piloto3 que nao tem esse argumento.
            win_id, win_name = current_id, current_name
            raw_args = attrs.get(K_ARGS, "")
            if isinstance(raw_args, str):
                try:
                    raw_args = json.loads(raw_args) if raw_args else {}
                except json.JSONDecodeError:
                    raw_args = {}
            if isinstance(raw_args, dict):
                parsed = _parse_mitre_field(raw_args.get("mitre_technique", ""))
                if parsed is not None:
                    win_id, win_name = parsed
            seq += 1
            timeline.append(Window(
                seq=seq,
                t_start=span["_t0"] + clock_offset_s,
                t_end=span["_t1"] + clock_offset_s,
                mitre_id=win_id,
                mitre_name=win_name,
                tool=attrs.get(K_TOOL, ""),
            ))
    return timeline


# --------------------------------------------------------------------------- #
# Rotulacao do dataset
# --------------------------------------------------------------------------- #
def label_dataframe(df, timeline: List[Window], scenario: str, ts_col: str = "ts"):
    """
    Adiciona colunas de rotulo a um DataFrame de features (uma linha por pacote/fluxo).

    Colunas adicionadas:
        scenario, hardening_level : cenario de hardening (H0..H3)
        attack                    : 1 se o pacote cai numa janela de acao do agente, senao 0
        mitre_technique_id        : tecnica declarada (ou 'none')
        mitre_technique_name      : nome da tecnica (ou 'benign/background')
        action_seq                : indice da janela de acao (0 = fora de acao)
        tool_name                 : tool da acao (ou '')
    """
    if ts_col not in df.columns:
        raise KeyError(
            f"coluna de timestamp {ts_col!r} ausente no dataset; "
            f"colunas disponiveis: {list(df.columns)[:12]}..."
        )

    ts = df[ts_col].astype(float)
    n = len(df)
    attack = [0] * n
    mid = [NO_TECH_ID] * n
    mname = [NO_TECH_NAME] * n
    aseq = [0] * n
    tool = [""] * n

    # Ordena janelas por inicio; atribuicao por busca linear (datasets de piloto sao pequenos;
    # para n>=30 trocar por busca binaria/merge_asof se virar gargalo).
    wins = sorted(timeline, key=lambda w: w.t_start)
    for i, t in enumerate(ts):
        if t != t:  # NaN
            continue
        for w in wins:
            if w.contains(t):
                attack[i] = 1
                mid[i] = w.mitre_id
                mname[i] = w.mitre_name
                aseq[i] = w.seq
                tool[i] = w.tool
                break

    out = df.copy()
    out["scenario"] = scenario
    out["hardening_level"] = scenario
    out["attack"] = attack
    out["mitre_technique_id"] = mid
    out["mitre_technique_name"] = mname
    out["action_seq"] = aseq
    out["tool_name"] = tool
    return out


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _load_csv(path: Path):
    try:
        import pandas as pd
    except ImportError:  # pragma: no cover
        sys.exit("[ERRO] pandas e necessario (pip install pandas).")
    return pd.read_csv(path)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="label_mitre.py",
        description="Rotula o dataset do AttackZoo por cenario (H0..H3) e tecnica MITRE declarada no trace do WebPostExploit.",
    )
    ap.add_argument("--trace", required=True, help="Trace JSONL do hbgpt (logs/log-*.jsonl).")
    ap.add_argument("--dataset", required=True, help="Dataset nao supervisionado do attackzoo (datasets/unsupervised-*.csv).")
    ap.add_argument("--scenario", required=True, help="Rotulo do cenario de hardening: H0, H1, H2 ou H3.")
    ap.add_argument("--out", required=True, help="CSV de saida com os rotulos.")
    ap.add_argument("--ts-col", default="ts", help="Coluna de timestamp epoch no dataset (default: ts).")
    ap.add_argument("--tool-name", default="HTTPRequest",
                    help="Tool(s) on-wire que definem janela de acao, separadas por virgula (default: HTTPRequest).")
    ap.add_argument("--assume-tz", default="utc", choices=("utc", "local"),
                    help="Como interpretar timestamps ISO sem fuso no trace (default: utc).")
    ap.add_argument("--clock-offset-s", type=float, default=0.0,
                    help="Desvio (s) a somar aos tempos do trace para alinhar com o relogio do pcap.")
    ap.add_argument("--timeline-out", default="",
                    help="(Opcional) grava a timeline MITRE extraida como JSONL para inspecao.")
    args = ap.parse_args(argv)

    trace = Path(args.trace)
    if not trace.exists():
        sys.exit(f"[ERRO] trace nao encontrado: {trace}")
    dataset = Path(args.dataset)
    if not dataset.exists():
        sys.exit(f"[ERRO] dataset nao encontrado: {dataset}")

    timeline = extract_mitre_timeline(
        trace,
        tool_names=args.tool_name.split(","),
        assume_tz=args.assume_tz,
        clock_offset_s=args.clock_offset_s,
    )
    if not timeline:
        print("[AVISO] nenhuma janela de acao extraida do trace "
              "(sem spans de tool on-wire ou sem linha 'MITRE:'). "
              "O dataset sera rotulado inteiro como benign/background.", file=sys.stderr)

    if args.timeline_out:
        with open(args.timeline_out, "w", encoding="utf-8") as fh:
            for w in timeline:
                fh.write(json.dumps(asdict(w), ensure_ascii=False) + "\n")

    df = _load_csv(dataset)
    labeled = label_dataframe(df, timeline, scenario=args.scenario, ts_col=args.ts_col)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    labeled.to_csv(args.out, index=False)

    n_attack = int(sum(1 for v in labeled["attack"] if v == 1))
    techs = sorted({f"{w.mitre_id} {w.mitre_name}" for w in timeline})
    print(f"[OK] {args.out}: {len(labeled)} linhas, {n_attack} marcadas como acao do agente, "
          f"{len(timeline)} janelas, cenario={args.scenario}.")
    if techs:
        print("     tecnicas: " + "; ".join(techs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
