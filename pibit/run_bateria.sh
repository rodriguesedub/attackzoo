#!/usr/bin/env bash
# pibit/run_bateria.sh
# =============================================================================
# Bateria n>=30 do vetor A (WebPostExploit) sobre H0-H3, com captura .pcap,
# extracao de features, dataset e rotulacao MITRE por run.
#
#   Operacao CARA (sobe o lab, roda o LLM por run, captura pcap): dry-run por padrao.
# Sem --run            -> DRY-RUN: imprime o plano e sai (nada roda).
# Com --run            -> executa a bateria (rode no host do lab, Linux).
#
# Desenho (ver pibit/README.md e LOG 2026-11-02 parte 5):
#   - Vetor A = agente web sem credencial (WebPostExploit). B (cred) e C (shell SSH)
#     usariam hooks analogos com use cases SSH do hbgpt -- NAO incluidos aqui.
#   - Por cenario H: provisiona o lab NO NIVEL H (apply) e verifica (22/22).
#   - Por run: REINICIA o lab ao estado inicial do nivel (down -v && up) -> independencia
#     entre amostras (D019); healthcheck; so entao ataca (nao se ataca lab morto).
#   - n>=30 por cenario, n IGUAL entre cenarios (D016). SEM seed fixa (D018).
#   - Resumivel: runs ja concluidas (.done) sao puladas.
#
# PRE-CONDICOES DE EXECUCAO (responsabilidade do operador, no host do lab):
#   - Rodar no HOST onde o lab Docker corre e onde o tcpdump enxerga a interface
#     (tipicamente Linux; em macOS a bridge do Docker nao e visivel ao tcpdump do host).
#   - tcpdump disponivel e com permissao (root/CAP_NET_RAW) para capturar em CAP_IFACE.
#   - venv do hbgpt ativo (wintermute no PATH) e $HBGPT_DIR/.env com llm.api_key.
#   - CONFIRMAR os comandos de lab abaixo (LAB_*_CMD) contra o seu sbseg25-IaC-ZT.
# =============================================================================
set -uo pipefail   # NAO -e: falha de uma run nao aborta a bateria (tratamos run a run).

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AZ_ROOT="$(cd "${HERE}/.." && pwd)"
cd "${AZ_ROOT}"

# ---- config -----------------------------------------------------------------
if [ -f "${HERE}/config.env" ]; then set -a; . "${HERE}/config.env"; set +a; fi

N="${N:-30}"                                  # runs por cenario (piso D016)
SCENARIOS="${SCENARIOS:-H0 H1 H2 H3}"
OUT_BASE="${OUT_BASE:-bateria}"
WARMUP="${WARMUP:-20}"; ATTACK="${ATTACK:-900}"; COOLDOWN="${COOLDOWN:-20}"
GLPI_HOST="${GLPI_HOST:-172.20.0.10}"; GLPI_PORT="${GLPI_PORT:-80}"
CAP_IFACE="${CAP_IFACE:-docker0}"
CAP_BPF="${CAP_BPF:-tcp port 80 or tcp port 443}"
HEALTH_RETRIES="${HEALTH_RETRIES:-6}"; HEALTH_SLEEP="${HEALTH_SLEEP:-5}"

# Ciclo de vida do lab -- CONFIRMAR contra o sbseg25-IaC-ZT. {H} = nivel (H0..H3).
# Deixe uma variavel VAZIA para pular aquela etapa (ex.: provisionar manualmente).
LAB_DIR="${LAB_DIR:-../infra/sbseg25-iac-zt}"
LAB_PROVISION_CMD="${LAB_PROVISION_CMD:-./apply.sh {H}}"       # sobe o lab no nivel H (1x por cenario)
LAB_VERIFY_CMD="${LAB_VERIFY_CMD:-./verify/verify.sh {H}}"     # 22/22 controles + fingerprint
LAB_RESET_CMD="${LAB_RESET_CMD:-./reset.sh && ./apply.sh {H}}"  # reinicio entre runs (D019): reset.sh NAO aceita arg (so "down -v"); apply.sh {H} recria o estado inicial do nivel
LAB_TEARDOWN_CMD="${LAB_TEARDOWN_CMD:-}"                       # opcional: derruba no fim do cenario

HOOK_START="pibit/hooks/webpostexploit_start.sh {service} {attack_id} {level} {host} {port} {duration_s} {run_dir}"
HOOK_STOP="pibit/hooks/webpostexploit_stop.sh {service} {attack_id} {level} {host} {port} {duration_s} {run_dir}"
ATTACK_ID="llm_web_postexploit"

TOTAL_PLANNED=0; for _h in $SCENARIOS; do TOTAL_PLANNED=$((TOTAL_PLANNED + N)); done

print_plan() {
  echo "=== PLANO DA BATERIA (vetor A / WebPostExploit) ==="
  echo "  cenarios        : ${SCENARIOS}"
  echo "  n por cenario   : ${N}   -> total de runs: ${TOTAL_PLANNED}"
  echo "  janela (s)      : warmup=${WARMUP} attack=${ATTACK} cooldown=${COOLDOWN}"
  echo "  alvo            : http://${GLPI_HOST}:${GLPI_PORT}/   iface=${CAP_IFACE}   bpf='${CAP_BPF}'"
  echo "  motor           : HBGPT_DIR=${HBGPT_DIR:-<NAO DEFINIDO>}  modelo=${HB_MODEL:-<default>}"
  echo "  lab (CONFIRMAR) : dir=${LAB_DIR}"
  echo "     provision    : ${LAB_PROVISION_CMD:-<pular>}"
  echo "     verify       : ${LAB_VERIFY_CMD:-<pular>}"
  echo "     reset/run    : ${LAB_RESET_CMD:-<pular>}"
  echo "     teardown     : ${LAB_TEARDOWN_CMD:-<pular>}"
  echo "  seed            : LIVRE (D018) | reset entre runs (D019) | resumivel (.done)"
}

# ---- dry-run por padrao (seguranca de operacao cara; nao e trava de aprovacao) -
if [ "${1:-}" != "--run" ]; then
  print_plan
  echo
  echo ">> DRY-RUN. Nada foi executado."
  echo ">> Para executar de verdade (no host do lab, Linux): pibit/run_bateria.sh --run"
  exit 0
fi

# ---- preflight --------------------------------------------------------------
pf_fail=0
[ -z "${HBGPT_DIR:-}" ] && { echo "[preflight] HBGPT_DIR nao definido." >&2; pf_fail=1; }
command -v wintermute >/dev/null 2>&1 || { echo "[preflight] 'wintermute' nao esta no PATH (ative o venv do hbgpt)." >&2; pf_fail=1; }
command -v tcpdump   >/dev/null 2>&1 || { echo "[preflight] 'tcpdump' nao encontrado." >&2; pf_fail=1; }
command -v curl      >/dev/null 2>&1 || { echo "[preflight] 'curl' nao encontrado (healthcheck)." >&2; pf_fail=1; }
case ",${SCENARIOS// /,}," in *,L0,*) echo "[preflight] nao use L0 (attackzoo pula o hook)." >&2; pf_fail=1;; esac
[ "$pf_fail" = 1 ] && { echo "[preflight] abortado." >&2; exit 4; }

STAMP="$(date -u +%Y%m%d-%H%M%S)"
BAT_DIR="experiments/${OUT_BASE}_${STAMP}"
mkdir -p "${BAT_DIR}"
LOG="${BAT_DIR}/battery.log"
log(){ echo "[$(date -u +%FT%TZ)] $*" | tee -a "${LOG}"; }

AZ_SHA="$(git -C "${AZ_ROOT}" rev-parse --short HEAD 2>/dev/null || echo NA)"
HB_SHA="$(git -C "${HBGPT_DIR:-/nonexistent}" rev-parse --short HEAD 2>/dev/null || echo NA)"

# roda um comando de lab (substitui {H}); vazio => pula.
lab_cmd(){ # $1=var_name $2=H
  local raw="${!1:-}"; local H="$2"
  if [ -z "$raw" ]; then log "lab ${1}: (vazio; pulado) [$H]"; return 0; fi
  local cmd="${raw//\{H\}/$H}"
  log "lab ${1} [$H]: (cd ${LAB_DIR} && ${cmd})"
  ( cd "${LAB_DIR}" && bash -c "${cmd}" ) >>"${LOG}" 2>&1
}
healthcheck(){ curl -fsS -o /dev/null --max-time 10 "http://${GLPI_HOST}:${GLPI_PORT}/"; }

log "BATERIA inicio | stamp=${STAMP} | attackzoo=${AZ_SHA} | hbgpt=${HB_SHA} | total=${TOTAL_PLANNED}"
print_plan | tee -a "${LOG}" >/dev/null

total=0; ok=0; fail=0; skip=0
for H in ${SCENARIOS}; do
  log "===== cenario ${H}: provisionando ====="
  if ! lab_cmd LAB_PROVISION_CMD "${H}"; then log "${H}: FALHA provision -> pula cenario"; continue; fi
  if ! lab_cmd LAB_VERIFY_CMD "${H}"; then log "${H}: FALHA verify -> pula cenario"; lab_cmd LAB_TEARDOWN_CMD "${H}"; continue; fi

  for i in $(seq 1 "${N}"); do
    NNN="$(printf '%03d' "${i}")"; total=$((total+1))
    SOUT="${OUT_BASE}_${STAMP}/${H}/s${NNN}"
    SDIR="experiments/${SOUT}"
    LEAF="${SDIR}/${ATTACK_ID}/${H}/run01"
    if [ -f "${SDIR}/.done" ]; then log "${H} s${NNN}: ja concluida -> skip"; skip=$((skip+1)); continue; fi
    mkdir -p "${SDIR}"

    log "${H} s${NNN}: reset do lab (independencia)"
    if ! lab_cmd LAB_RESET_CMD "${H}"; then log "${H} s${NNN}: FALHA reset -> fail"; fail=$((fail+1)); echo fail >"${SDIR}/.status"; continue; fi

    hc=0
    for _t in $(seq 1 "${HEALTH_RETRIES}"); do if healthcheck; then hc=1; break; fi; sleep "${HEALTH_SLEEP}"; done
    if [ "${hc}" != 1 ]; then log "${H} s${NNN}: alvo nao responde pos-reset -> fail (nao ataco lab morto)"; fail=$((fail+1)); echo fail >"${SDIR}/.status"; continue; fi

    FEAT="${SDIR}/features"; DS="${SDIR}/datasets"
    log "${H} s${NNN}: captura + WebPostExploit (janela ${ATTACK}s)"
    python3 attackzoo.py experiment \
      --attack-id "${ATTACK_ID}" --out "${SOUT}" --service glpi \
      --runs 1 --levels "${H}" \
      --warmup "${WARMUP}" --attack "${ATTACK}" --cooldown "${COOLDOWN}" \
      --iface "${CAP_IFACE}" --bpf "${CAP_BPF}" \
      --probes http --http-url "http://${GLPI_HOST}:${GLPI_PORT}/" \
      --host "${GLPI_HOST}" --port "${GLPI_PORT}" \
      --extract-features --tools-tshark --features-dir "${FEAT}" \
      --build-dataset --dataset-dir "${DS}" \
      --attack-start-hook "${HOOK_START}" \
      --attack-stop-hook "${HOOK_STOP}" >>"${LOG}" 2>&1
    rc=$?
    if [ "${rc}" -ne 0 ]; then log "${H} s${NNN}: experiment rc=${rc} -> fail"; fail=$((fail+1)); echo fail >"${SDIR}/.status"; continue; fi

    PCAP="$(ls "${LEAF}"/*.pcap 2>/dev/null | head -1)"
    UNSUP="$(ls "${DS}"/unsupervised-*.csv 2>/dev/null | head -1)"
    TRACE="$(ls "${LEAF}"/hbgpt-trace/log-*.jsonl 2>/dev/null | tail -1)"

    if [ -n "${UNSUP}" ] && [ -n "${TRACE}" ]; then
      if python3 pibit/label_mitre.py --trace "${TRACE}" --dataset "${UNSUP}" \
           --scenario "${H}" --out "${LEAF}/labeled.csv" \
           --timeline-out "${LEAF}/mitre_timeline.jsonl" >>"${LOG}" 2>&1; then
        log "${H} s${NNN}: rotulado"
      else
        log "${H} s${NNN}: WARN rotulacao falhou (pcap=${PCAP:-NA})"
      fi
    else
      log "${H} s${NNN}: WARN sem trace/dataset p/ rotular (trace=${TRACE:-NA} dataset=${UNSUP:-NA})"
    fi

    # manifesto de reprodutibilidade (C1/artefatos)
    python3 - "${SDIR}/manifest.json" "${H}" "${NNN}" "${STAMP}" "${AZ_SHA}" "${HB_SHA}" \
             "${HB_MODEL:-}" "${PCAP:-}" "${TRACE:-}" "${LEAF}/labeled.csv" <<'PY'
import json,sys,datetime
p,H,NNN,stamp,az,hb,model,pcap,trace,labeled=sys.argv[1:11]
json.dump({
 "scenario":H,"sample":NNN,"vector":"A-web-WebPostExploit","batch_stamp":stamp,
 "attackzoo_sha":az,"hbgpt_sha":hb,"model":model,"seed":"free(D018)",
 "finished_at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
 "pcap":pcap,"trace":trace,"labeled":labeled,"status":"ok",
},open(p,"w"),indent=2)
PY
    echo ok >"${SDIR}/.status"; : > "${SDIR}/.done"
    ok=$((ok+1)); log "${H} s${NNN}: OK"
  done

  log "===== cenario ${H}: teardown ====="
  lab_cmd LAB_TEARDOWN_CMD "${H}"
done

log "BATERIA fim | total=${total} ok=${ok} fail=${fail} skip=${skip}"

AGG="datasets/bateria_${STAMP}.csv"
if python3 pibit/aggregate_bateria.py --root "${BAT_DIR}" --out "${AGG}" --summary "${BAT_DIR}/summary.md" >>"${LOG}" 2>&1; then
  log "dataset agregado: ${AGG} | resumo: ${BAT_DIR}/summary.md"
else
  log "WARN: agregacao falhou (veja ${LOG})"
fi
log "FIM."
