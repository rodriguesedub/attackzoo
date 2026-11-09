# pibit/ — Adaptação do AttackZoo ao contexto do PIBIT/WTICG

> Subárvore **isolada** (fácil de *diffar* e citar vs. o upstream, no espírito da
> decisão D038). Nada aqui modifica os arquivos do AttackZoo original, exceto o
> registro de **um** attack-id novo em `docker/attackers/llm-web-postexploit/`
> (exigência do `experiment` do AttackZoo, que valida `--attack-id` no registry).

## 1. O que é isto

O AttackZoo (GT-IoTEdu) é uma harness de **captura + extração de features +
dataset** para tráfego de ataque/benigno. Esta pasta adapta essa harness ao
nosso experimento: em vez de um container de ataque do catálogo, a "janela de
ataque" passa a ser **uma run do `WebPostExploit`** (hackingBuddyGPT) contra o
alvo **GLPI** do lab `sbseg25-IaC-ZT`, com o `.pcap` capturado em volta e o
dataset rotulado por **cenário (H0–H3)** e **técnica MITRE declarada por passo**.

Três peças, três repositórios:

| Peça | Repositório | Papel |
|---|---|---|
| Alvo | `sbseg25-IaC-ZT` (lab IaC) | GLPI + MariaDB nos níveis H0–H3 |
| Motor | `rodriguesedub/hackingBuddyGPT` | agente `WebPostExploit` (pós-exploração guiada por MITRE) |
| Captura | **este fork** `rodriguesedub/attackzoo` | pcap + probes + features + dataset rotulado |

## 2. Como a captura encaixa no motor

O runner `attackzoo.py experiment` (ver `modules/attackzoo/experiment.py`) executa,
por run, as fases **warmup → attack → cooldown**, com, simultaneamente:

- **`tcpdump`** gravando o `.pcap` da janela (`modules/attackzoo/capture.py`);
- **probes de disponibilidade** (`--probes http`) amostrando o alvo durante toda a
  janela → é o **healthcheck de disponibilidade** do GLPI (pega, p.ex., o agente
  derrubando o próprio alvo, como no Piloto 00 do DVWA);
- ao **início da janela** (níveis ≠ `L0`), chama o `--attack-start-hook`.

Nosso hook (`pibit/hooks/webpostexploit_start.sh`) dispara, em vez de um container:

```
cd $HBGPT_DIR && wintermute WebPostExploit \
    --host=http://<glpi>:<porta>/ \
    --log.log_dir=<run_dir>/hbgpt-trace \
    --llm.model=$HB_MODEL --limits.max_duration=<duração_da_janela> ...
```

O AttackZoo mantém o hook vivo pela duração da janela e encerra o **grupo de
processo** no fim (`_stop_proc`), então a run do motor é limitada à janela (reforçado
por `--limits.max_duration`). O trace OTel (`log-*.jsonl`) fica **dentro do run_dir**,
lado a lado com o `.pcap` daquela execução.

## 3. As 3 pendências do motor — onde cada uma vive

| Pendência | Onde | Status nesta entrega |
|---|---|---|
| **Captura `.pcap` por execução** | attackzoo (aqui) | **Feito** como *wiring*: hook + driver + dataset. Falta só rodar (após aval). |
| **Healthcheck do alvo** | motor (hbgpt) + aqui | **Feito.** Disponibilidade na orquestração via `--probes http` (aqui) **e** healthcheck **por-round** dentro do `WebPostExploit` (motor): a cada round o agente sonda `HEAD /` e **encerra a run** se o alvo ficar mudo por `health_max_consecutive_down` probes, gravando `HEALTHCHECK round=N alive=…` no trace. |
| **MITRE como campo obrigatório da ação** | motor (hbgpt) + aqui | **Feito.** No motor, cada `HTTPRequest` agora exige o campo **estrutural** `mitre_technique` (capturado nos argumentos da tool call no trace — sobrevive à poda da janela de contexto), não só a linha de prompt. O **labeler** (`label_mitre.py`) e a **telemetria** (`analyze_telemetry.py`) **preferem** esse campo, caindo para a linha `MITRE: <id> <nome>` do chat (compatível com os traces do piloto3). |

> Resumo honesto: as **quatro** pendências do motor estão fechadas no `hackingBuddyGPT`
> (healthcheck por-round; campo `mitre_technique` estrutural; remoção da "dica de CTF"
> do prompt; texto do `EndRun`). A camada de captura/rotulação/telemetria vive aqui.
> **Nada foi executado ainda** — a medição depende do aval do Santin (D040).

## 4. Cenários H0–H3 (atenção ao `L0`)

O nível de hardening é propriedade do **alvo**, não do motor: o comando do
`WebPostExploit` é o mesmo em H0–H3; o que muda é o lab que está no ar. Suba o lab
no nível certo **antes** de cada cenário (`apply.sh` do `sbseg25-IaC-ZT`).

⚠️ **Nunca** nomeie um nível como `L0`: o `experiment` do AttackZoo **pula o hook**
em `L0` (trata como baseline sem ataque). Por isso usamos `H0,H1,H2,H3` — o hook
roda em **todos**, inclusive H0.

## 5. Uso (NÃO executar ainda)

**Ponto de entrada único: `pibit/pentest.sh`.** Ele orquestra tudo e **não
reimplementa** motor/lab — delega ao `run_bateria.sh`, que carrega a **trava
dupla**. Comandos somente-leitura nunca sobem o lab nem rodam o motor:

```bash
cp pibit/config.example.env pibit/config.env   # edite HBGPT_DIR, GLPI_HOST, CAP_IFACE...
pibit/pentest.sh preflight        # checa wintermute/tcpdump/curl/python3, HBGPT_DIR, LAB_DIR + SHAs/modelo
pibit/pentest.sh plan             # DRY-RUN: plano da bateria (n≥30) e do piloto (n=1)
pibit/pentest.sh pilot            # sem --run -> DRY-RUN (nada executa)
pibit/pentest.sh analyze [DIR]    # telemetria por run (analyze_telemetry.py)
pibit/pentest.sh aggregate [DIR]  # dataset agregado + summary.md (aggregate_bateria.py)
pibit/pentest.sh status [DIR]     # conta .done/.status por cenário
```

(O driver de baixo nível `pibit/run_experiment_webpostexploit.sh` continua
disponível para 1 run avulsa; `pentest.sh` é a camada acima dele + `run_bateria.sh`.)

A execução real está **bloqueada por trava dupla** (`--run` +
`PIBIT_I_HAVE_SANTIN_APPROVAL=1`), porque **nenhuma execução acontece até o aval
do Santin** (D040) — ex.: `PIBIT_I_HAVE_SANTIN_APPROVAL=1 pibit/pentest.sh pilot --run`.
O piloto usa `RUNS=1`; a bateria pré-registrada é **n≥30 por cenário, n igual
entre cenários** (D016).

## 6. Rotulação por cenário + MITRE (C4)

`pibit/label_mitre.py` cruza o trace do motor com o dataset do AttackZoo:

```bash
python3 pibit/label_mitre.py \
    --trace   experiments/webpostexploit/llm_web_postexploit/H0/run01/hbgpt-trace/log-*.jsonl \
    --dataset datasets/unsupervised-<base>.csv \
    --scenario H0 \
    --out     datasets/labeled-<base>.csv
```

Modelo: cada ação on-wire (tool `HTTPRequest`) vira uma janela `[start,end]` com a
técnica MITRE **vigente** (última linha `MITRE: <id> <nome>` declarada antes dela);
pacotes na janela recebem a técnica como rótulo *ground-truth*; fora das janelas,
`benign/background`. Testado em `pibit/tests/test_label_mitre.py` (sem laboratório).

**Limitações da rotulação (honestas):**
- **Relógio:** o trace usa ISO; o `frame.time_epoch` do pcap é Unix. Sincronize os
  relógios do host de captura e do motor, ou informe o desvio em `--clock-offset-s`
  (e `--assume-tz` para ISO sem fuso).
- **Tráfego do probe** de disponibilidade também cai na janela; para separar
  agente × probe, filtre por IP de origem (refinamento futuro).
- `n=1` no piloto **não** vira lei — linguagem sempre como distribuição (C1).

## 7. Reprodutibilidade

- Motor pinado por SHA (ver ESTADO do projeto); imagens do lab por `@sha256`.
- Trace OTel por run (`log-*.jsonl`) + `.pcap` + `meta.json` por execução → linhagem
  **IaC → LLM → evidência** completa (C4).
- `pibit/config.env` e artefatos (`experiments/`, `*.pcap`, trace) ficam no
  `.gitignore` — versiona-se o **código** da adaptação, não as evidências.

## 8. Isolamento do repositório

`origin` = `rodriguesedub/attackzoo` (nosso fork privado). `upstream` =
`GT-IoTEdu/attackzoo-sbseg26` com **push desabilitado** — nenhum commit nosso
chega ao repositório autoral (lição do D042).

## 9. Bateria n≥30 (quando o Santin aprovar)

`pibit/run_bateria.sh` orquestra a bateria do **vetor A** (WebPostExploit) sobre
H0–H3, `n≥30` por cenário (D016), **travada** por `--run` +
`PIBIT_I_HAVE_SANTIN_APPROVAL=1` (D040). Dry-run (imprime o plano, nada roda):

```bash
pibit/run_bateria.sh
```

Por cenário H: provisiona o lab no nível H (`LAB_PROVISION_CMD`) e verifica
(`LAB_VERIFY_CMD`, 22/22). Por run: **reinicia** o lab ao estado inicial do nível
(`LAB_RESET_CMD` = `./reset.sh && ./apply.sh {H}` — o `reset.sh` **não aceita
argumento**, só faz `docker compose down -v`; o `apply.sh {H}` recria o nível;
independência D019), confere o alvo com healthcheck (não se ataca lab morto —
lição do DVWA), roda o `experiment` (captura + motor + features + dataset) e
**rotula** com `label_mitre.py`. É **resumível** (runs com `.done` são puladas) e
grava `manifest.json` por run (SHAs do attackzoo e do hbgpt, modelo, tempos) para
reprodutibilidade. No fim, `pibit/aggregate_bateria.py` junta tudo em
`datasets/bateria_<stamp>.csv` + `summary.md` (linhas por cenário/técnica, custo
estimado) e `pibit/analyze_telemetry.py` extrai a **telemetria por run** (rounds,
tokens, custo estimado, **aderência MITRE**, disponibilidade). Sem seed fixa (D018).

**Pré-condições de execução** (no **host do lab**, tipicamente Linux):
- `tcpdump` com permissão para capturar em `CAP_IFACE` (em macOS a bridge do
  Docker não é visível ao `tcpdump` do host — rode no host/VM Linux do lab).
- venv do hbgpt ativo (`wintermute` no PATH) e `.env` com `llm.api_key`.
- **Confirmar** `LAB_DIR` (default corrigido: `../infra/sbseg25-iac-zt`) e os `LAB_*_CMD` no `config.env` contra o seu sbseg25-IaC-ZT.

> Só o **vetor A** está automatizado aqui. B (credencial baixo-privilégio) e C
> (shell SSH) entram quando os use cases SSH do motor forem conectados — mesma
> mecânica de captura, outro hook.
>
> Ineficiência conhecida: o `experiment` dorme a janela `ATTACK` inteira mesmo que
> o agente termine antes (via `EndRun`). Ajuste `ATTACK` ao maior tempo de run
> observado no piloto; encerrar a janela no `EndRun` é melhoria futura.
