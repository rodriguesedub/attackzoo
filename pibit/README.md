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
| **Healthcheck do alvo** | parcial aqui / motor | **Disponibilidade** via `--probes http` (nível orquestração) feito aqui. O healthcheck **por-round dentro** do `WebPostExploit` é mudança no motor → follow-up no hbgpt. |
| **MITRE como campo obrigatório da ação** | motor (hbgpt) | Hoje é **instrução de prompt** (`POST_EXPLOIT_MITRE`). Torná-lo campo estrutural da ação é mudança no hbgpt → follow-up. O **labeler** aqui já consome o rótulo `MITRE: <id> <nome>` por passo. |

> Resumo honesto: esta sessão entrega **a camada de captura/rotulação** (attackzoo).
> As duas mudanças *internas ao motor* ficam para quando o `hackingBuddyGPT` estiver
> conectado — não dá para fazê-las a partir deste repositório.

## 4. Cenários H0–H3 (atenção ao `L0`)

O nível de hardening é propriedade do **alvo**, não do motor: o comando do
`WebPostExploit` é o mesmo em H0–H3; o que muda é o lab que está no ar. Suba o lab
no nível certo **antes** de cada cenário (`apply.sh` do `sbseg25-IaC-ZT`).

⚠️ **Nunca** nomeie um nível como `L0`: o `experiment` do AttackZoo **pula o hook**
em `L0` (trata como baseline sem ataque). Por isso usamos `H0,H1,H2,H3` — o hook
roda em **todos**, inclusive H0.

## 5. Uso (NÃO executar ainda)

```bash
cp pibit/config.example.env pibit/config.env   # edite HBGPT_DIR, GLPI_HOST, CAP_IFACE...
pibit/run_experiment_webpostexploit.sh         # DRY-RUN: só imprime o comando
```

A execução real está **bloqueada por trava dupla** (`--run` + `PIBIT_I_HAVE_SANTIN_APPROVAL=1`),
porque **nenhuma execução acontece até o aval do Santin** (D040). O piloto usa
`RUNS=1`; a bateria pré-registrada é **n≥30 por cenário, n igual entre cenários** (D016).

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
(`LAB_VERIFY_CMD`, 22/22). Por run: **reinicia** o lab (`LAB_RESET_CMD` =
`down -v && up`, independência D019), confere o alvo com healthcheck (não se
ataca lab morto — lição do DVWA), roda o `experiment` (captura + motor + features
+ dataset) e **rotula** com `label_mitre.py`. É **resumível** (runs com `.done`
são puladas) e grava `manifest.json` por run (SHAs do attackzoo e do hbgpt,
modelo, tempos) para reprodutibilidade. No fim, `pibit/aggregate_bateria.py`
junta tudo em `datasets/bateria_<stamp>.csv` + `summary.md` (linhas por
cenário/técnica, custo estimado). Sem seed fixa (D018).

**Pré-condições de execução** (no **host do lab**, tipicamente Linux):
- `tcpdump` com permissão para capturar em `CAP_IFACE` (em macOS a bridge do
  Docker não é visível ao `tcpdump` do host — rode no host/VM Linux do lab).
- venv do hbgpt ativo (`wintermute` no PATH) e `.env` com `llm.api_key`.
- **Confirmar** `LAB_DIR` e `LAB_*_CMD` no `config.env` contra o seu sbseg25-IaC-ZT.

> Só o **vetor A** está automatizado aqui. B (credencial baixo-privilégio) e C
> (shell SSH) entram quando os use cases SSH do motor forem conectados — mesma
> mecânica de captura, outro hook.
>
> Ineficiência conhecida: o `experiment` dorme a janela `ATTACK` inteira mesmo que
> o agente termine antes (via `EndRun`). Ajuste `ATTACK` ao maior tempo de run
> observado no piloto; encerrar a janela no `EndRun` é melhoria futura.
