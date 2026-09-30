# ids-xai-audit — Auditoria de XAI em IDS sob ataques adversariais

Benchmark de robustez de explicações SHAP para um Sistema de Detecção de
Intrusão (IDS) treinado no **CICIDS2017**. Objetivo: medir quanto um ataque
de *fooling* — que mantém a predição do IDS inalterada — degrada a
correlação de Spearman do ranking de features do SHAP.

Critérios de aceitação do projeto:

| ID | Critério | Descrição |
| --- | --- | --- |
| CA01 | Integridade da predição | O ataque mantém a predição original do IDS. |
| CA02 | Mensurabilidade da queda | A queda na correlação de Spearman do SHAP é detectável e mensurável. |
| CA03 | Viabilidade de hardware | Tudo roda localmente em CPU, sem hardware especializado. |

## Status

- [x] **Etapa 1 — download** do dataset com verificação de integridade
- [x] **Etapa 2 — tratamento** e exportação do dataset pronto para IA
- [ ] Etapa 3 — treino do IDS (RandomForest)
- [ ] Etapa 4 — explicações SHAP (TreeExplainer)
- [ ] Etapa 5 — ataque *fooling* e medição da queda de Spearman

Infográfico do fluxo de dados: [`docs/PIPELINE.md`](docs/PIPELINE.md).

## Como executar

```bash
cd src/ids-xai-audit
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python scripts/download_dataset.py      # ~850 MB -> data/raw/ (idempotente)
python scripts/preprocess_dataset.py    # ~30 s, ~5 GB de RAM -> data/processed/
```

Ou, da raiz do repositório: `make dataset-download` e `make dataset-preprocess`.

Para um teste rápido (não use para experimentos):
`python scripts/preprocess_dataset.py --sample-frac 0.05 --out-dir /tmp/teste`.
Todas as opções: `python scripts/preprocess_dataset.py --help`.

## Estrutura

```text
src/ids-xai-audit/
├── scripts/
│   ├── download_dataset.py     # Etapa 1: kagglehub + SHA-256 + manifesto
│   └── preprocess_dataset.py   # Etapa 2: limpeza, divisão, balanceamento, normalização
├── docs/PIPELINE.md            # infográfico (Mermaid) e justificativas
├── data/                       # NÃO versionado (.gitignore)
│   ├── raw/                    # 8 CSVs originais + download_manifest.json
│   └── processed/              # saída pronta para o modelo
└── requirements.txt
```

## Saída do tratamento (`data/processed/`)

| Arquivo | Conteúdo | Uso |
| --- | --- | --- |
| `train.parquet` | 470.708 fluxos, balanceado 50/50 | treino do modelo |
| `val.parquet` | 334.877 fluxos, distribuição natural (15% ataque) | ajuste de hiperparâmetros/limiar |
| `test.parquet` | 334.877 fluxos, distribuição natural | avaliação final e auditoria XAI |
| `*_scaled.parquet` | mesmos conjuntos normalizados (float32) | modelos sensíveis a escala (MLP, LR, SVM) |
| `scaler.joblib` | `arcsinh → StandardScaler` ajustado no treino | normalizar dados novos / inverter perturbações |
| `metadata.json` | config, proveniência, passos, distribuições, estatísticas | reprodutibilidade e etapa de ataque |

Cada Parquet tem as **50 features** (float64, unidades físicas) mais 4 colunas
que **não** são features: `is_attack` (alvo binário, 0 = BENIGN), `label`
(rótulo original, 15 classes), `family` (9 famílias) e `day` (período de
captura). Para carregar:

```python
import json
import pandas as pd

meta = json.load(open("data/processed/metadata.json"))
features, target = meta["columns"]["features"], meta["columns"]["target"]

train = pd.read_parquet("data/processed/train.parquet")
X_train, y_train = train[features], train[target]
```

## Decisões de tratamento (resumo)

1. **Integridade**: SHA-256 de cada CSV conferido contra um manifesto fixo.
2. **Rótulos**: corrige o caractere corrompido dos "Web Attack" e cria alvo binário + famílias.
3. **Colunas**: remove `Destination Port` (atalho), 8 constantes e 5 cópias exatas.
4. **Valores**: remove NaN/±inf e negativos impossíveis; zera jitter de IAT (−1 a −14 µs).
5. **Duplicatas**: remove conflitos de rótulo e duplicatas exatas **antes** da divisão (sem vazamento).
6. **Divisão**: 70/15/15 estratificada pelo rótulo fino (ataques raros em todos os conjuntos).
7. **Balanceamento**: subamostragem de BENIGN **só no treino**; sem SMOTE (fluxos sintéticos seriam fisicamente inválidos).
8. **Features**: remove constantes e redundantes (|Spearman| ≥ 0,99), ajustado no treino → 50 features.
9. **Normalização**: `arcsinh` + `StandardScaler` ajustado no treino; dados brutos preservados para o RandomForest/TreeSHAP.

Detalhes e números de cada passo em [`docs/PIPELINE.md`](docs/PIPELINE.md);
os comentários dos scripts explicam o porquê de cada escolha.

## Limitações conhecidas

- Só duplicatas exatas e erros evidentes são tratados; a errata completa de
  rótulos do CICIDS2017 (Engelen et al., 2021) não é aplicada.
- Classes muito raras continuam raras (Heartbleed: 7/2/2; SQL Injection: 15/3/3;
  Infiltration: 26/5/5); métricas por classe nelas têm alta variância.
- Sem `Destination Port`, PortScan fica com apenas 1.850 fluxos únicos (ver `docs/PIPELINE.md`).
- A divisão é aleatória estratificada, não temporal; avaliar generalização
  para ataques de dias não vistos exigiria uma divisão por `day`.

## Referências

- Sharafaldin, Lashkari, Ghorbani (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. ICISSP.
- Engelen, Rimmer, Joosen (2021). *Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study*. IEEE SPW.
- Arp et al. (2022). *Dos and Don'ts of Machine Learning in Computer Security*. USENIX Security.
- Slack et al. (2020). *Fooling LIME and SHAP: Adversarial Attacks on Post hoc Explanation Methods*. AIES.
