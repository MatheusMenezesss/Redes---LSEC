# Fluxo do processamento de dados — CICIDS2017

Infográfico da etapa de dados do projeto **"Auditoria de XAI em Ambientes
Adversariais para Sistemas de Detecção de Intrusão"**. Os números são da
execução com a configuração padrão (`seed=42`) e ficam registrados em
`data/processed/metadata.json`.

> Versões em imagem (para visualizadores sem Mermaid): [`pipeline.png`](pipeline.png)
> e [`funil.png`](funil.png).

## Visão geral

```mermaid
flowchart TD
    %% ---------- Etapa 1: download ----------
    subgraph S1["① download_dataset.py"]
        K[("Kaggle<br/>mdalamintalukder/cicids2017")] -->|kagglehub| C["Copia 8 CSVs<br/>MachineLearningCVE"]
        C --> H{"SHA-256 e<br/>coluna Label ok?"}
        H -- não --> X["❌ aborta"]
        H -- sim --> RAW[("data/raw/<br/>8 CSVs · 2.830.743 fluxos · 78 features<br/>+ download_manifest.json")]
    end

    %% ---------- Etapa 2: tratamento ----------
    subgraph S2["② preprocess_dataset.py"]
        direction TB
        subgraph PRE["Limpeza sem estatística — dataset inteiro (sem risco de vazamento)"]
            L["Rótulos normalizados<br/>'Web Attack � XSS' → 'Web Attack - XSS'<br/>alvos: is_attack · family · label"]
            SC["Remoção estrutural de colunas (−14)<br/>Destination Port (atalho) · 8 constantes · 5 cópias exatas"]
            V["Valores inválidos<br/>−2.867 NaN/±inf · −150 negativos impossíveis<br/>2.792 IAT com jitter (−1…−14 µs) → 0"]
            D["Duplicatas<br/>−82.458 conflitos de rótulo (270 vetores únicos)<br/>−512.761 duplicatas exatas"]
            L --> SC --> V --> D
        end

        SP{{"Divisão estratificada por rótulo fino<br/>70 / 15 / 15 · 2.232.507 fluxos únicos"}}
        D --> SP

        SP --> TRN["Treino natural<br/>1.562.753 · 15,1% ataque"]
        SP --> VAL["Validação<br/>334.877 · distribuição natural"]
        SP --> TST["Teste<br/>334.877 · distribuição natural<br/>(intocado até a avaliação final)"]

        subgraph FIT["Ajustado SOMENTE no treino"]
            B["Balanceamento<br/>subamostragem de BENIGN por dia<br/>→ 470.708 · 50/50 · nenhum ataque descartado"]
            FS["Seleção de features (−14)<br/>constantes + |Spearman| ≥ 0,99<br/>→ 50 features"]
            ST["Estatísticas por feature<br/>min · max · std · non_negative · integer_like"]
            SCL["Scaler: arcsinh → StandardScaler"]
            B --> FS --> ST --> SCL
        end
        TRN --> B
    end

    %% ---------- Saídas ----------
    subgraph OUT["data/processed/ (≈177 MB)"]
        P1[("train / val / test .parquet<br/>unidades físicas · float64<br/>→ RandomForest + TreeSHAP")]
        P2[("*_scaled.parquet<br/>float32 normalizado<br/>→ MLP / LR / SVM")]
        P3[("scaler.joblib")]
        P4[("metadata.json<br/>config · proveniência · passos · distribuições · estatísticas")]
    end

    RAW --> L
    SCL --> P1 & P2 & P3 & P4
    VAL -. "mesmas 50 features +<br/>transform do scaler" .-> P1
    TST -. "mesmas 50 features +<br/>transform do scaler" .-> P1

    %% ---------- Próximas fases ----------
    NEXT["🔜 Próximas fases<br/>treino do IDS · SHAP · ataque fooling · queda de Spearman (CA01–CA03)"]
    P1 -.-> NEXT

    classDef fit fill:#fff4e5,stroke:#e8a33d,color:#000
    classDef out fill:#e8f5e9,stroke:#43a047,color:#000
    classDef bad fill:#ffebee,stroke:#e53935,color:#000
    class B,FS,ST,SCL fit
    class P1,P2,P3,P4 out
    class X bad
```

## Funil de linhas

```mermaid
xychart-beta
    title "Fluxos restantes após cada etapa (milhares)"
    x-axis ["Bruto", "NaN/inf", "Negativos", "Conflitos", "Duplicatas", "Treino bal."]
    y-axis "fluxos (mil)" 0 --> 3000
    bar [2831, 2828, 2828, 2745, 2233, 471]
```

> "Treino bal." é só a parte de treino após o balanceamento; validação e teste
> (334.877 cada) não são balanceados.

## Por que cada decisão

| Etapa | Decisão | Motivo |
| --- | --- | --- |
| Download | Hash SHA-256 fixo por arquivo | Espelhos do CICIDS2017 diferem entre si; garante que todos usem os mesmos bytes. |
| Rótulos | Corrige `�` e agrupa em 9 famílias | Rótulos consistentes; famílias permitem relatório por tipo de ataque. |
| Colunas | Remove `Destination Port` | Identificador que permite "decorar" o laboratório (shortcut); não tem sentido físico perturbá-lo no ataque. |
| Colunas | Remove constantes e cópias exatas | Não trazem informação; cópias dividem a atribuição SHAP arbitrariamente. |
| Valores | Remove NaN/inf e negativos impossíveis; zera jitter de IAT | Erros de medição do CICFlowMeter (Engelen et al., 2021). Zerar o jitter preserva 4 dos 11 Heartbleed. |
| Duplicatas | Remove **antes** da divisão | Impede que o mesmo fluxo esteja no treino e no teste (vazamento). Verificado: 0 vetores em comum. |
| Divisão | Estratificada pelo rótulo fino | Garante ataques raros (Heartbleed, SQL Injection) em todos os conjuntos. |
| Balanceamento | Subamostrar BENIGN, só no treino, sem SMOTE | SMOTE cria fluxos fisicamente inválidos; val/test com distribuição real dão métricas honestas. |
| Features | Spearman ≥ 0,99, ajustado no treino | Árvores são invariantes a transformações monotônicas; redundância embaralharia o ranking SHAP (CA02). |
| Normalização | arcsinh + StandardScaler, ajustado no treino | Caudas pesadas; arcsinh aceita o sentinela −1 e é inversível. RandomForest usa os dados brutos. |
| Formato | Parquet (zstd) + `metadata.json` | Tipado, compacto e rápido; tudo rastreável e reprodutível sem reprocessar. |

## Observação sobre o PortScan

Sem `Destination Port`, a maioria das sondas de PortScan (1 pacote, sem
resposta) fica **idêntica** a fluxos benignos ou entre si, e sai na
deduplicação: de 158.930 linhas restam 1.850 fluxos únicos. Isso é esperado —
uma varredura de portas é um fenômeno de *vários* fluxos, não de um fluxo
isolado. Quem quiser o cenário com a porta pode usar
`--keep-destination-port` (e documentar o risco de atalho).
