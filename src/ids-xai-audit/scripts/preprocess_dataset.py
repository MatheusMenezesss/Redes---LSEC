#!/usr/bin/env python3
"""Etapa 2 do pipeline: tratamento do CICIDS2017 e exportação pronta para IA.

Transforma os 8 CSVs brutos (``data/raw/``) em conjuntos de treino, validação
e teste limpos, sem vazamento de informação e prontos para o modelo de
detecção de intrusão (IDS) e para a auditoria de XAI (SHAP) do projeto.
O resultado é salvo em ``data/processed/`` para que este script NÃO precise
ser executado novamente a cada experimento.

Visão geral das etapas (a ordem importa!)
-----------------------------------------
 1. Carga + verificação SHA-256 dos CSVs brutos.
 2. Normalização dos rótulos (corrige o caractere corrompido dos "Web Attack")
    e criação dos alvos: binário (``is_attack``), família e rótulo fino.
 3. Remoção estrutural de colunas: colunas idênticas a outras (ex.:
    ``Fwd Header Length.1``) e ``Destination Port`` (atalho/"shortcut").
 4. Limpeza de valores: linhas com NaN/±inf e linhas com valores negativos
    fisicamente impossíveis (durações, contagens, tamanhos).
 5. Deduplicação: remove fluxos com rótulos conflitantes e duplicatas exatas
    ANTES da divisão, para que um mesmo fluxo não caia em treino e teste.
 6. Divisão estratificada treino/validação/teste (70/15/15) pelo rótulo fino,
    garantindo que ataques raros (Heartbleed, SQL Injection...) apareçam
    em todos os conjuntos. Validação e teste mantêm a distribuição NATURAL.
 7. Balanceamento SOMENTE do treino, por subamostragem aleatória da classe
    BENIGN (sem dados sintéticos como SMOTE).
 8. Seleção de features ajustada SOMENTE no treino: remove colunas constantes
    e features redundantes (|Spearman| >= 0.99).
 9. Estatísticas por feature (treino) para a etapa de ataque adversarial.
10. Normalização (arcsinh + StandardScaler) ajustada SOMENTE no treino e
    exportada como artefato reutilizável; os dados também são exportados em
    unidades físicas (brutas), que é o que o RandomForest/TreeSHAP usa.
11. Exportação em Parquet + ``metadata.json`` com todo o rastro do processo.

Uso
---
    python scripts/preprocess_dataset.py                  # configuração padrão
    python scripts/preprocess_dataset.py --sample-frac 0.05   # teste rápido
    python scripts/preprocess_dataset.py --help           # todas as opções
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn

# Reaproveita o manifesto de arquivos/hashes da etapa de download (mesma pasta).
from download_dataset import DEFAULT_OUT_DIR as DEFAULT_RAW_DIR
from download_dataset import EXPECTED_FILES, sha256_of
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.utils.class_weight import compute_class_weight

# ---------------------------------------------------------------------------
# Constantes do domínio
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT_DIR = PROJECT_ROOT / "data" / "processed"

BENIGN = "BENIGN"

# Rótulo fino -> família de ataque. As famílias seguem a Tabela 2 de
# Sharafaldin et al. (2018) e servem para relatórios por tipo de ataque.
# Qualquer rótulo fora deste dicionário interrompe o script (falha explícita
# é melhor do que treinar com um rótulo desconhecido sem perceber).
LABEL_TO_FAMILY: dict[str, str] = {
    BENIGN: BENIGN,
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Web Attack - Brute Force": "WebAttack",
    "Web Attack - XSS": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Bot": "Botnet",
    "Infiltration": "Infiltration",
    "Heartbleed": "Heartbleed",
}

# Colunas que NÃO são features do modelo (alvos e metadados de proveniência).
#   label     -> rótulo original normalizado (multiclasse, 15 valores)
#   family    -> família do ataque (9 valores)
#   is_attack -> alvo binário do IDS: 0 = BENIGN, 1 = qualquer ataque
#   day       -> período de captura de origem (útil para análises, nunca feature)
META_COLUMNS = ["label", "family", "is_attack", "day"]
TARGET_COLUMN = "is_attack"

# Nestas colunas o CICFlowMeter usa -1 como "valor não observado" (janela TCP
# inicial ausente, p.ex. em UDP). É um sentinela legítimo, não um erro.
SENTINEL_NEGATIVE: dict[str, float] = {
    "Init_Win_bytes_forward": -1.0,
    "Init_Win_bytes_backward": -1.0,
}

# Tempos entre pacotes (IAT, em microssegundos) levemente negativos (-1 a
# -14 µs no CICIDS2017) vêm de jitter do relógio/reordenação de pacotes na
# captura: o valor físico real é ~0. Corrigimos para 0 em vez de descartar a
# linha — descartar custaria 4 dos 11 fluxos Heartbleed. Negativos maiores
# que a tolerância continuam sendo tratados como erro (linha removida).
JITTER_TOLERANCE_US = 1_000.0

# "Destination Port" é um identificador categórico codificado como número.
# No CICIDS2017 ele permite ao modelo "decorar" o laboratório (ex.: todo
# ataque web vai para a porta 80 do mesmo servidor) em vez de aprender o
# comportamento do fluxo — um atalho (shortcut learning) apontado por Arp et
# al. (2022, "Dos and Don'ts of Machine Learning in Computer Security").
# Para XAI isso é pior ainda: o SHAP apontaria a porta como "motivo" do
# alerta, e perturbar a porta num ataque adversarial não tem sentido físico.
SHORTCUT_COLUMNS = ["Destination Port"]

log = logging.getLogger("preprocess")


# ---------------------------------------------------------------------------
# Registro das etapas (vai para metadata.json)
# ---------------------------------------------------------------------------


class StepReport:
    """Acumula, etapa por etapa, quantas linhas entraram/saíram e por quê.

    Documentar cada remoção é boa prática em ML: permite auditar se alguma
    limpeza eliminou desproporcionalmente uma classe (ex.: um ataque raro).
    """

    def __init__(self) -> None:
        self.steps: list[dict[str, object]] = []

    def rows(self, name: str, before: pd.DataFrame, removed_mask: np.ndarray, note: str) -> None:
        """Registra uma remoção de linhas, com a contagem removida por rótulo."""
        removed = before.loc[removed_mask, "label"].value_counts().to_dict()
        entry = {
            "step": name,
            "rows_before": len(before),
            "rows_removed": int(removed_mask.sum()),
            "rows_after": int(len(before) - removed_mask.sum()),
            "removed_by_label": {str(k): int(v) for k, v in removed.items()},
            "note": note,
        }
        self.steps.append(entry)
        log.info("%-28s -%9d linhas  (restam %d)", name, entry["rows_removed"], entry["rows_after"])
        if removed:
            log.info("%28s   por rótulo: %s", "", entry["removed_by_label"])

    def info(self, name: str, **details: object) -> None:
        """Registra uma etapa que não remove linhas (ex.: colunas, divisão)."""
        self.steps.append({"step": name, **details})


# ---------------------------------------------------------------------------
# 1-2. Carga e rótulos
# ---------------------------------------------------------------------------


def day_from_filename(name: str) -> str:
    """'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv' -> 'Thursday-Morning-WebAttacks'."""
    stem = name.split(".pcap")[0]
    return stem.replace("-WorkingHours", "").replace("-workingHours", "")


def load_raw(raw_dir: Path, verify_hash: bool) -> tuple[pd.DataFrame, list[dict[str, object]]]:
    """Lê os 8 CSVs, confere hashes e esquema, e concatena em um DataFrame.

    Detalhes dos CSVs originais tratados aqui:
    - nomes de coluna com espaços no início (" Flow Duration") -> ``strip()``;
    - bytes inválidos em UTF-8 nos rótulos "Web Attack" -> ``encoding_errors``;
    - todos os arquivos devem ter exatamente as mesmas colunas (checado).
    """
    frames: list[pd.DataFrame] = []
    provenance: list[dict[str, object]] = []
    reference_columns: list[str] | None = None

    for name, expected_hash in EXPECTED_FILES.items():
        path = raw_dir / name
        if not path.is_file():
            sys.exit(f"[erro] {path} não existe. Rode antes: python scripts/download_dataset.py")
        digest = sha256_of(path) if verify_hash else "not-verified"
        if verify_hash and digest != expected_hash:
            sys.exit(
                f"[erro] SHA-256 divergente em {name}. Rebaixe com download_dataset.py --force"
            )

        df = pd.read_csv(path, encoding="utf-8", encoding_errors="replace", low_memory=False)
        df.columns = [str(c).strip() for c in df.columns]
        if reference_columns is None:
            reference_columns = list(df.columns)
        elif list(df.columns) != reference_columns:
            sys.exit(f"[erro] Esquema de colunas de {name} difere dos demais arquivos")

        df = df.rename(columns={"Label": "label"})
        df["day"] = day_from_filename(name)
        frames.append(df)
        provenance.append({"name": name, "rows": len(df), "sha256": digest})
        log.info("lido %-60s %9d linhas", name, len(df))

    data = pd.concat(frames, ignore_index=True)
    return data, provenance


def normalize_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Padroniza rótulos e cria os alvos ``family`` e ``is_attack``.

    Nos CSVs originais o separador de "Web Attack – Brute Force" é um
    caractere corrompido (aparece como '�'). A regex troca qualquer sequência
    de não-letras após "Web Attack" por " - ".
    """
    df["label"] = (
        df["label"]
        .astype(str)
        .str.strip()
        .str.replace(r"^Web Attack\W+", "Web Attack - ", regex=True)
    )
    unknown = set(df["label"].unique()) - set(LABEL_TO_FAMILY)
    if unknown:
        sys.exit(f"[erro] Rótulos desconhecidos: {sorted(unknown)}. Atualize LABEL_TO_FAMILY.")
    df["family"] = df["label"].map(LABEL_TO_FAMILY)
    df["is_attack"] = (df["label"] != BENIGN).astype(np.int8)
    return df


def feature_columns(df: pd.DataFrame) -> list[str]:
    """Todas as colunas que não são alvo/metadado."""
    return [c for c in df.columns if c not in META_COLUMNS]


# ---------------------------------------------------------------------------
# 3. Colunas estruturalmente inúteis
# ---------------------------------------------------------------------------


def drop_structural_columns(
    df: pd.DataFrame, keep_port: bool, report: StepReport
) -> tuple[pd.DataFrame, dict[str, str]]:
    """Remove colunas-atalho, colunas constantes e colunas idênticas a outra.

    Por que fazer isso ANTES da divisão sem risco de vazamento? Porque não é
    uma decisão estatística (não usa rótulos nem distribuições): uma coluna
    constante em todo o dataset, ou cópia exata de outra, é inútil em
    qualquer subconjunto. Exemplos no CICIDS2017: as 6 colunas "Bulk" são
    sempre zero; ``Fwd Header Length.1`` repete ``Fwd Header Length`` e
    ``SYN Flag Count`` repete ``Fwd PSH Flags`` (defeitos conhecidos do
    CICFlowMeter).

    Também precisa vir antes da deduplicação: a deduplicação deve considerar
    apenas as colunas que o modelo realmente verá.
    """
    dropped: dict[str, str] = {}
    if not keep_port:
        for col in SHORTCUT_COLUMNS:
            if col in df.columns:
                dropped[col] = "atalho/identificador (shortcut learning)"

    # Duplicatas exatas de coluna: compara um hash do conteúdo de cada coluna
    # e confirma com comparação elemento a elemento (NaN == NaN conta como igual).
    seen: dict[str, str] = {}
    for col in feature_columns(df):
        if col in dropped:
            continue
        values = df[col].to_numpy(dtype=np.float64)
        if np.nanmin(values) == np.nanmax(values):
            dropped[col] = "constante em todo o dataset"
            continue
        key = hashlib.sha1(np.ascontiguousarray(values).tobytes()).hexdigest()
        original = seen.get(key)
        if original is not None and np.array_equal(
            values, df[original].to_numpy(dtype=np.float64), equal_nan=True
        ):
            dropped[col] = f"cópia exata de '{original}'"
        else:
            seen[key] = col

    df = df.drop(columns=list(dropped))
    for col, reason in dropped.items():
        log.info("coluna removida: %-28s (%s)", col, reason)
    report.info("drop_structural_columns", dropped_columns=dropped)
    return df, dropped


# ---------------------------------------------------------------------------
# 4. Valores inválidos
# ---------------------------------------------------------------------------


def clean_values(df: pd.DataFrame, report: StepReport) -> pd.DataFrame:
    """Remove linhas com NaN/±inf e com negativos fisicamente impossíveis.

    - ``Flow Bytes/s`` e ``Flow Packets/s`` têm NaN/inf quando o fluxo tem
      duração 0 (divisão por zero no CICFlowMeter). São ~0,1% das linhas.
      Remover é preferível a imputar: um valor inventado para uma taxa
      indefinida criaria fluxos que não existem.
    - IAT levemente negativo (jitter, >= -``JITTER_TOLERANCE_US``) é
      corrigido para 0. É uma regra por linha, sem estatística, então pode
      ser aplicada antes da divisão sem vazamento.
    - Demais negativos em durações, IAT, contagens e tamanhos de cabeçalho
      são erros de medição documentados (Engelen et al., 2021): duração
      negativa, overflow de inteiro em ``Fwd Header Length`` (-3e10) etc.
      A linha inteira é removida porque as taxas derivadas também estão
      corrompidas. Exceção: colunas de ``SENTINEL_NEGATIVE`` (-1 legítimo).

    As máscaras são calculadas coluna a coluna para não duplicar o DataFrame
    inteiro (~2 GB) na memória.
    """
    feats = feature_columns(df)
    iat_columns = [c for c in feats if "IAT" in c]

    # (a) Máscaras de linhas inválidas. Nas colunas IAT, negativos dentro da
    #     tolerância de jitter não invalidam a linha (serão corrigidos em (c)).
    non_finite = np.zeros(len(df), dtype=bool)
    negative = np.zeros(len(df), dtype=bool)
    for col in feats:
        values = df[col].to_numpy(dtype=np.float64)
        non_finite |= ~np.isfinite(values)
        floor = -JITTER_TOLERANCE_US if col in iat_columns else SENTINEL_NEGATIVE.get(col, 0.0)
        with np.errstate(invalid="ignore"):
            negative |= values < floor

    # (b) Remoção das linhas inválidas, registrando o impacto por rótulo.
    report.rows("remove_non_finite", df, non_finite, "NaN/inf em taxas de fluxos com duração 0")
    df = df.loc[~non_finite]
    negative = negative[~non_finite]
    report.rows("remove_invalid_negative", df, negative, "negativos impossíveis (erro de medição)")
    df = df.loc[~negative].reset_index(drop=True)

    # (c) Correção do jitter nas linhas que sobraram: IAT em [-tolerância, 0) -> 0.
    clipped: dict[str, int] = {}
    for col in iat_columns:
        jitter = df[col].to_numpy(dtype=np.float64) < 0
        if jitter.any():
            df.loc[jitter, col] = 0
            clipped[col] = int(jitter.sum())
            log.info("jitter corrigido para 0: %-20s %6d valores", col, clipped[col])
    report.info("clip_iat_jitter", tolerance_us=JITTER_TOLERANCE_US, clipped_values=clipped)
    return df


# ---------------------------------------------------------------------------
# 5. Duplicatas
# ---------------------------------------------------------------------------


def deduplicate(df: pd.DataFrame, report: StepReport) -> pd.DataFrame:
    """Remove fluxos com rótulos conflitantes e duplicatas exatas.

    Por que antes da divisão? Se o mesmo fluxo aparece no treino e no teste,
    o modelo é avaliado em algo que já "decorou" (vazamento), inflando as
    métricas. O CICIDS2017 tem ~11% de linhas duplicadas.

    Conflitos: vetores de features idênticos com rótulos diferentes (ex.: um
    fluxo igual rotulado BENIGN e DoS) são ruído de rotulagem — não há como
    saber o correto, então todos os membros do grupo são removidos.

    Implementação: cada linha vira um hash de 64 bits das features. Com ~2,8M
    linhas a chance de colisão é da ordem de 1e-7, desprezível.
    """
    feats = feature_columns(df)
    row_hash = pd.util.hash_pandas_object(df[feats], index=False).to_numpy()
    groups = pd.DataFrame({"h": row_hash, "label": df["label"].to_numpy()})

    n_labels = groups.groupby("h")["label"].transform("nunique").to_numpy()
    conflict = n_labels > 1
    # A maioria das linhas conflitantes são cópias de poucos vetores únicos
    # (ex.: sondas de PortScan de 1 pacote idênticas a fluxos benignos quando
    # a porta de destino é removida); o nº de vetores únicos é registrado.
    n_vectors = int(np.unique(row_hash[conflict]).size)
    report.rows(
        "remove_label_conflicts",
        df,
        conflict,
        f"mesmas features, rótulos diferentes ({n_vectors} vetores únicos)",
    )
    df = df.loc[~conflict]
    row_hash = row_hash[~conflict]

    duplicate = pd.Series(row_hash).duplicated(keep="first").to_numpy()
    report.rows("remove_exact_duplicates", df, duplicate, "fluxo repetido (mantida 1ª ocorrência)")
    return df.loc[~duplicate].reset_index(drop=True)


# ---------------------------------------------------------------------------
# 6. Divisão treino / validação / teste
# ---------------------------------------------------------------------------


def stratified_split(
    df: pd.DataFrame, val_size: float, test_size: float, seed: int
) -> dict[str, pd.DataFrame]:
    """Divisão estratificada pelo rótulo FINO (15 classes).

    Estratificar só pelo alvo binário poderia deixar ataques raros (11
    Heartbleed, ~20 SQL Injection) inteiramente fora do teste. Aqui cada
    rótulo é dividido separadamente nas proporções pedidas; classes com
    3+ exemplos têm garantido pelo menos 1 na validação e 1 no teste.

    Implementado à mão (em vez de ``train_test_split``) porque o sklearn
    falha quando uma classe tem poucos membros na segunda divisão.
    """
    rng = np.random.default_rng(seed)
    parts: dict[str, list[np.ndarray]] = {"train": [], "val": [], "test": []}
    for label, positions in sorted(df.groupby("label").indices.items()):
        positions = rng.permutation(positions)
        n = len(positions)
        n_test, n_val = round(n * test_size), round(n * val_size)
        if n >= 3:
            n_test, n_val = max(n_test, 1), max(n_val, 1)
        else:
            n_test = n_val = 0
            log.warning("rótulo '%s' tem só %d exemplo(s): vai todo para o treino", label, n)
        parts["test"].append(positions[:n_test])
        parts["val"].append(positions[n_test : n_test + n_val])
        parts["train"].append(positions[n_test + n_val :])
    return {
        name: df.iloc[np.sort(np.concatenate(idx))].reset_index(drop=True)
        for name, idx in parts.items()
    }


# ---------------------------------------------------------------------------
# 7. Balanceamento (somente treino)
# ---------------------------------------------------------------------------


def sample_per_group(
    df: pd.DataFrame, key: str, n_by_group: dict[str, int], seed: int
) -> pd.DataFrame:
    """Amostra sem reposição ``n_by_group[g]`` linhas de cada grupo ``g``."""
    pieces = [
        group.sample(n=min(len(group), n_by_group[name]), random_state=seed)
        for name, group in df.groupby(key)
    ]
    return pd.concat(pieces)


def balance_train(
    train: pd.DataFrame,
    benign_ratio: float,
    max_per_attack_class: int | None,
    seed: int,
    report: StepReport,
) -> pd.DataFrame:
    """Subamostra a classe majoritária (BENIGN) apenas no treino.

    Por que balancear? Com ~83% de BENIGN, um modelo pode ter acurácia alta
    ignorando ataques, e o SHAP/RandomForest ficam dominados pelo tráfego
    normal. Por que subamostragem e não SMOTE/oversampling?
      * SMOTE cria fluxos sintéticos por interpolação que podem ser
        fisicamente inválidos (ex.: 2,5 pacotes, flags fracionárias). Isso
        contaminaria o background do SHAP e as restrições físicas do ataque
        adversarial do projeto;
      * há BENIGN de sobra (~1,5M no treino), então descartar parte deles
        custa pouco e reduz o custo de CPU (critério CA03).

    Detalhes:
      * BENIGN é amostrado proporcionalmente por ``day`` para preservar a
        diversidade do tráfego normal de todos os dias de captura;
      * nenhum ataque é descartado, a não ser que ``max_per_attack_class``
        seja definido (limita classes enormes como DoS Hulk);
      * validação e teste NÃO são balanceados: devem refletir o tráfego real,
        senão as métricas de avaliação ficam otimistas.
    """
    attacks = train[train["is_attack"] == 1]
    benign = train[train["is_attack"] == 0]

    if max_per_attack_class:
        counts = attacks["label"].value_counts()
        attacks = sample_per_group(
            attacks, "label", {k: min(v, max_per_attack_class) for k, v in counts.items()}, seed
        )

    n_benign_target = min(len(benign), round(benign_ratio * len(attacks)))
    day_share = benign["day"].value_counts(normalize=True)
    benign = sample_per_group(
        benign, "day", {d: round(n_benign_target * s) for d, s in day_share.items()}, seed
    )

    balanced = pd.concat([benign, attacks]).sample(frac=1.0, random_state=seed)  # embaralha
    removed = ~train.index.isin(balanced.index)
    report.rows("balance_train", train, removed, f"subamostragem BENIGN (razão {benign_ratio}:1)")
    return balanced.reset_index(drop=True)


# ---------------------------------------------------------------------------
# 8. Seleção de features (ajustada no treino)
# ---------------------------------------------------------------------------


def select_features(
    train: pd.DataFrame,
    features: list[str],
    corr_threshold: float | None,
    corr_sample: int,
    seed: int,
) -> tuple[list[str], dict[str, str]]:
    """Remove features constantes e redundantes olhando SÓ para o treino.

    Constantes: não carregam informação (8 colunas de "Bulk"/flags no
    CICIDS2017 são sempre zero).

    Redundantes (|Spearman| >= limiar): por que Spearman e não Pearson?
      * árvores de decisão são invariantes a transformações monotônicas,
        então duas features com relação monotônica perfeita são equivalentes
        para o RandomForest — é exatamente isso que Spearman mede;
      * os fluxos têm caudas pesadas, onde Pearson é instável.
    Por que isso importa para XAI? O SHAP divide a atribuição entre features
    quase idênticas de forma arbitrária, o que "embaralha" o ranking de
    importância mesmo sem ataque e poluiria a medida de queda de Spearman
    do projeto (CA02).

    Regra gulosa e determinística: percorre as features na ordem original do
    CICFlowMeter e descarta a que for redundante com uma já mantida.
    A correlação é estimada numa amostra do treino (custo de CPU).
    """
    dropped: dict[str, str] = {}
    nunique = train[features].nunique()
    for col in nunique[nunique <= 1].index:
        dropped[col] = "constante no treino"
    candidates = [c for c in features if c not in dropped]

    if corr_threshold is not None:
        sample = train[candidates].sample(n=min(len(train), corr_sample), random_state=seed)
        ranks = sample.rank(method="average").to_numpy()
        with np.errstate(invalid="ignore", divide="ignore"):
            corr = np.abs(np.corrcoef(ranks, rowvar=False))
        corr = np.nan_to_num(corr, nan=0.0)
        position = {c: i for i, c in enumerate(candidates)}
        kept: list[str] = []
        for col in candidates:
            partner = next(
                (k for k in kept if corr[position[col], position[k]] >= corr_threshold), None
            )
            if partner is None:
                kept.append(col)
            else:
                rho = corr[position[col], position[partner]]
                dropped[col] = f"|spearman|={rho:.4f} com '{partner}'"
        candidates = kept

    for col, reason in dropped.items():
        log.info("feature removida: %-28s (%s)", col, reason)
    return candidates, dropped


# ---------------------------------------------------------------------------
# 9. Estatísticas por feature (insumo para o ataque adversarial)
# ---------------------------------------------------------------------------


def feature_statistics(train: pd.DataFrame, features: list[str]) -> dict[str, dict[str, object]]:
    """Resumo por feature, calculado só no treino.

    ``non_negative`` e ``integer_like`` serão usados na próxima fase para
    manter as perturbações adversariais fisicamente válidas (ex.: contagem
    de pacotes continua inteira e >= 0); ``std`` define o orçamento epsilon.
    """
    stats: dict[str, dict[str, object]] = {}
    for col in features:
        values = train[col].to_numpy(dtype=np.float64)
        stats[col] = {
            "min": float(values.min()),
            "max": float(values.max()),
            "mean": float(values.mean()),
            "median": float(np.median(values)),
            "std": float(values.std(ddof=1)),
            "zero_fraction": float(np.mean(values == 0)),
            "non_negative": bool(values.min() >= 0),
            "integer_like": bool(np.all(np.abs(values - np.round(values)) < 1e-6)),
        }
    return stats


# ---------------------------------------------------------------------------
# 10. Normalização
# ---------------------------------------------------------------------------


def build_scaler() -> Pipeline:
    """arcsinh seguido de padronização (média 0, desvio 1).

    Por que não só StandardScaler? As features de fluxo têm caudas enormes
    (ex.: ``Flow Bytes/s`` vai de 0 a ~2e9). Padronizar direto deixaria quase
    todos os valores espremidos perto de zero. ``arcsinh(x)`` comprime a
    cauda como um log (≈ log(2x) para x grande), mas, ao contrário de
    ``log1p``, aceita os negativos-sentinela (-1) e é inversível exatamente
    (``sinh``) — útil para levar perturbações do espaço normalizado de volta
    ao espaço físico no ataque adversarial.

    Observação: o RandomForest (modelo previsto no projeto) não precisa de
    normalização, pois árvores só comparam limiares. O scaler é exportado
    para modelos sensíveis a escala (MLP, regressão logística, SVM, KNN).
    """
    pipeline = Pipeline(
        [
            (
                "arcsinh",
                FunctionTransformer(
                    np.arcsinh,
                    inverse_func=np.sinh,
                    feature_names_out="one-to-one",
                    check_inverse=False,
                ),
            ),
            ("standardize", StandardScaler()),
        ]
    )
    return pipeline.set_output(transform="pandas")


# ---------------------------------------------------------------------------
# 11. Exportação
# ---------------------------------------------------------------------------


def distribution(df: pd.DataFrame) -> dict[str, object]:
    """Contagens por rótulo, família e alvo binário (para o metadata.json)."""
    return {
        "rows": len(df),
        "attack_rate": float(df["is_attack"].mean()),
        "by_label": {str(k): int(v) for k, v in df["label"].value_counts().items()},
        "by_family": {str(k): int(v) for k, v in df["family"].value_counts().items()},
    }


def write_parquet(df: pd.DataFrame, path: Path) -> dict[str, object]:
    """Salva em Parquet (colunar, tipado, comprimido) e retorna a proveniência.

    Parquet em vez de CSV: preserva tipos (float64/int8/string), é ~10x menor com
    zstd e ~10x mais rápido de ler — ideal para não reprocessar a cada treino.
    """
    df.to_parquet(path, index=False, compression="zstd")
    log.info("salvo %-26s %9d linhas  %7.1f MB", path.name, len(df), path.stat().st_size / 1e6)
    return {"file": path.name, "rows": len(df), "sha256": sha256_of(path)}


# ---------------------------------------------------------------------------
# Programa principal
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trata o CICIDS2017 e exporta treino/validação/teste prontos para IA.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW_DIR, help="CSVs brutos")
    p.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="saída processada")
    p.add_argument("--seed", type=int, default=42, help="semente de todas as amostragens")
    p.add_argument("--val-size", type=float, default=0.15, help="fração de validação")
    p.add_argument("--test-size", type=float, default=0.15, help="fração de teste")
    p.add_argument(
        "--benign-ratio",
        type=float,
        default=1.0,
        help="nº de BENIGN por ataque no treino balanceado (1.0 = 50/50)",
    )
    p.add_argument("--no-balance", action="store_true", help="não balanceia o treino")
    p.add_argument(
        "--max-per-attack-class",
        type=int,
        default=None,
        help="limite de exemplos por rótulo de ataque no treino (padrão: sem limite)",
    )
    p.add_argument(
        "--corr-threshold", type=float, default=0.99, help="limiar |Spearman| de redundância"
    )
    p.add_argument("--no-corr-filter", action="store_true", help="não remove redundantes")
    p.add_argument(
        "--corr-sample", type=int, default=200_000, help="linhas usadas para estimar Spearman"
    )
    p.add_argument("--keep-destination-port", action="store_true", help="mantém 'Destination Port'")
    p.add_argument(
        "--export-natural-train",
        action="store_true",
        help="também salva o treino NÃO balanceado (train_natural.parquet)",
    )
    p.add_argument("--no-scaled", action="store_true", help="não exporta versões normalizadas")
    p.add_argument("--skip-hash", action="store_true", help="não verifica SHA-256 dos CSVs")
    p.add_argument(
        "--sample-frac",
        type=float,
        default=1.0,
        help="usa só esta fração dos dados (APENAS para testes rápidos)",
    )
    args = p.parse_args()
    if not 0 < args.val_size + args.test_size < 1:
        p.error("--val-size + --test-size deve estar entre 0 e 1")
    if not 0 < args.sample_frac <= 1:
        p.error("--sample-frac deve estar em (0, 1]")
    return args


def main() -> None:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")
    t0 = time.time()
    out_dir: Path = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    report = StepReport()

    # --- 1-2. Carga e rótulos ---------------------------------------------
    log.info("== 1. Carga dos CSVs brutos de %s", args.raw_dir)
    df, raw_provenance = load_raw(args.raw_dir.resolve(), verify_hash=not args.skip_hash)
    df = normalize_labels(df)
    if args.sample_frac < 1:
        log.warning("usando só %.1f%% dos dados (--sample-frac)", 100 * args.sample_frac)
        df = df.groupby("label").sample(frac=args.sample_frac, random_state=args.seed)
        df = df.reset_index(drop=True)
    raw_distribution = distribution(df)
    original_features = feature_columns(df)
    report.info("load", rows=len(df), n_features=len(original_features))

    # --- 3-5. Limpeza que independe da divisão ----------------------------
    log.info("== 2. Limpeza estrutural, de valores e duplicatas")
    df, structural_dropped = drop_structural_columns(df, args.keep_destination_port, report)
    df = clean_values(df, report)
    df = deduplicate(df, report)
    clean_distribution = distribution(df)

    # --- 6. Divisão -------------------------------------------------------
    log.info("== 3. Divisão estratificada treino/val/teste")
    splits = stratified_split(df, args.val_size, args.test_size, args.seed)
    del df  # libera ~1,5 GB de memória
    for name, part in splits.items():
        log.info(
            "%-5s %9d linhas  (taxa de ataque %.3f)", name, len(part), part["is_attack"].mean()
        )
    report.info("split", sizes={k: len(v) for k, v in splits.items()}, stratify_by="label")

    # Pesos de classe do treino natural: alternativa ao balanceamento para quem
    # quiser treinar com ``class_weight`` (ex.: --no-balance).
    natural_train = splits["train"]
    class_weights = compute_class_weight(
        "balanced", classes=np.array([0, 1]), y=natural_train["is_attack"].to_numpy()
    )
    natural_train_distribution = distribution(natural_train)

    # --- 7. Balanceamento (só treino) --------------------------------------
    log.info("== 4. Balanceamento do treino")
    if args.no_balance:
        train = natural_train
        report.info("balance_train", skipped=True)
    else:
        train = balance_train(
            natural_train, args.benign_ratio, args.max_per_attack_class, args.seed, report
        )
    if not args.export_natural_train:
        del natural_train
    log.info("treino final: %d linhas (taxa de ataque %.3f)", len(train), train["is_attack"].mean())

    # --- 8. Seleção de features (ajustada no treino final) -----------------
    log.info("== 5. Seleção de features (ajustada no treino)")
    features, selection_dropped = select_features(
        train,
        feature_columns(train),
        None if args.no_corr_filter else args.corr_threshold,
        args.corr_sample,
        args.seed,
    )
    report.info("select_features", dropped_columns=selection_dropped, n_kept=len(features))
    log.info("%d features finais", len(features))

    # Monta os conjuntos finais com colunas em ordem fixa: features + metadados.
    # Features em float64 uniforme: evita erros quando a etapa de ataque
    # escrever perturbações fracionárias em colunas originalmente inteiras
    # (a natureza inteira fica registrada em ``integer_like`` no metadata).
    def finalize(part: pd.DataFrame) -> pd.DataFrame:
        return part[features].astype(np.float64).join(part[META_COLUMNS])

    final = {
        "train": finalize(train),
        "val": finalize(splits["val"]),
        "test": finalize(splits["test"]),
    }
    if args.export_natural_train:
        final["train_natural"] = finalize(natural_train)

    # --- 9. Estatísticas das features --------------------------------------
    stats = feature_statistics(final["train"], features)

    # --- 10-11. Normalização e exportação ----------------------------------
    log.info("== 6. Normalização e exportação para %s", out_dir)
    outputs = [write_parquet(part, out_dir / f"{name}.parquet") for name, part in final.items()]

    scaler_info: dict[str, object] | None = None
    if not args.no_scaled:
        scaler = build_scaler().fit(final["train"][features])  # fit SÓ no treino
        for name, part in final.items():
            # float32 basta para valores padronizados (~7 dígitos) e reduz o
            # arquivo; os dados brutos ficam em float64 porque contadores
            # chegam a ~3e10 e perderiam exatidão inteira em float32.
            scaled = scaler.transform(part[features]).astype(np.float32)
            scaled = scaled.join(part[META_COLUMNS])  # alinha pelo índice
            outputs.append(write_parquet(scaled, out_dir / f"{name}_scaled.parquet"))
        scaler_path = out_dir / "scaler.joblib"
        joblib.dump(scaler, scaler_path)
        scaler_info = {
            "file": scaler_path.name,
            "steps": ["arcsinh", "StandardScaler"],
            "fitted_on": "train",
            "usage": "joblib.load(path).transform(X[features]); inverso: inverse_transform",
        }

    # --- metadata.json: tudo o que é preciso para entender/reproduzir -------
    metadata = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "elapsed_seconds": round(time.time() - t0, 1),
        "config": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
        "environment": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit-learn": sklearn.__version__,
        },
        "raw_files": raw_provenance,
        "columns": {
            "features": features,
            "target": TARGET_COLUMN,
            "target_encoding": {"0": BENIGN, "1": "attack (any family)"},
            "metadata_columns": META_COLUMNS,
            "label_to_family": LABEL_TO_FAMILY,
        },
        "feature_selection": {
            "original_features": original_features,
            "dropped_structural": structural_dropped,
            "dropped_on_train": selection_dropped,
        },
        "steps": report.steps,
        "distributions": {
            "raw": raw_distribution,
            "after_cleaning": clean_distribution,
            "train_natural": natural_train_distribution,
            **{name: distribution(part) for name, part in final.items()},
        },
        "class_weights_natural_train": {"0": float(class_weights[0]), "1": float(class_weights[1])},
        "feature_statistics_train": stats,
        "scaler": scaler_info,
        "outputs": outputs,
    }
    meta_path = out_dir / "metadata.json"
    meta_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("salvo %s", meta_path.name)
    log.info("== Concluído em %.0f s. Dados prontos em %s", time.time() - t0, out_dir)


if __name__ == "__main__":
    main()
