#!/usr/bin/env python3
"""Etapa 1 do pipeline: download e verificação do dataset CICIDS2017.

O que este script faz
---------------------
1. Verifica se os 8 CSVs oficiais do CICIDS2017 ("MachineLearningCVE", um CSV
   por período de captura) já estão em ``data/raw/`` e íntegros. Se estiverem,
   não baixa nada de novo (execução idempotente).
2. Caso contrário, baixa o dataset do Kaggle com ``kagglehub`` (datasets
   públicos não exigem credenciais).
3. Localiza os CSVs dentro do pacote baixado (o Kaggle os coloca em uma
   subpasta) e os copia, com nomes originais, para ``data/raw/``.
4. Verifica a integridade de cada arquivo com SHA-256 contra um manifesto fixo
   (``EXPECTED_FILES``) e confere se o cabeçalho tem a coluna ``Label``.
5. Grava ``data/raw/download_manifest.json`` com a proveniência (origem, data,
   tamanho e hash de cada arquivo), usada depois pelo script de tratamento.

Por que fixar os hashes?
    Espelhos do CICIDS2017 na internet NÃO são idênticos: alguns trocam
    colunas, renomeiam rótulos ou removem linhas. Fixar o SHA-256 garante que
    todo o grupo trabalhe exatamente com os mesmos bytes, o que é pré-requisito
    para resultados reprodutíveis no benchmark de XAI.

Uso
---
    python scripts/download_dataset.py                 # baixa se necessário
    python scripts/download_dataset.py --force         # rebaixa do zero
    python scripts/download_dataset.py --out-dir /outro/caminho
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

# Raiz do subprojeto (src/ids-xai-audit/), calculada a partir deste arquivo
# para que o script funcione independentemente do diretório de onde é chamado.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT_DIR = PROJECT_ROOT / "data" / "raw"

# Espelho do Kaggle com os CSVs oficiais "MachineLearningCVE" do CIC/UNB.
# Os hashes abaixo foram conferidos contra esse espelho; o link oficial da UNB
# (cicresearch.ca) exige formulário e frequentemente devolve HTML em vez do ZIP.
DEFAULT_KAGGLE_DATASET = "mdalamintalukder/cicids2017"

# Manifesto: nome do arquivo -> SHA-256 esperado. São os 8 períodos de captura
# (segunda a sexta, 03 a 07/07/2017) descritos por Sharafaldin et al. (2018).
EXPECTED_FILES: dict[str, str] = {
    "Monday-WorkingHours.pcap_ISCX.csv": (
        "852c4beb34eda186f32561fa79df7a0747e92e1a6535b01270820dd9ffe17f34"
    ),
    "Tuesday-WorkingHours.pcap_ISCX.csv": (
        "52b8692ae8c7d2ed04671fe2b98335693c0a92c7ab157d8c8b534d6523080851"
    ),
    "Wednesday-workingHours.pcap_ISCX.csv": (
        "893c27dc968bf7a8adef1689f90be55ca4a4dc3088fb63d6ff247ac56856df2a"
    ),
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": (
        "d67066211fb1689c78406f1506f4c44704ecb92088353d5c96d96d6474eb819d"
    ),
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv": (
        "6bcda3857c2504676034e3ea57762d38393cc734cb377a726bd5cb153961b1b5"
    ),
    "Friday-WorkingHours-Morning.pcap_ISCX.csv": (
        "53a41c24d570ea83b7ac55b2e94df94e7a8216aeb80a2af0246b6bc8bb543000"
    ),
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv": (
        "ca1824c51bfbb7b3c72290a11be04366ba8815878c6a1cc5c44cb1cee269e99b"
    ),
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": (
        "6ff1580f5f81c0ae28a26f7631721018577f5f7c5e0feac28b795fcfe7b411ee"
    ),
}

MANIFEST_NAME = "download_manifest.json"


# ---------------------------------------------------------------------------
# Funções auxiliares
# ---------------------------------------------------------------------------


def sha256_of(path: Path) -> str:
    """Calcula o SHA-256 de um arquivo lendo em blocos de 1 MiB.

    Ler em blocos evita carregar arquivos de ~200 MB inteiros na memória.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def has_label_column(path: Path) -> bool:
    """Confere, lendo só a 1ª linha, se o CSV tem a coluna ``Label``.

    Os CSVs originais têm espaços no início dos nomes (ex.: ``" Label"``),
    por isso comparamos após ``strip()``.
    """
    with open(path, encoding="utf-8", errors="replace") as fh:
        header = fh.readline()
    return any(col.strip().lower() == "label" for col in header.split(","))


def verify_files(out_dir: Path, check_hash: bool = True) -> list[str]:
    """Retorna a lista de problemas encontrados (lista vazia = tudo certo)."""
    problems: list[str] = []
    for name, expected in EXPECTED_FILES.items():
        path = out_dir / name
        if not path.is_file():
            problems.append(f"ausente: {name}")
            continue
        if not has_label_column(path):
            problems.append(f"sem coluna Label: {name}")
            continue
        if check_hash and sha256_of(path) != expected:
            problems.append(f"hash divergente: {name}")
    return problems


def download_with_kagglehub(dataset: str, force: bool) -> Path:
    """Baixa o dataset via kagglehub e retorna o diretório onde ele ficou.

    O kagglehub guarda os arquivos em cache (``~/.cache/kagglehub``); se o
    download já tiver sido feito antes, ele apenas devolve o caminho do cache.
    """
    try:
        import kagglehub  # import tardio: só é necessário se for baixar
    except ImportError:
        sys.exit("kagglehub não instalado. Rode: pip install -r requirements.txt")

    print(f"[download] Baixando '{dataset}' via kagglehub (pode levar alguns minutos)...")
    return Path(kagglehub.dataset_download(dataset, force_download=force))


def collect_csvs(source_dir: Path, out_dir: Path) -> None:
    """Procura os CSVs esperados (recursivamente) e copia para ``out_dir``.

    Copiamos em vez de mover para não corromper o cache do kagglehub (que
    marcaria o download como completo sem os arquivos).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    found = {p.name: p for p in source_dir.rglob("*.csv")}
    for name in EXPECTED_FILES:
        if name not in found:
            sys.exit(f"[erro] '{name}' não encontrado no pacote baixado em {source_dir}")
        dst = out_dir / name
        shutil.copy2(found[name], dst)
        print(f"[download] {name:<62} {dst.stat().st_size / 1e6:8.1f} MB")


def write_manifest(out_dir: Path, dataset: str) -> None:
    """Salva a proveniência dos arquivos brutos em JSON (reprodutibilidade)."""
    manifest = {
        "dataset": "CICIDS2017 (MachineLearningCVE)",
        "source": f"kaggle:{dataset}",
        "reference": (
            "Sharafaldin, Lashkari, Ghorbani (2018). Toward Generating a New "
            "Intrusion Detection Dataset and Intrusion Traffic Characterization. ICISSP."
        ),
        "downloaded_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": [
            {
                "name": name,
                "bytes": (out_dir / name).stat().st_size,
                "sha256": sha256_of(out_dir / name),
            }
            for name in EXPECTED_FILES
        ],
    }
    (out_dir / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Programa principal
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=DEFAULT_OUT_DIR,
        help=f"Destino dos CSVs brutos (padrão: {DEFAULT_OUT_DIR})",
    )
    parser.add_argument(
        "--dataset",
        default=DEFAULT_KAGGLE_DATASET,
        help="Identificador do dataset no Kaggle (padrão: %(default)s)",
    )
    parser.add_argument(
        "--force", action="store_true", help="Ignora arquivos existentes e baixa novamente"
    )
    parser.add_argument(
        "--skip-hash",
        action="store_true",
        help="Não verifica SHA-256 (use só se escolher outro espelho de propósito)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    out_dir: Path = args.out_dir.resolve()
    check_hash = not args.skip_hash

    # 1) Execução idempotente: se já está tudo íntegro, não faz nada.
    if not args.force and not verify_files(out_dir, check_hash):
        print(f"[ok] Os {len(EXPECTED_FILES)} CSVs já estão íntegros em {out_dir}")
        if not (out_dir / MANIFEST_NAME).exists():
            write_manifest(out_dir, args.dataset)
        return

    # 2) Download + 3) cópia dos CSVs para data/raw/.
    source_dir = download_with_kagglehub(args.dataset, args.force)
    collect_csvs(source_dir, out_dir)

    # 4) Verificação de integridade: aborta com erro se algo não bater.
    problems = verify_files(out_dir, check_hash)
    if problems:
        print("[erro] Falha na verificação dos arquivos:")
        for problem in problems:
            print(f"  - {problem}")
        sys.exit(1)

    # 5) Registro de proveniência.
    write_manifest(out_dir, args.dataset)
    print(f"[ok] Dataset verificado (SHA-256) e salvo em {out_dir}")
    print("[ok] Próximo passo: python scripts/preprocess_dataset.py")


if __name__ == "__main__":
    main()
