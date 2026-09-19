# Install dependencies as needed:
import os
import kagglehub
from kagglehub import KaggleDatasetAdapter
import numpy as np
import subprocess
from dotenv import load_dotenv

load_dotenv()

output_dir = str(os.getenv("M_PATH"))
print(f"PATH: {output_dir} e tipo: {type(output_dir)}")

commands = [
    "python3 -m venv venv",
    "source venv/bin/activate",
    "pip install -r requirements.txt"]

for command in commands:
    resultado = subprocess.run(command, shell=True)
    print(resultado)

path = kagglehub.dataset_download(
    "chethuhn/network-intrusion-dataset",
    output_dir="../data/"
)

print(f"Dataset baixado em: {output_dir} e tipo: {type(output_dir)}")