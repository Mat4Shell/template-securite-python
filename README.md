# Template code Sécurité Python

## Description

Projet contenant les modèles de TP pour le cours de sécurité Python de 4e année de l'ESGI.

## Installation

Faire un fork puis un clone du projet :
```bash
git clone git@github.com:<VotreNom>/template-securite-python.git
```

Installer les dépendances :
```bash
cd template-securite-python
poetry lock
poetry install
```

## Utilisation

### TP1 - Analyse réseau et détection de menaces (IDS/IPS)

Capture et analyse le trafic réseau, génère un rapport PDF avec graphiques et détection d'attaques (ARP Spoofing, Port Scanning, ICMP Flood, SQL Injection).
```bash
poetry run tp1
```

### TP2 - Analyse de shellcode

Analyse statique et dynamique de shellcodes via extraction de strings, désassemblage Capstone, émulation pylibemu et explication LLM.
```bash
# Définir la clé API Anthropic (PowerShell)
$env:ANTHROPIC_API_KEY = "sk-ant-..."

# Analyser un shellcode
poetry run tp2 -f shellcodes/easy.txt
poetry run tp2 -f shellcodes/medium.txt
poetry run tp2 -f shellcodes/hard.txt

# Sans analyse LLM
poetry run tp2 -f shellcodes/easy.txt --no-llm
```

### TP3 - CAPTCHA solver

Contournement automatique de CAPTCHAs.
```bash
poetry run tp3
```

## Tests
```bash
# Tous les tests
poetry run pytest

# Par TP
poetry run pytest tests/tp1/
poetry run pytest tests/tp2/
poetry run pytest tests/tp3/
```