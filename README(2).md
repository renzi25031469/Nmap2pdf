<div align="center">


<br/>

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![ReportLab](https://img.shields.io/badge/ReportLab-PDF-FF0000?style=flat-square)
![Nmap](https://img.shields.io/badge/Nmap-XML-4B8BBE?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)

**Converta relatórios Nmap XML em PDFs executivos de segurança — com análise de risco, recomendações e visual profissional.**

</div>

---

## Sumário

- [Visão Geral](#visão-geral)
- [Funcionalidades](#funcionalidades)
- [Estrutura do Relatório PDF](#estrutura-do-relatório-pdf)
- [Classificação de Risco](#classificação-de-risco)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Como Usar](#como-usar)
- [Exemplos](#exemplos)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Como Contribuir](#como-contribuir)
- [Licença](#licença)

---

## Visão Geral

O **Nmap2pdf** é uma ferramenta de linha de comando que transforma arquivos XML gerados pelo Nmap em relatórios PDF executivos prontos para apresentação a equipes de segurança, gestores ou clientes. O relatório inclui sumário executivo, detalhamento de hosts, análise de portas com classificação de risco e recomendações de remediação baseadas exclusivamente nos achados do scan.

```
            XML  ──────────────►  PDF
   ┌─────────────────┐      ┌──────────────────────┐
   │  nmap -sV -sC   │      │  • Capa executiva     │
   │  -O target.xml  │  →   │  • Sumário de riscos  │
   │                 │      │  • Detalhamento hosts  │
   │  scan.xml       │      │  • Recomendações       │
   └─────────────────┘      └──────────────────────┘
```

---

## Funcionalidades

- **Capa profissional** com título, nome da empresa, autor e data da varredura
- **Sumário executivo** com estatísticas de hosts e distribuição de risco por nível
- **Detalhamento de hosts** com IP, hostname, MAC, sistema operacional detectado e portas
- **Análise de portas abertas** com serviço, versão, protocolo e classificação de risco
- **Saída de scripts NSE** exibida inline por porta e por host
- **Recomendações de segurança** geradas dinamicamente — apenas para portas encontradas no scan
- **Suporte a múltiplos arquivos XML** em um único relatório consolidado
- **Tema dark profissional** com paleta cybersecurity (fundo `#0D1117`, acentos azul/cyan)
- **Rodapé com paginação**, autor e nome da empresa em todas as páginas
- **Banner ANSI colorido** no terminal com gradiente cyan → azul → magenta

---

## Estrutura do Relatório PDF

```
┌──────────────────────────────────┐
│           CAPA                   │  Título, empresa, autor, data
├──────────────────────────────────┤
│     1. SUMÁRIO EXECUTIVO         │  Hosts up/down, portas abertas,
│                                  │  serviços únicos, distribuição
│                                  │  de riscos CRITICAL→INFO
├──────────────────────────────────┤
│     2. DETALHAMENTO DOS HOSTS    │  Por host ativo:
│                                  │  • Endereço IP / MAC / hostname
│                                  │  • SO detectado (osmatch)
│                                  │  • Tabela de portas abertas
│                                  │    com risco colorido
│                                  │  • Saída de scripts NSE
│                                  │  • Resumo de portas fechadas
├──────────────────────────────────┤
│     3. RECOMENDAÇÕES             │  Ações priorizadas por nível,
│                                  │  geradas apenas para portas
│                                  │  encontradas no scan
├──────────────────────────────────┤
│     4. INFORMAÇÕES DA VARREDURA  │  Versão Nmap, argumentos,
│                                  │  duração, arquivo de origem
└──────────────────────────────────┘
```

---

## Classificação de Risco

Cada porta aberta recebe automaticamente um nível de risco com base em um mapeamento interno de vulnerabilidades conhecidas:

| Nível | Cor | Exemplos de Portas |
|-------|-----|--------------------|
| `CRITICAL` | 🔴 Vermelho | 23 (Telnet), 445 (SMB), 512–514 (rsh/rexec), 6379 (Redis), 27017 (MongoDB) |
| `HIGH` | 🟠 Laranja | 21 (FTP), 135 (MS RPC), 139 (NetBIOS), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL) |
| `MEDIUM` | 🟡 Amarelo | 53 (DNS), 80 (HTTP), 389 (LDAP), 8080 (HTTP alt) |
| `LOW` | 🟢 Verde | 443 (HTTPS), 8443 (HTTPS alt) |
| `INFO` | 🔵 Azul | Demais serviços não catalogados |

> As recomendações de segurança são filtradas dinamicamente — somente as portas **efetivamente encontradas abertas** no scan geram recomendações no relatório.

---

## Pré-requisitos

- Python **3.10** ou superior
- [Nmap](https://nmap.org/) instalado (para gerar os arquivos XML)

### Gerar o XML com Nmap

```bash
# Scan básico com detecção de versão e OS
nmap -sV -sC -O -oX scan.xml 192.168.1.0/24

# Scan completo com scripts NSE
nmap -sV -sC -O -A --script=vuln -oX scan_full.xml 192.168.1.1

# Múltiplos alvos
nmap -sV -oX scan.xml 10.0.0.0/24 172.16.0.0/24
```

---

## Instalação

```bash
# 1. Clone o repositório
git clone https://github.com/seu-usuario/nmap2pdf.git
cd nmap2pdf

# 2. (Opcional) Crie um ambiente virtual
python3 -m venv .venv
source .venv/bin/activate       # Linux / macOS
.venv\Scripts\activate          # Windows

# 3. Instale a dependência
pip install reportlab
```

### Dependências

| Pacote | Versão mínima | Uso |
|--------|--------------|-----|
| `reportlab` | 4.0+ | Geração do PDF |
| `xml.etree.ElementTree` | stdlib | Parsing do XML do Nmap |
| `argparse` | stdlib | Interface de linha de comando |

---

## Como Usar

```
usage: nmap_to_pdf.py [-h] [-o OUTPUT] [--author AUTHOR] [--company COMPANY]
                      [FILE.xml ...]

positional arguments:
  FILE.xml              Um ou mais arquivos XML gerados pelo Nmap

options:
  -h, --help            Exibe ajuda e sai
  -o, --output OUTPUT   Nome do PDF de saída
                        (padrão: network_scanning_report.pdf)
  --author  AUTHOR      Nome do responsável (aparece na capa e rodapé)
  --company COMPANY     Nome da empresa/equipe (aparece na capa)
```

> Executar o script **sem argumentos** ou com `-h` exibe o banner e a ajuda completa.

---

## Exemplos

### Uso básico

```bash
python nmap_to_pdf.py scan.xml
```

### Com autor e empresa

```bash
python nmap_to_pdf.py scan.xml \
  --author "Carlos Mendes" \
  --company "SecTeam Brasil" \
  -o relatorio_rede.pdf
```

### Múltiplos arquivos XML → relatório consolidado

```bash
python nmap_to_pdf.py scan_dmz.xml scan_intranet.xml scan_servidores.xml \
  --author "Time de Segurança" \
  --company "ACME Corp" \
  -o pentest_completo.pdf
```

### Pipeline Nmap → PDF direto

```bash
nmap -sV -sC -O -oX /tmp/scan.xml 192.168.0.0/24 && \
python nmap_to_pdf.py /tmp/scan.xml --author "Analista" -o resultado.pdf
```

---

## Estrutura do Projeto

```
nmap2pdf/
├── nmap_to_pdf.py       # Script principal
├── README.md            # Este arquivo
├── requirements.txt     # Dependências (reportlab)
└── examples/
    └── sample_scan.xml  # XML de exemplo para testes
```

### `requirements.txt`

```
reportlab>=4.0
```

---

## Como Contribuir

Contribuições são bem-vindas! Para adicionar suporte a novas portas no mapeamento de risco, edite o dicionário `RISK_MAP` e o catálogo `REC_CATALOG` dentro de `nmap_to_pdf.py`:

```python
RISK_MAP = {
    "8888": ("HIGH", "Jupyter Notebook exposto sem autenticação"),
    # ...
}

REC_CATALOG = {
    "8888": ("HIGH", "Proteger Jupyter Notebook (8888)",
             "Habilitar autenticação por token ou senha. "
             "Nunca expor publicamente sem VPN."),
    # ...
}
```

### Fluxo de contribuição

```bash
# Fork → clone → branch
git checkout -b feature/nova-porta

# Edite, teste, commit
python nmap_to_pdf.py examples/sample_scan.xml -o /tmp/test.pdf

git commit -m "feat: adiciona mapeamento para porta 8888 (Jupyter)"
git push origin feature/nova-porta
# Abra um Pull Request
```

---

## Licença

Distribuído sob a licença **MIT**. Veja [`LICENSE`](LICENSE) para detalhes.

---

<div align="center">

Feito com Python e ReportLab &nbsp;·&nbsp; Para uso em assessments de segurança

</div>
