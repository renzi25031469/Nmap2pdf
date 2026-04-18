#!/usr/bin/env python3
"""
nmap_to_pdf.py — Converte relatórios Nmap (XML) em PDF executivo.
Uso:
    python nmap_to_pdf.py scan.xml -o relatorio.pdf
    python nmap_to_pdf.py scan.xml -o relatorio.pdf --author "João Silva" --company "ACME Sec"
    python nmap_to_pdf.py *.xml  -o relatorio.pdf --author "Time de Segurança"
"""

# ──────────────────────────────────────────────
# ANSI color codes
# ──────────────────────────────────────────────
_R  = "\033[0m"       # reset
_B  = "\033[1;34m"    # blue bold
_C  = "\033[1;36m"    # cyan bold
_G  = "\033[1;32m"    # green bold
_Y  = "\033[1;33m"    # yellow bold
_D  = "\033[2;37m"    # dim white
_W  = "\033[1;37m"    # white bold
_M  = "\033[1;35m"    # magenta bold


def print_banner() -> None:
    # fonte: graffiti (pyfiglet)
    art = [
        " _______                        ________            .___ _____ ",
        " \\      \\   _____ _____  ______ \\_____  \\______   __| _// ____\\",
        " /   |   \\ /     \\\\__  \\ \\____ \\ /  ____/\\____ \\ / __ |\\   __\\ ",
        "/    |    \\  Y Y  \\/ __ \\|  |_> >       \\|  |_> > /_/ | |  |  ",
        "\\____|__  /__|_|  (____  /   __/\\_______ \\   __/\\____ | |__|   ",
        "        \\/      \\/     \\/|__|            \\/__|        \\/        ",
    ]

    W = 72
    top = f"{_B}╔{'═'*W}╗{_R}"
    mid = f"{_B}╠{'═'*W}╣{_R}"
    bot = f"{_B}╚{'═'*W}╝{_R}"
    row = lambda content, color="": (
        f"{_B}║{_R}{color}{content:<{W}}{_R}{_B}║{_R}"
    )

    print()
    print(top)
    print(row(""))
    # art com gradiente cyan → azul → magenta
    grad = [_C, _C, _B, _B, _M, _M]
    for line, color in zip(art, grad):
        print(row(f"  {line}", color))
    print(row(""))
    print(mid)

    sub_l = "        nmap xml  ›  executive pdf security report by Renzi"
    sub_r = ""
    gap   = W - len(sub_l) - len(sub_r)
    print(f"{_B}║{_R}{_D}{sub_l}{' '*gap}{sub_r}{_R}{_B}║{_R}")

    tags = [
        (_Y,  " [ network scanning ] "),
        (_C,  " [ risk assessment ] "),
        (_M,  " [ pdf report ] "),
    ]
    tag_plain = "".join(t for _, t in tags)
    pad_left  = (W - len(tag_plain)) // 2
    pad_right = W - len(tag_plain) - pad_left
    tag_colored = "".join(f"{c}{t}{_R}" for c, t in tags)
    print(f"{_B}║{_R}{' '*pad_left}{tag_colored}{' '*pad_right}{_B}║{_R}")

    print(bot)
    print()

import argparse
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    HRFlowable,
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ──────────────────────────────────────────────
# Paleta de cores (tema escuro/profissional)
# ──────────────────────────────────────────────
C_BG         = colors.HexColor("#0D1117")
C_SURFACE    = colors.HexColor("#161B22")
C_BORDER     = colors.HexColor("#30363D")
C_ACCENT     = colors.HexColor("#58A6FF")
C_ACCENT2    = colors.HexColor("#1F6FEB")
C_TEXT       = colors.HexColor("#E6EDF3")
C_MUTED      = colors.HexColor("#8B949E")
C_CRITICAL   = colors.HexColor("#F85149")
C_HIGH       = colors.HexColor("#FF8C00")
C_MEDIUM     = colors.HexColor("#D29922")
C_LOW        = colors.HexColor("#3FB950")
C_INFO       = colors.HexColor("#58A6FF")
C_WHITE      = colors.white
C_OPEN       = colors.HexColor("#3FB950")
C_CLOSED     = colors.HexColor("#F85149")
C_FILTERED   = colors.HexColor("#D29922")


# ──────────────────────────────────────────────
# Helpers de parsing XML
# ──────────────────────────────────────────────

def parse_nmap_xml(xml_path: str) -> dict:
    """Extrai tudo que interessa de um arquivo XML do Nmap."""
    tree = ET.parse(xml_path)
    root = tree.getroot()

    meta = {
        "args":      root.get("args", ""),
        "version":   root.get("version", ""),
        "start":     root.get("startstr", ""),
        "elapsed":   "",
        "hosts_up":  0,
        "hosts_down": 0,
        "hosts_total": 0,
    }

    runstats = root.find("runstats")
    if runstats is not None:
        fin = runstats.find("finished")
        if fin is not None:
            meta["elapsed"]  = fin.get("elapsed", "")
        hs = runstats.find("hosts")
        if hs is not None:
            meta["hosts_up"]    = int(hs.get("up",    0))
            meta["hosts_down"]  = int(hs.get("down",  0))
            meta["hosts_total"] = int(hs.get("total", 0))

    hosts = []
    for host_el in root.findall("host"):
        state_el = host_el.find("status")
        state    = state_el.get("state", "unknown") if state_el is not None else "unknown"

        # endereços
        addrs = {}
        for addr_el in host_el.findall("address"):
            addrs[addr_el.get("addrtype", "ipv4")] = addr_el.get("addr", "")

        # hostname
        hostnames = []
        hn_el = host_el.find("hostnames")
        if hn_el is not None:
            for hn in hn_el.findall("hostname"):
                hostnames.append(hn.get("name", ""))

        # OS
        os_matches = []
        os_el = host_el.find("os")
        if os_el is not None:
            for om in os_el.findall("osmatch"):
                os_matches.append({
                    "name":     om.get("name", ""),
                    "accuracy": om.get("accuracy", ""),
                })

        # portas
        ports = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                p_state = port_el.find("state")
                p_svc   = port_el.find("service")
                p_scripts = []
                for sc in port_el.findall("script"):
                    p_scripts.append({
                        "id":     sc.get("id", ""),
                        "output": sc.get("output", ""),
                    })
                ports.append({
                    "protocol": port_el.get("protocol", ""),
                    "portid":   port_el.get("portid", ""),
                    "state":    p_state.get("state", "") if p_state is not None else "",
                    "reason":   p_state.get("reason", "") if p_state is not None else "",
                    "service":  p_svc.get("name", "") if p_svc is not None else "",
                    "product":  p_svc.get("product", "") if p_svc is not None else "",
                    "version":  p_svc.get("version", "") if p_svc is not None else "",
                    "extrainfo":p_svc.get("extrainfo", "") if p_svc is not None else "",
                    "scripts":  p_scripts,
                })

        # scripts de host
        host_scripts = []
        hs_el = host_el.find("hostscript")
        if hs_el is not None:
            for sc in hs_el.findall("script"):
                host_scripts.append({
                    "id":     sc.get("id", ""),
                    "output": sc.get("output", ""),
                })

        hosts.append({
            "state":        state,
            "addrs":        addrs,
            "hostnames":    hostnames,
            "os_matches":   os_matches,
            "ports":        ports,
            "host_scripts": host_scripts,
        })

    return {"meta": meta, "hosts": hosts}


# ──────────────────────────────────────────────
# Funções de risco (heurística por porta/serviço)
# ──────────────────────────────────────────────

RISK_MAP = {
    "21": ("HIGH",     "FTP — transferência em texto claro"),
    "23": ("CRITICAL", "Telnet — protocolo sem criptografia"),
    "25": ("HIGH",     "SMTP aberto pode ser explorado"),
    "53": ("MEDIUM",   "DNS exposto publicamente"),
    "69": ("HIGH",     "TFTP — sem autenticação"),
    "80": ("MEDIUM",   "HTTP — tráfego não cifrado"),
    "111": ("HIGH",    "RPC portmapper exposto"),
    "135": ("HIGH",    "MS RPC — vetor de exploração comum"),
    "137": ("HIGH",    "NetBIOS Name Service"),
    "139": ("HIGH",    "NetBIOS Session — SMB legado"),
    "161": ("HIGH",    "SNMP — possível vazamento de informações"),
    "389": ("MEDIUM",  "LDAP — verifique se requer autenticação"),
    "443": ("LOW",     "HTTPS"),
    "445": ("CRITICAL","SMB — vulnerável a EternalBlue/WannaCry"),
    "512": ("CRITICAL","rexec — execução remota sem criptografia"),
    "513": ("CRITICAL","rlogin — login remoto sem criptografia"),
    "514": ("CRITICAL","rsh — shell remoto sem criptografia"),
    "1433": ("HIGH",   "MS SQL Server exposto"),
    "1521": ("HIGH",   "Oracle DB exposto"),
    "2049": ("HIGH",   "NFS — montagem remota de sistema de arquivos"),
    "3306": ("HIGH",   "MySQL exposto"),
    "3389": ("HIGH",   "RDP — alvo frequente de ataques de força bruta"),
    "4444": ("CRITICAL","Porta usada por Metasploit/backdoors"),
    "5432": ("HIGH",   "PostgreSQL exposto"),
    "5900": ("HIGH",   "VNC — acesso gráfico remoto"),
    "6379": ("CRITICAL","Redis sem autenticação"),
    "8080": ("MEDIUM", "HTTP alternativo"),
    "8443": ("LOW",    "HTTPS alternativo"),
    "27017": ("CRITICAL","MongoDB — comumente sem autenticação"),
}

RISK_LEVELS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

def port_risk(portid: str, service: str) -> tuple[str, str]:
    """Retorna (nível, descrição) para uma porta."""
    if portid in RISK_MAP:
        return RISK_MAP[portid]
    return ("INFO", service or "Serviço desconhecido")

def risk_color(level: str) -> colors.Color:
    return {
        "CRITICAL": C_CRITICAL,
        "HIGH":     C_HIGH,
        "MEDIUM":   C_MEDIUM,
        "LOW":      C_LOW,
        "INFO":     C_INFO,
    }.get(level, C_INFO)


# ──────────────────────────────────────────────
# Estilos
# ──────────────────────────────────────────────

def build_styles():
    base = getSampleStyleSheet()
    s = {}

    def ps(name, **kw):
        s[name] = ParagraphStyle(name, **kw)

    ps("cover_title",
        fontSize=38, textColor=C_WHITE, alignment=TA_CENTER,
        fontName="Helvetica-Bold", leading=46, spaceAfter=6)
    ps("cover_subtitle",
        fontSize=16, textColor=C_ACCENT, alignment=TA_CENTER,
        fontName="Helvetica", leading=22, spaceAfter=4)
    ps("cover_meta",
        fontSize=11, textColor=C_MUTED, alignment=TA_CENTER,
        fontName="Helvetica", leading=16)

    ps("h1",
        fontSize=18, textColor=C_ACCENT, fontName="Helvetica-Bold",
        leading=24, spaceBefore=18, spaceAfter=6)
    ps("h2",
        fontSize=13, textColor=C_TEXT, fontName="Helvetica-Bold",
        leading=18, spaceBefore=10, spaceAfter=4)
    ps("h3",
        fontSize=11, textColor=C_ACCENT, fontName="Helvetica-Bold",
        leading=15, spaceBefore=6, spaceAfter=3)
    ps("body",
        fontSize=9, textColor=C_TEXT, fontName="Helvetica",
        leading=14, spaceAfter=3)
    ps("body_muted",
        fontSize=8, textColor=C_MUTED, fontName="Helvetica",
        leading=12, spaceAfter=2)
    ps("badge_critical",
        fontSize=8, textColor=C_WHITE, fontName="Helvetica-Bold",
        alignment=TA_CENTER, backColor=C_CRITICAL, leading=10)
    ps("footer",
        fontSize=7, textColor=C_MUTED, fontName="Helvetica",
        alignment=TA_CENTER, leading=10)
    ps("toc_entry",
        fontSize=10, textColor=C_TEXT, fontName="Helvetica", leading=16)

    return s


# ──────────────────────────────────────────────
# Construção de elementos PDF
# ──────────────────────────────────────────────

def hr(color=C_BORDER, thickness=0.5):
    return HRFlowable(width="100%", thickness=thickness,
                      color=color, spaceAfter=6, spaceBefore=6)


def badge_paragraph(text: str, level: str, styles: dict) -> Paragraph:
    color = risk_color(level)
    hex_c = color.hexval() if hasattr(color, "hexval") else "#58A6FF"
    # fallback manual
    hex_map = {
        C_CRITICAL: "#F85149",
        C_HIGH:     "#FF8C00",
        C_MEDIUM:   "#D29922",
        C_LOW:      "#3FB950",
        C_INFO:     "#58A6FF",
    }
    hex_c = hex_map.get(color, "#58A6FF")
    markup = (
        f'<font color="{hex_c}"><b>[{text}]</b></font>'
    )
    return Paragraph(markup, styles["body"])


def summary_table(data: list[list], col_widths: list[float],
                  header_bg=C_SURFACE, alt_bg=None) -> Table:
    """Tabela genérica com estilo escuro."""
    t = Table(data, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ("BACKGROUND",   (0, 0), (-1, 0),  header_bg),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  C_ACCENT),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0),  9),
        ("ALIGN",        (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#161B22"), colors.HexColor("#0D1117")]),
        ("TEXTCOLOR",    (0, 1), (-1, -1), C_TEXT),
        ("FONTNAME",     (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",     (0, 1), (-1, -1), 8),
        ("GRID",         (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]
    t.setStyle(TableStyle(style_cmds))
    return t


# ──────────────────────────────────────────────
# Seções do relatório
# ──────────────────────────────────────────────

def build_cover(styles, author: str, company: str,
                scan_date: str, total_hosts: int) -> list:
    story = []
    story.append(Spacer(1, 3.5*cm))
    story.append(Paragraph("Network Scanning", styles["cover_title"]))
    story.append(Spacer(1, 0.3*cm))

    subtitle = "Security Assessment Report"
    if company:
        subtitle = f"Security Assessment Report — {company}"
    story.append(Paragraph(subtitle, styles["cover_subtitle"]))
    story.append(Spacer(1, 0.6*cm))
    story.append(hr(C_ACCENT2, 1.5))
    story.append(Spacer(1, 0.6*cm))

    meta_lines = []
    if scan_date:
        meta_lines.append(f"Data da Varredura: {scan_date}")
    meta_lines.append(f"Total de Hosts Analisados: {total_hosts}")
    if author:
        meta_lines.append(f"Gerado por: {author}")
    meta_lines.append(f"Data do Relatório: {datetime.now().strftime('%d/%m/%Y %H:%M')}")

    for line in meta_lines:
        story.append(Paragraph(line, styles["cover_meta"]))
        story.append(Spacer(1, 0.15*cm))

    story.append(PageBreak())
    return story


def build_executive_summary(styles, all_data: list[dict]) -> list:
    story = []
    story.append(Paragraph("1. Sumário Executivo", styles["h1"]))
    story.append(hr())

    total_hosts_up   = sum(d["meta"]["hosts_up"]   for d in all_data)
    total_hosts_down = sum(d["meta"]["hosts_down"] for d in all_data)
    total_hosts      = sum(d["meta"]["hosts_total"] for d in all_data)

    open_ports_count = 0
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    services_seen = set()

    for data in all_data:
        for host in data["hosts"]:
            if host["state"] != "up":
                continue
            for port in host["ports"]:
                if port["state"] == "open":
                    open_ports_count += 1
                    services_seen.add(port["service"] or port["portid"])
                    lvl, _ = port_risk(port["portid"], port["service"])
                    risk_counts[lvl] += 1

    # bloco de estatísticas
    stats_data = [
        [Paragraph("<b>Métrica</b>", styles["body"]),
         Paragraph("<b>Valor</b>",   styles["body"])],
        ["Hosts ativos",    str(total_hosts_up)],
        ["Hosts inativos",  str(total_hosts_down)],
        ["Total de hosts",  str(total_hosts)],
        ["Portas abertas",  str(open_ports_count)],
        ["Serviços únicos", str(len(services_seen))],
    ]
    story.append(summary_table(stats_data, [8*cm, 8*cm]))
    story.append(Spacer(1, 0.5*cm))

    # tabela de riscos
    story.append(Paragraph("Distribuição de Riscos por Porta Aberta", styles["h2"]))

    def risk_cell(level, count):
        c = risk_color(level)
        hex_map = {C_CRITICAL:"#F85149",C_HIGH:"#FF8C00",
                   C_MEDIUM:"#D29922",C_LOW:"#3FB950",C_INFO:"#58A6FF"}
        h = hex_map.get(c, "#58A6FF")
        return Paragraph(
            f'<font color="{h}"><b>{level}</b></font> &nbsp; {count} ocorrência(s)',
            styles["body"])

    risk_data = [
        [Paragraph("<b>Nível de Risco</b>", styles["body"]),
         Paragraph("<b>Ocorrências</b>", styles["body"])]
    ] + [
        [risk_cell(lvl, risk_counts[lvl]),
         Paragraph(str(risk_counts[lvl]), styles["body"])]
        for lvl in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    ]
    story.append(summary_table(risk_data, [10*cm, 6*cm]))
    story.append(Spacer(1, 0.4*cm))

    # aviso executivo
    if risk_counts["CRITICAL"] > 0 or risk_counts["HIGH"] > 0:
        msg = (
            f"<b><font color='#F85149'>ATENÇÃO:</font></b> Foram identificadas "
            f"<b>{risk_counts['CRITICAL']}</b> porta(s) com risco CRITICAL e "
            f"<b>{risk_counts['HIGH']}</b> com risco HIGH. "
            "Recomenda-se ação imediata para remediação."
        )
    else:
        msg = (
            "Nenhuma porta de risco crítico ou alto foi identificada. "
            "Mantenha o monitoramento contínuo e aplique patches regularmente."
        )
    story.append(Paragraph(msg, styles["body"]))
    story.append(PageBreak())
    return story


def build_host_detail(styles, data: dict, source_file: str) -> list:
    story = []
    story.append(Paragraph(f"2. Detalhamento dos Hosts — {Path(source_file).name}",
                            styles["h1"]))
    story.append(hr())

    active_hosts = [h for h in data["hosts"] if h["state"] == "up"]
    if not active_hosts:
        story.append(Paragraph("Nenhum host ativo encontrado neste arquivo.",
                               styles["body"]))
        story.append(PageBreak())
        return story

    for idx, host in enumerate(active_hosts, 1):
        ip = host["addrs"].get("ipv4") or host["addrs"].get("ipv6", "N/A")
        mac = host["addrs"].get("mac", "")
        hostname = ", ".join(host["hostnames"]) if host["hostnames"] else "—"

        # cabeçalho do host
        story.append(Spacer(1, 0.3*cm))
        title = f"Host {idx}: {ip}"
        if hostname != "—":
            title += f"  ({hostname})"
        story.append(Paragraph(title, styles["h2"]))
        story.append(hr(C_ACCENT2, 0.7))

        # info básica
        info_rows = [
            [Paragraph("<b>Campo</b>", styles["body"]),
             Paragraph("<b>Valor</b>",  styles["body"])],
            ["Endereço IP",   ip],
            ["Hostname",      hostname],
            ["MAC Address",   mac or "—"],
            ["Estado",        host["state"].upper()],
        ]

        os_name = "—"
        if host["os_matches"]:
            best = host["os_matches"][0]
            os_name = f"{best['name']} (precisão: {best['accuracy']}%)"
        info_rows.append(["Sistema Operacional", os_name])

        story.append(summary_table(info_rows, [5*cm, 11*cm]))
        story.append(Spacer(1, 0.3*cm))

        # portas
        open_ports = [p for p in host["ports"] if p["state"] == "open"]
        other_ports = [p for p in host["ports"] if p["state"] != "open"]

        if open_ports:
            story.append(Paragraph("Portas Abertas", styles["h3"]))
            port_header = [
                Paragraph("<b>Porta</b>",    styles["body"]),
                Paragraph("<b>Protocolo</b>",styles["body"]),
                Paragraph("<b>Serviço</b>",  styles["body"]),
                Paragraph("<b>Produto/Versão</b>", styles["body"]),
                Paragraph("<b>Risco</b>",    styles["body"]),
                Paragraph("<b>Observação</b>", styles["body"]),
            ]
            port_rows = [port_header]
            for p in sorted(open_ports, key=lambda x: int(x["portid"])):
                lvl, obs = port_risk(p["portid"], p["service"])
                c = risk_color(lvl)
                hex_map = {C_CRITICAL:"#F85149",C_HIGH:"#FF8C00",
                           C_MEDIUM:"#D29922",C_LOW:"#3FB950",C_INFO:"#58A6FF"}
                h = hex_map.get(c, "#58A6FF")
                version_str = " ".join(filter(None, [p["product"], p["version"],
                                                     p["extrainfo"]])) or "—"
                port_rows.append([
                    Paragraph(f'<font color="#3FB950"><b>{p["portid"]}</b></font>',
                               styles["body"]),
                    Paragraph(p["protocol"].upper(), styles["body"]),
                    Paragraph(p["service"] or "—", styles["body"]),
                    Paragraph(version_str[:45], styles["body_muted"]),
                    Paragraph(f'<font color="{h}"><b>{lvl}</b></font>', styles["body"]),
                    Paragraph(obs[:50], styles["body_muted"]),
                ])

            t = Table(port_rows,
                      colWidths=[1.4*cm, 1.8*cm, 2.5*cm, 4*cm, 2.2*cm, 4.1*cm],
                      repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND",   (0,0),(-1,0),  C_SURFACE),
                ("TEXTCOLOR",    (0,0),(-1,0),  C_ACCENT),
                ("FONTNAME",     (0,0),(-1,0),  "Helvetica-Bold"),
                ("FONTSIZE",     (0,0),(-1,0),  8),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),
                 [colors.HexColor("#161B22"), colors.HexColor("#0D1117")]),
                ("TEXTCOLOR",    (0,1),(-1,-1), C_TEXT),
                ("FONTNAME",     (0,1),(-1,-1), "Helvetica"),
                ("FONTSIZE",     (0,1),(-1,-1), 7.5),
                ("GRID",         (0,0),(-1,-1), 0.3, C_BORDER),
                ("VALIGN",       (0,0),(-1,-1), "MIDDLE"),
                ("TOPPADDING",   (0,0),(-1,-1), 4),
                ("BOTTOMPADDING",(0,0),(-1,-1), 4),
                ("LEFTPADDING",  (0,0),(-1,-1), 5),
                ("RIGHTPADDING", (0,0),(-1,-1), 5),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.2*cm))

            # scripts NSE
            for p in open_ports:
                if p["scripts"]:
                    story.append(Paragraph(
                        f'Scripts NSE — Porta {p["portid"]}/{p["protocol"]}',
                        styles["h3"]))
                    for sc in p["scripts"]:
                        out = sc["output"].replace("\n", " | ")[:300]
                        story.append(Paragraph(
                            f'<b>{sc["id"]}:</b> {out}', styles["body_muted"]))

        if other_ports:
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph(
                f"Outras Portas ({len(other_ports)} — fechadas/filtradas)",
                styles["h3"]))
            summary = ", ".join(
                f'{p["portid"]}/{p["protocol"]} ({p["state"]})'
                for p in sorted(other_ports, key=lambda x: int(x["portid"]))[:30]
            )
            if len(other_ports) > 30:
                summary += f" ... (+{len(other_ports)-30} mais)"
            story.append(Paragraph(summary, styles["body_muted"]))

        # host scripts
        if host["host_scripts"]:
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph("Scripts de Host (NSE)", styles["h3"]))
            for sc in host["host_scripts"]:
                out = sc["output"].replace("\n", " | ")[:400]
                story.append(Paragraph(
                    f'<b>{sc["id"]}:</b> {out}', styles["body_muted"]))

        story.append(Spacer(1, 0.3*cm))
        story.append(hr(C_BORDER, 0.3))

    story.append(PageBreak())
    return story


def build_recommendations(styles, all_data: list[dict]) -> list:
    story = []
    story.append(Paragraph("3. Recomendações de Segurança", styles["h1"]))
    story.append(hr())

    # Catálogo completo de recomendações indexado por porta
    REC_CATALOG: dict[str, tuple[str, str, str]] = {
        "21":    ("HIGH",     "Desabilitar FTP (21) e substituir por SFTP/FTPS",
                  "FTP transmite dados e credenciais sem criptografia. "
                  "Use SFTP (SSH) ou FTPS para transferências seguras."),
        "23":    ("CRITICAL", "Desabilitar Telnet (23)",
                  "Substituir por SSH com autenticação por chave pública. "
                  "Telnet transmite credenciais em texto claro."),
        "53":    ("MEDIUM",   "Revisar configuração de DNS público (53)",
                  "Desativar recursão em servidores DNS públicos. "
                  "Implementar DNSSEC para autenticidade das respostas."),
        "69":    ("HIGH",     "Desabilitar TFTP (69)",
                  "TFTP não possui mecanismo de autenticação. "
                  "Restrinja o acesso por firewall ou desative o serviço."),
        "80":    ("MEDIUM",   "Forçar HTTPS — HTTP (80) detectado",
                  "Redirecionar HTTP (80) para HTTPS (443). "
                  "Utilizar certificados válidos e configurar HSTS."),
        "111":   ("HIGH",     "Restringir RPC portmapper (111)",
                  "O portmapper expõe serviços RPC internos. "
                  "Bloqueie via firewall e desative serviços RPC desnecessários."),
        "135":   ("HIGH",     "Restringir MS RPC (135)",
                  "Porta frequentemente explorada em ambientes Windows. "
                  "Bloqueie no perímetro e aplique patches de segurança."),
        "137":   ("HIGH",     "Desabilitar NetBIOS Name Service (137)",
                  "NetBIOS expõe informações de rede e é alvo de ataques de envenenamento. "
                  "Desative se não for necessário ou bloqueie no firewall."),
        "139":   ("HIGH",     "Desabilitar NetBIOS Session / SMB legado (139)",
                  "SMBv1 é inseguro e deve ser desabilitado. "
                  "Use SMBv3 com assinatura obrigatória."),
        "161":   ("HIGH",     "Proteger SNMP (161)",
                  "Usar SNMPv3 com autenticação e criptografia. "
                  "Evitar community strings padrão como 'public' ou 'private'."),
        "389":   ("MEDIUM",   "Revisar LDAP exposto (389)",
                  "Verifique se o servidor LDAP exige autenticação. "
                  "Considere LDAPS (636) para comunicação cifrada."),
        "445":   ("CRITICAL", "Aplicar patches para SMB (445) — risco EternalBlue/WannaCry",
                  "Manter o sistema operacional atualizado. Desativar SMBv1. "
                  "Bloquear a porta 445 no perímetro de rede."),
        "512":   ("CRITICAL", "Desabilitar rexec (512)",
                  "Execução remota sem criptografia. "
                  "Substitua por SSH imediatamente."),
        "513":   ("CRITICAL", "Desabilitar rlogin (513)",
                  "Login remoto sem criptografia. "
                  "Substitua por SSH com autenticação por chave pública."),
        "514":   ("CRITICAL", "Desabilitar rsh (514)",
                  "Shell remoto sem criptografia nem autenticação adequada. "
                  "Substitua por SSH imediatamente."),
        "1433":  ("HIGH",     "Restringir MS SQL Server exposto (1433)",
                  "Serviços de banco de dados não devem ser acessíveis pela internet. "
                  "Use VPN ou bastion host para acesso remoto."),
        "1521":  ("HIGH",     "Restringir Oracle DB exposto (1521)",
                  "Serviços de banco de dados não devem ser acessíveis pela internet. "
                  "Use VPN ou bastion host para acesso remoto."),
        "2049":  ("HIGH",     "Restringir NFS (2049)",
                  "NFS pode permitir montagem remota de sistema de arquivos sem autenticação forte. "
                  "Restrinja exportações e use NFSv4 com Kerberos."),
        "3306":  ("HIGH",     "Restringir MySQL exposto (3306)",
                  "Banco de dados não deve ser acessível diretamente pela rede. "
                  "Restrinja bind ao loopback ou use VPN."),
        "3389":  ("HIGH",     "Proteger RDP (3389)",
                  "Habilitar NLA, usar senhas fortes e autenticação multifator. "
                  "Limitar acesso por firewall e VPN. Monitorar tentativas de força bruta."),
        "4444":  ("CRITICAL", "Porta 4444 aberta — possível backdoor/Metasploit",
                  "Esta porta é amplamente associada a ferramentas de ataque e backdoors. "
                  "Investigue imediatamente o processo em escuta."),
        "5432":  ("HIGH",     "Restringir PostgreSQL exposto (5432)",
                  "Banco de dados não deve ser acessível diretamente pela rede. "
                  "Restrinja bind ao loopback ou use VPN."),
        "5900":  ("HIGH",     "Proteger VNC (5900)",
                  "VNC expõe acesso gráfico remoto. Use senhas fortes, "
                  "tunnel via SSH e restrinja por firewall."),
        "6379":  ("CRITICAL", "Proteger Redis (6379) — frequentemente sem autenticação",
                  "Habilitar autenticação obrigatória (requirepass), "
                  "bind apenas em interfaces internas e bloquear acesso externo."),
        "8080":  ("MEDIUM",   "Revisar HTTP alternativo (8080)",
                  "Verifique se o serviço deve ser acessível publicamente. "
                  "Considere migrar para HTTPS."),
        "27017": ("CRITICAL", "Proteger MongoDB (27017) — comumente sem autenticação",
                  "Habilitar autenticação, bind apenas em interfaces internas "
                  "e usar firewall para bloquear acesso externo."),
    }

    # Recomendação geral — sempre incluída
    ALWAYS_REC = ("INFO", "Manter inventário atualizado de ativos e serviços",
                  "Executar varreduras periódicas de rede e comparar com o inventário "
                  "para detectar novos dispositivos e serviços não autorizados.")

    # Coletar portas abertas encontradas no scan
    found_ports: set[str] = set()
    for data in all_data:
        for host in data["hosts"]:
            for port in host["ports"]:
                if port["state"] == "open":
                    found_ports.add(port["portid"])

    # Filtrar recomendações relevantes
    relevant: list[tuple[str, str, str]] = []
    for portid, rec in REC_CATALOG.items():
        if portid in found_ports:
            relevant.append(rec)

    # Ordenar por criticidade
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    relevant.sort(key=lambda r: order.get(r[0], 99))
    relevant.append(ALWAYS_REC)

    if len(relevant) == 1:
        story.append(Paragraph(
            "Nenhuma porta de risco identificada nas recomendações catalogadas. "
            "Mantenha o monitoramento contínuo.",
            styles["body"]))
    else:
        story.append(Paragraph(
            f"As {len(relevant) - 1} recomendação(ões) abaixo são baseadas "
            "exclusivamente nas portas abertas identificadas nesta varredura.",
            styles["body"]))
        story.append(Spacer(1, 0.3*cm))

    hex_map = {
        "CRITICAL": "#F85149", "HIGH": "#FF8C00",
        "MEDIUM":   "#D29922", "LOW":  "#3FB950", "INFO": "#58A6FF",
    }

    for level, title, desc in relevant:
        h = hex_map[level]
        story.append(Paragraph(
            f'<font color="{h}"><b>[{level}]</b></font>  <b>{title}</b>',
            styles["body"]))
        story.append(Paragraph(desc, styles["body_muted"]))
        story.append(Spacer(1, 0.15*cm))

    story.append(PageBreak())
    return story


def build_scan_info(styles, all_data: list[dict], files: list[str]) -> list:
    story = []
    story.append(Paragraph("4. Informações da Varredura", styles["h1"]))
    story.append(hr())

    rows = [[
        Paragraph("<b>Arquivo</b>",  styles["body"]),
        Paragraph("<b>Nmap</b>",     styles["body"]),
        Paragraph("<b>Início</b>",   styles["body"]),
        Paragraph("<b>Duração</b>",  styles["body"]),
        Paragraph("<b>Argumentos</b>", styles["body"]),
    ]]
    for f, d in zip(files, all_data):
        m = d["meta"]
        rows.append([
            Paragraph(Path(f).name, styles["body_muted"]),
            Paragraph(m["version"],                 styles["body_muted"]),
            Paragraph(m["start"][:25],              styles["body_muted"]),
            Paragraph(f'{m["elapsed"]}s' if m["elapsed"] else "—",
                      styles["body_muted"]),
            Paragraph(m["args"][:60],               styles["body_muted"]),
        ])

    story.append(summary_table(rows, [3.5*cm, 1.5*cm, 4*cm, 2*cm, 5*cm]))
    story.append(PageBreak())
    return story


# ──────────────────────────────────────────────
# Canvas com fundo e rodapé
# ──────────────────────────────────────────────

class DarkCanvas:
    def __init__(self, author: str, company: str):
        self.author  = author
        self.company = company

    def __call__(self, canvas, doc):
        canvas.saveState()
        w, h = A4

        # fundo
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, w, h, fill=1, stroke=0)

        # linha de topo
        canvas.setStrokeColor(C_ACCENT2)
        canvas.setLineWidth(2)
        canvas.line(0, h - 4*mm, w, h - 4*mm)

        # rodapé
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.4)
        canvas.line(1.5*cm, 1.4*cm, w - 1.5*cm, 1.4*cm)

        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(C_MUTED)

        # esquerda
        left_text = "Network Scanning — Security Assessment Report"
        if self.company:
            left_text += f" | {self.company}"
        canvas.drawString(1.5*cm, 0.9*cm, left_text)

        # centro
        if self.author:
            canvas.drawCentredString(w / 2, 0.9*cm, f"Gerado por: {self.author}")

        # direita
        canvas.drawRightString(w - 1.5*cm, 0.9*cm,
                               f"Página {doc.page}  |  {datetime.now().strftime('%d/%m/%Y')}")

        canvas.restoreState()


# ──────────────────────────────────────────────
# Main builder
# ──────────────────────────────────────────────

def build_pdf(xml_files: list[str], output: str,
              author: str = "", company: str = "") -> None:
    print(f"[*] Lendo {len(xml_files)} arquivo(s) XML...")

    all_data = []
    for f in xml_files:
        try:
            all_data.append(parse_nmap_xml(f))
            print(f"    ✓ {f}")
        except Exception as e:
            print(f"    ✗ {f} — erro: {e}", file=sys.stderr)

    if not all_data:
        print("Nenhum arquivo válido. Abortando.", file=sys.stderr)
        sys.exit(1)

    styles = build_styles()
    on_page = DarkCanvas(author, company)

    doc = SimpleDocTemplate(
        output,
        pagesize=A4,
        leftMargin=1.8*cm, rightMargin=1.8*cm,
        topMargin=1.5*cm, bottomMargin=2*cm,
        title="Network Scanning — Security Assessment Report",
        author=author or "N/A",
        subject="Nmap Security Report",
        creator="nmap_to_pdf.py",
    )

    story = []

    # Capa
    total_hosts = sum(d["meta"]["hosts_total"] for d in all_data)
    scan_date = all_data[0]["meta"]["start"] if all_data else ""
    story += build_cover(styles, author, company, scan_date, total_hosts)

    # Sumário executivo
    story += build_executive_summary(styles, all_data)

    # Detalhamento por arquivo
    for f, data in zip(xml_files, all_data):
        story += build_host_detail(styles, data, f)

    # Recomendações
    story += build_recommendations(styles, all_data)

    # Info de varredura
    story += build_scan_info(styles, all_data, xml_files)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    print(f"\n[✓] PDF gerado: {output}")


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

class BannerHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Exibe o banner antes do texto de ajuda padrão."""
    def format_help(self):
        print_banner()
        return super().format_help()


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Converte relatórios Nmap XML em PDF executivo de segurança.\n\n"
            "Exemplos:\n"
            "  %(prog)s scan.xml\n"
            "  %(prog)s scan.xml -o relatorio.pdf --author \"João Silva\"\n"
            "  %(prog)s scan.xml -o relatorio.pdf --author \"João\" --company \"ACME\"\n"
            "  %(prog)s *.xml   -o relatorio.pdf --author \"Time de Segurança\""
        ),
        formatter_class=BannerHelpFormatter,
        epilog="O relatório gerado inclui: sumário executivo, detalhamento de hosts,\n"
               "análise de portas com classificação de risco e recomendações de segurança.",
    )
    parser.add_argument("xml_files", nargs="*", metavar="FILE.xml",
                        help="Um ou mais arquivos XML gerados pelo Nmap")
    parser.add_argument("-o", "--output", default="network_scanning_report.pdf",
                        help="Nome do arquivo PDF de saída (padrão: network_scanning_report.pdf)")
    parser.add_argument("--author",  default="",
                        help="Nome do responsável pelo relatório (subtítulo e rodapé)")
    parser.add_argument("--company", default="",
                        help="Nome da empresa/equipe (subtítulo da capa)")

    args = parser.parse_args()

    # sem argumentos: exibe banner + ajuda e sai
    if not args.xml_files:
        print_banner()
        parser.print_help()
        sys.exit(0)

    print_banner()
    build_pdf(args.xml_files, args.output, args.author, args.company)


if __name__ == "__main__":
    main()
