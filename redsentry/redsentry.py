#!/usr/bin/env python3
"""
RedSentry — Red Team Automation Tool
Ferramenta de automação para reconhecimento e análise de segurança.

Autor: Gabriel Vittorazzi
GitHub: https://github.com/Gbtapas/redsentry
"""
    
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.port_scanner import port_scan, PORTAS_COMUNS
from modules.cve_search import buscar_cves
from modules.subdomain_enum import enum_subdominios
from modules.dns_collector import dns_info
from modules.report_gen import gerar_relatorio

# Importação condicional do módulo de IA
AI_DISPONIVEL = False
try:
    from modules.ai_analyzer import configurar as configurar_gemini
    from modules.ai_analyzer import analisar_achados as analisar_com_ia
    AI_DISPONIVEL = True
except ImportError:
    pass


BANNER = r"""
  ____          ____            _
 |  _ \ ___ _ _/ ___|  ___  ___| |_ _   _ _ __
 | |_) / -_) ' \___ \ / _ \/ __| __| | | | '_ \
 |____/\___|_||_|___/ \___/___|\__|\_,_| .__/
                                        |_|
  Red Team Automation Tool v1.0
  Gabriel Vittorazzi — github.com/Gbtapas/redsentry
"""


def separador(titulo=""):
    largura = 55
    print(f"\n{'='*largura}")
    if titulo:
        espaco = (largura - len(titulo) - 4) // 2
        print(f"{' '*espaco}[ {titulo} ]")
        print(f"{'='*largura}")


def main():
    # ──────────────────────────────────────────────
    # Verificar argumentos
    # ──────────────────────────────────────────────
    if len(sys.argv) < 2:
        print(BANNER)
        print("  Uso: python redsentry.py <alvo> [--ai SuaApiKey]")
        print()
        print("  Exemplos:")
        print("    python redsentry.py scanme.nmap.org")
        print("    python redsentry.py scanme.nmap.org --ai SUA_API_KEY")
        print()
        print("  Opções:")
        print("    --ai <key>   Ativar análise com IA (Google Gemini)")
        print()
        print("  Obtenha sua API key em: https://aistudio.google.com/apikey")
        print()
        sys.exit(1)

    alvo = sys.argv[1]
    api_key = None

    # Verificar se foi passada API key
 if "--ai" in sys.argv:
    idx = sys.argv.index("--ai")
    if idx + 1 < len(sys.argv):
        api_key = sys.argv[idx + 1]

# Se nao passou, tenta variavel de ambiente
if api_key is None:
    api_key = os.environ.get("GEMINI_API_KEY")

    print(BANNER)
    separador("INICIANDO ANALISE")
    print(f"  Alvo: {alvo}")
    print(f"  IA: {'Ativada (Google Gemini)' if api_key else 'Desativada (use --ai para ativar)'}")

    # ──────────────────────────────────────────────
    # FASE 1: Coleta de Informações DNS
    # ──────────────────────────────────────────────
    separador("FASE 1: DNS COLLECTOR")
    dns = dns_info(alvo)
    ip_alvo = dns.get("ip", alvo)

    if ip_alvo == "Não resolvido":
        print("\n  [!] Não foi possível resolver o IP. Usando o alvo diretamente.")
        ip_alvo = alvo

    # ──────────────────────────────────────────────
    # FASE 2: Scan de Portas
    # ──────────────────────────────────────────────
    separador("FASE 2: PORT SCANNER")
    portas = port_scan(ip_alvo, PORTAS_COMUNS)

    # ──────────────────────────────────────────────
    # FASE 3: Busca de CVEs
    # ──────────────────────────────────────────────
    separador("FASE 3: CVE SEARCH")
    todos_cves = []
    servicos_escaneados = set()

    for p in portas:
        servico = p.get("servico", "").strip()
        if servico and servico != "Desconhecido" and servico not in servicos_escaneados:
            servicos_escaneados.add(servico)
            cves = buscar_cves(servico, max_resultados=5)
            todos_cves.extend(cves)

    if not servicos_escaneados:
        print("\n  [INFO] Nenhum serviço identificado para busca de CVEs.")

    # ──────────────────────────────────────────────
    # FASE 4: Enumeração de Subdomínios
    # ──────────────────────────────────────────────
    separador("FASE 4: SUBDOMAIN ENUMERATION")

    dominio_base = alvo
    partes = alvo.split(".")
    eh_ip = all(p.isdigit() for p in partes) and len(partes) == 4

    if eh_ip:
        print("\n  [INFO] Alvo é um IP. Enumeração de subdomínios ignorada.")
        subdominios = []
    else:
        subdominios = enum_subdominios(dominio_base)

    # ──────────────────────────────────────────────
    # FASE 5: Análise com IA (se habilitada)
    # ──────────────────────────────────────────────
    analise_ia = None

    if api_key and AI_DISPONIVEL:
        separador("FASE 5: ANÁLISE COM IA")

        sucesso = configurar_gemini(api_key=os.environ.get("GEMINI_API_KEY"))
        if sucesso:
            analise_ia = analisar_com_ia(
                alvo=alvo,
                portas=portas,
                cves=todos_cves,
                subdominios=subdominios,
                dns=dns,
            )
        else:
            print("  [!] Análise com IA descontinuada. Continuando sem IA.")
    elif api_key and not AI_DISPONIVEL:
        separador("FASE 5: ANÁLISE COM IA")
        print("  [!] Módulo de IA não disponível.")
        print("  [!] Rode: pip install google-generativeai")

    # ──────────────────────────────────────────────
    # FASE 6: Geração de Relatório
    # ──────────────────────────────────────────────
    fase_label = "FASE 6" if analise_ia else "FASE 5"
    separador(f"{fase_label}: RELATORIO")
    caminho_relatorio = gerar_relatorio(
        alvo=alvo,
        portas=portas,
        cves=todos_cves,
        subdominios=subdominios,
        dns=dns,
        analise_ia=analise_ia,
    )

    # ──────────────────────────────────────────────
    # RESUMO FINAL
    # ──────────────────────────────────────────────
    separador("ANALISE COMPLETA")
    print(f"  Alvo:          {alvo}")
    print(f"  IP:            {ip_alvo}")
    print(f"  Portas abertas: {len(portas)}")
    print(f"  CVEs:          {len(todos_cves)}")
    print(f"  Subdomínios:   {len(subdominios)}")
    print(f"  IA:            {'Sim (Google Gemini)' if analise_ia else 'Não'}")
    print(f"  Relatório:     {caminho_relatorio}")
    separador()

    # Abrir relatório
    try:
        import webbrowser
        webbrowser.open(f"file://{os.path.abspath(caminho_relatorio)}")
        print("  [+] Relatório aberto no navegador.")
    except Exception:
        print(f"  [i] Abra o relatório manualmente: {caminho_relatorio}")


if __name__ == "__main__":
    main()
