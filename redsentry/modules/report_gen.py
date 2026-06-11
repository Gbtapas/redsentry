"""
Módulo de Geração de Relatórios HTML
Gera relatórios visuais com todos os achados do RedSentry.
Agora inclui seção de análise com IA.
"""

import os
from datetime import datetime


def gerar_relatorio(alvo, portas, cves, subdominios, dns,
                    diretorio="reports", analise_ia=None):
    """
    Gera um relatório HTML com todos os achados da análise.

    Args:
        alvo (str): Domínio ou IP analisado.
        portas (list): Lista de portas abertas encontradas.
        cves (list): Lista de CVEs encontradas.
        subdominios (list): Lista de subdomínios encontrados.
        dns (dict): Informações DNS coletadas.
        diretorio (str): Pasta onde o relatório será salvo.
        analise_ia (dict ou None): Resultado da análise com IA.

    Returns:
        str: Caminho do arquivo de relatório gerado.
    """
    os.makedirs(diretorio, exist_ok=True)

    criticos = [c for c in cves if c.get("severidade") == "CRITICAL"]
    altos = [c for c in cves if c.get("severidade") == "HIGH"]
    medios = [c for c in cves if c.get("severidade") == "MEDIUM"]
    baixos = [c for c in cves if c.get("severidade") == "LOW"]

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nome_arquivo = f"redsentry_{alvo.replace('.', '_')}_{timestamp}.html"
    caminho = os.path.join(diretorio, nome_arquivo)

    html = _montar_html(
        alvo=alvo,
        portas=portas,
        cves=cves,
        subdominios=subdominios,
        dns=dns,
        criticos=criticos,
        altos=altos,
        medios=medios,
        baixos=baixos,
        analise_ia=analise_ia,
    )

    with open(caminho, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n{'='*50}")
    print(f"  [+] RELATÓRIO GERADO")
    print(f"  [+] Arquivo: {caminho}")
    print(f"  [+] Portas abertas: {len(portas)}")
    print(f"  [+] CVEs encontradas: {len(cves)}")
    print(f"  [+] Subdomínios: {len(subdominios)}")
    print(f"  [+] Análise IA: {'Sim' if analise_ia else 'Não'}")
    print(f"{'='*50}\n")

    return caminho


def _gerar_secao_ia(analise):
    """Gera a seção HTML com a análise da IA."""
    if not analise:
        return ""

    risco = analise.get("risco_geral", "N/A")
    resumo = analise.get("resumo", "N/A")

    cor_risco = {
        "CRITICO": "#ff3333",
        "ALTO": "#ff8800",
        "MEDIO": "#ffcc00",
        "BAIXO": "#00ff41",
        "ERRO": "#666666",
        "N/A": "#666666",
    }
    cor = cor_risco.get(risco, "#666666")

    # Vulnerabilidades priorizadas pela IA
    vulns_html = ""
    vulns = analise.get("vulnerabilidades_priorizadas", [])
    if vulns:
        for v in vulns:
            sev = v.get("severidade", "N/A")
            sev_css = sev.lower() if sev.lower() in ["critico", "alto", "medio", "baixos"] else "info"
            vulns_html += f"""
            <div class="cve-card {sev_css}">
                <div class="cve-header">
                    <span class="cve-id">{v.get('id', 'N/A')}</span>
                    <span class="badge badge-{sev_css}">{sev}</span>
                </div>
                <div class="cve-desc"><strong>Risco:</strong> {v.get('risco', 'N/A')}</div>
                <div class="cve-desc" style="margin-top:6px;color:var(--accent)"><strong>Remediação:</strong> {v.get('remediacao', 'N/A')}</div>
            </div>"""
    else:
        vulns_html = '<div class="item-row empty">Nenhuma vulnerabilidade priorizada.</div>'

    # Portas críticas pela IA
    portas_html = ""
    portas_criticas = analise.get("portas_criticas", [])
    if portas_criticas:
        for p in portas_criticas:
            portas_html += f"""
            <div class="item-row">
                <span class="badge badge-open">Porta {p.get('porta', '?')}</span>
                <span class="porta-num">{p.get('servico', '?')}</span>
                <span class="servico">{p.get('risco', '')}</span>
            </div>
            <div class="item-row" style="border:none;padding-top:0">
                <span class="servico" style="color:var(--accent)"><strong>Recomendação:</strong> {p.get('recomendacao', '')}</span>
            </div>"""

    # Recomendações
    recs_html = ""
    recomendacoes = analise.get("recomendacoes", [])
    if recomendacoes:
        recs_html = "<ol class='rec-list'>"
        for r in recomendacoes:
            recs_html += f"<li>{r}</li>"
        recs_html += "</ol>"
    else:
        recs_html = '<div class="item-row empty">Nenhuma recomendação.</div>'

    # Próximos passos
    proximos_html = ""
    proximos = analise.get("proximos_passos", [])
    if proximos:
        proximos_html = "<ol class='rec-list'>"
        for p in proximos:
            proximos_html += f"<li>{p}</li>"
        proximos_html += "</ol>"

    # Se a análise veio como texto puro (não JSON)
    texto_completo = analise.get("analise_completa", "")
    if texto_completo and not vulns and not recomendacoes:
        return f"""
        <div class="section ai-section">
            <h2 class="section-title">[+] ANÁLISE COM IA — Google Gemini</h2>
            <div class="ai-risk-badge" style="background:{cor}">RISCO: {risco}</div>
            <div class="ai-resumo"><pre style="white-space:pre-wrap;color:var(--text-muted);font-size:12px">{texto_completo}</pre></div>
        </div>"""

    return f"""
    <div class="section ai-section">
        <h2 class="section-title">[+] ANÁLISE COM IA — Google Gemini</h2>

        <div class="ai-risk-container">
            <div class="ai-risk-badge" style="background:{cor}">
                RISCO GERAL: {risco}
            </div>
        </div>

        <div class="ai-resumo">
            <h3>Resumo Executivo</h3>
            <p>{resumo}</p>
        </div>

        <h3 style="color:var(--accent);margin:20px 0 10px">Vulnerabilidades Priorizadas</h3>
        {vulns_html}

        {"" if not portas_criticas else f'<h3 style="color:var(--accent);margin:20px 0 10px">Portas Críticas</h3>{portas_html}'}

        {"" if not recomendacoes else f'<h3 style="color:var(--accent);margin:20px 0 10px">Recomendações</h3>{recs_html}'}

        {"" if not proximos else f'<h3 style="color:var(--accent);margin:20px 0 10px">Próximos Passos</h3>{proximos_html}'}
    </div>"""


def _montar_html(alvo, portas, cves, subdominios, dns,
                 criticos, altos, medios, baixos, analise_ia=None):
    """Monta o conteúdo HTML completo do relatório."""

    data_geracao = datetime.now().strftime("%d/%m/%Y às %H:%M:%S")
    ip = dns.get("ip", "N/A") if isinstance(dns, dict) else "N/A"
    reverse_dns = dns.get("reverse_dns", "N/A") if isinstance(dns, dict) else "N/A"
    ipv6 = dns.get("ipv6", "N/A") if isinstance(dns, dict) else "N/A"

    portas_html = ""
    if portas:
        for p in portas:
            portas_html += f"""
            <div class="item-row">
                <span class="badge badge-open">ABERTA</span>
                <span class="porta-num">Porta {p['porta']}</span>
                <span class="servico">{p['servico']}</span>
            </div>"""
    else:
        portas_html = '<div class="item-row empty">Nenhuma porta aberta encontrada.</div>'

    cves_html = ""
    if cves:
        for c in cves:
            sev = c.get("severidade", "N/A").upper()
            css_class = sev.lower() if sev.lower() in [
                "critical", "high", "medium", "low"
            ] else "info"

            refs_html = ""
            if c.get("referencias"):
                refs_html = "<div class='refs'>"
                for ref in c["referencias"][:2]:
                    refs_html += f'<a href="{ref}" target="_blank">Ref</a> '
                refs_html += "</div>"

            cves_html += f"""
            <div class="cve-card {css_class}">
                <div class="cve-header">
                    <span class="cve-id">{c['id']}</span>
                    <span class="badge badge-{css_class}">{sev} | Score: {c['score']}</span>
                </div>
                <div class="cve-desc">{c['descricao']}</div>
                {refs_html}
            </div>"""
    else:
        cves_html = '<div class="item-row empty">Nenhuma CVE encontrada.</div>'

    sub_html = ""
    if subdominios:
        sub_html = """<table>
            <thead><tr><th>Subdomínio</th><th>IP</th></tr></thead>
            <tbody>"""
        for s in subdominios:
            sub_html += f"<tr><td>{s['subdominio']}</td><td>{s['ip']}</td></tr>"
        sub_html += "</tbody></table>"
    else:
        sub_html = '<div class="item-row empty">Nenhum subdomínio encontrado.</div>'

    whois_html = ""
    if isinstance(dns, dict) and dns.get("whois"):
        whois_html = "<div class='whois-block'>"
        for linha in dns["whois"]:
            whois_html += f"<div class='whois-line'>{linha}</div>"
        whois_html += "</div>"
    else:
        whois_html = '<div class="item-row empty">Informações WHOIS não disponíveis.</div>'

    ia_section = _gerar_secao_ia(analise_ia)

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedSentry — {alvo}</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #0a0a0a;
            --surface: #111111;
            --surface-2: #1a1a1a;
            --border: #222222;
            --accent: #00ff41;
            --accent-dim: #00cc33;
            --red: #ff3333;
            --orange: #ff8800;
            --yellow: #ffcc00;
            --blue: #3399ff;
            --text: #e0e0e0;
            --text-muted: #666666;
            --font: 'JetBrains Mono', 'Courier New', monospace;
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            background: var(--bg);
            color: var(--text);
            font-family: var(--font);
            font-size: 13px;
            line-height: 1.6;
        }}

        .header {{
            background: var(--surface);
            border-bottom: 2px solid var(--accent);
            padding: 30px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .header h1 {{
            color: var(--accent);
            font-size: 24px;
            font-weight: 700;
            letter-spacing: 2px;
        }}

        .header .meta {{
            text-align: right;
            color: var(--text-muted);
            font-size: 12px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 30px 40px;
        }}

        .target-info {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 30px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }}

        .target-item {{
            display: flex;
            flex-direction: column;
        }}

        .target-label {{
            color: var(--text-muted);
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 4px;
        }}

        .target-value {{
            color: var(--accent);
            font-size: 14px;
            font-weight: 500;
        }}

        .resumo-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }}

        .resumo-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 20px;
            text-align: center;
        }}

        .resumo-card .numero {{
            font-size: 32px;
            font-weight: 700;
            display: block;
        }}

        .resumo-card .label {{
            font-size: 10px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 5px;
        }}

        .section {{
            margin-bottom: 30px;
        }}

        .section-title {{
            color: var(--accent);
            font-size: 16px;
            font-weight: 700;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 15px;
            letter-spacing: 1px;
        }}

        .item-row {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 12px 16px;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 15px;
        }}

        .item-row.empty {{
            color: var(--text-muted);
            font-style: italic;
        }}

        .badge {{
            font-size: 10px;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 3px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .badge-open {{ background: var(--accent); color: #000; }}
        .badge-critical {{ background: var(--red); color: #fff; }}
        .badge-high {{ background: var(--orange); color: #000; }}
        .badge-medium {{ background: var(--yellow); color: #000; }}
        .badge-low {{ background: var(--blue); color: #fff; }}
        .badge-info {{ background: #444; color: #fff; }}
        .badge-critico {{ background: var(--red); color: #fff; }}
        .badge-alto {{ background: var(--orange); color: #000; }}
        .badge-medio {{ background: var(--yellow); color: #000; }}
        .badge-baixo {{ background: var(--blue); color: #fff; }}

        .porta-num {{
            font-weight: 700;
            color: var(--accent);
            min-width: 100px;
        }}

        .servico {{
            color: var(--text-muted);
        }}

        .cve-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 10px;
            border-left: 4px solid var(--border);
        }}

        .cve-card.critical, .cve-card.critico {{ border-left-color: var(--red); }}
        .cve-card.high, .cve-card.alto {{ border-left-color: var(--orange); }}
        .cve-card.medium, .cve-card.medio {{ border-left-color: var(--yellow); }}
        .cve-card.low, .cve-card.baixo {{ border-left-color: var(--blue); }}

        .cve-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}

        .cve-id {{
            font-weight: 700;
            font-size: 14px;
            color: #fff;
        }}

        .cve-desc {{
            color: var(--text-muted);
            font-size: 12px;
            line-height: 1.5;
        }}

        .refs {{ margin-top: 8px; }}
        .refs a {{
            color: var(--blue);
            text-decoration: none;
            font-size: 11px;
            margin-right: 10px;
        }}
        .refs a:hover {{ text-decoration: underline; }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--surface);
            border-radius: 6px;
            overflow: hidden;
        }}

        th {{
            background: var(--surface-2);
            color: var(--accent);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 12px 16px;
            text-align: left;
            border-bottom: 2px solid var(--border);
        }}

        td {{
            padding: 10px 16px;
            border-bottom: 1px solid var(--border);
            font-size: 13px;
        }}

        tr:hover td {{ background: var(--surface-2); }}

        .whois-block {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 16px;
        }}

        .whois-line {{
            padding: 4px 0;
            font-size: 12px;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border);
        }}

        .whois-line:last-child {{ border-bottom: none; }}

        /* Estilos da seção de IA */
        .ai-section {{
            background: linear-gradient(135deg, #0a0f0a 0%, #0a0a0a 100%);
            border: 1px solid var(--accent);
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 30px;
        }}

        .ai-risk-container {{
            text-align: center;
            margin: 20px 0;
        }}

        .ai-risk-badge {{
            display: inline-block;
            padding: 12px 30px;
            border-radius: 6px;
            font-size: 18px;
            font-weight: 700;
            color: #000;
            letter-spacing: 2px;
        }}

        .ai-resumo {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 20px;
            margin: 15px 0;
        }}

        .ai-resumo h3 {{
            color: var(--accent);
            font-size: 13px;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .ai-resumo p {{
            color: var(--text-muted);
            font-size: 13px;
            line-height: 1.7;
        }}

        .rec-list {{
            padding-left: 20px;
            color: var(--text-muted);
        }}

        .rec-list li {{
            padding: 8px 0;
            border-bottom: 1px solid var(--border);
            font-size: 12px;
            line-height: 1.6;
        }}

        .rec-list li:last-child {{ border-bottom: none; }}

        .footer {{
            text-align: center;
            padding: 30px;
            color: var(--text-muted);
            font-size: 11px;
            border-top: 1px solid var(--border);
            margin-top: 30px;
        }}

        @media (max-width: 768px) {{
            .resumo-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .target-info {{ grid-template-columns: 1fr; }}
            .header {{ flex-direction: column; gap: 10px; }}
            .container {{ padding: 15px; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>[ REDSENTRY ]</h1>
        <div class="meta">
            <div>Relatório de Segurança</div>
            <div>{data_geracao}</div>
        </div>
    </div>

    <div class="container">
        <div class="target-info">
            <div class="target-item">
                <span class="target-label">Alvo</span>
                <span class="target-value">{alvo}</span>
            </div>
            <div class="target-item">
                <span class="target-label">IP</span>
                <span class="target-value">{ip}</span>
            </div>
            <div class="target-item">
                <span class="target-label">IPv6</span>
                <span class="target-value">{ipv6}</span>
            </div>
            <div class="target-item">
                <span class="target-label">Reverse DNS</span>
                <span class="target-value">{reverse_dns}</span>
            </div>
        </div>

        <div class="resumo-grid">
            <div class="resumo-card">
                <span class="numero" style="color: var(--accent)">{len(portas)}</span>
                <span class="label">Portas Abertas</span>
            </div>
            <div class="resumo-card">
                <span class="numero" style="color: var(--red)">{len(cves)}</span>
                <span class="label">CVEs</span>
            </div>
            <div class="resumo-card">
                <span class="numero" style="color: var(--yellow)">{len(subdominios)}</span>
                <span class="label">Subdomínios</span>
            </div>
            <div class="resumo-card">
                <span class="numero" style="color: var(--red)">{len(criticos)}</span>
                <span class="label">Críticos</span>
            </div>
            <div class="resumo-card">
                <span class="numero" style="color: var(--orange)">{len(altos)}</span>
                <span class="label">Altos</span>
            </div>
        </div>

        {ia_section}

        <div class="section">
            <h2 class="section-title">[+] PORTAS ABERTAS ({len(portas)})</h2>
            {portas_html}
        </div>

        <div class="section">
            <h2 class="section-title">[+] VULNERABILIDADES ({len(cves)})</h2>
            {cves_html}
        </div>

        <div class="section">
            <h2 class="section-title">[+] SUBDOMÍNIOS ({len(subdominios)})</h2>
            {sub_html}
        </div>

        <div class="section">
            <h2 class="section-title">[+] INFORMAÇÕES DNS / WHOIS</h2>
            {whois_html}
        </div>

        <div class="footer">
            RedSentry — Red Team Automation Tool | Gerado automaticamente em {data_geracao}
        </div>
    </div>
</body>
</html>"""
