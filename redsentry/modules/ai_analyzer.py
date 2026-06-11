"""
Módulo de Análise com Inteligência Artificial
Utiliza Google Gemini para analisar achados de segurança,
classificar riscos e gerar recomendações de remediação.
"""

import json
import time
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
    DOTENV_DISPONIVEL = True
except ImportError:
    DOTENV_DISPONIVEL = False

try:
    import google.generativeai as genai
    GEMINI_DISPONIVEL = True
except ImportError:
    GEMINI_DISPONIVEL = False


def configurar(api_key):
    """
    Configura a API key do Gemini.

    Args:
        api_key (str): Chave de API do Google AI Studio.
    """
    if not GEMINI_DISPONIVEL:
        print("  [ERRO] Biblioteca google-generativeai não instalada.")
        print("         Rode: pip install google-generativeai")
        return False

    try:
        genai.configure(api_key="GEMINI_API_KEY")
        return True
    except Exception as e:
        print(f"  [ERRO] Falha ao configurar Gemini: {e}")
        return False


def analisar_achados(alvo, portas, cves, subdominios, dns):
    """
    Envia todos os achados para o Gemini e recebe uma análise completa.

    Args:
        alvo (str): Domínio ou IP analisado.
        portas (list): Lista de portas abertas.
        cves (list): Lista de CVEs encontradas.
        subdominios (list): Lista de subdomínios encontrados.
        dns (dict): Informações DNS coletadas.

    Returns:
        dict: Dicionário com a análise do Gemini contendo:
              - risco_geral: nível de risco geral
              - resumo: resumo executivo
              - vulnerabilidades_priorizadas: CVEs ordenadas por prioridade
              - portas_criticas: portas que representam risco
              - recomendacoes: ações de remediação sugeridas
              - proximos_passos: sugestões de próximos testes
    """
    if not GEMINI_DISPONIVEL:
        return _resposta_erro("Biblioteca google-generativeai não instalada.")

    print(f"\n{'='*55}")
    print(f"  [*] ANÁLISE COM IA (Google Gemini)")
    print(f"{'='*55}\n")

    # Montar o contexto para o Gemini
    contexto = _montar_contexto(alvo, portas, cves, subdominios, dns)

    # Montar o prompt
    prompt = _montar_prompt(contexto)

    print("  [*] Enviando dados para o Gemini...")
    print("  [*] Aguardando análise...\n")

    try:
        model = genai.GenerativeModel(
            model_name="gemini-3.5-flash",
            generation_config={
                "temperature": 0.3,
                "top_p": 0.9,
                "max_output_tokens": 4096,
            },
        )

        response = model.generate_content(prompt)

        if response.text:
            analise_texto = response.text

            # Tentar extrair JSON da resposta
            analise_json = _extrair_json(analise_texto)

            if analise_json:
                _exibir_analise(analise_json)
                return analise_json
            else:
                # Se não for JSON, retorna como texto puro
                resultado = {
                    "risco_geral": "N/A",
                    "resumo": analise_texto,
                    "vulnerabilidades_priorizadas": [],
                    "portas_criticas": [],
                    "recomendacoes": [],
                    "proximos_passos": [],
                    "analise_completa": analise_texto,
                }
                _exibir_analise_texto(analise_texto)
                return resultado
        else:
            return _resposta_erro("Gemini retornou resposta vazia.")

    except Exception as e:
        return _resposta_erro(f"Erro na chamada ao Gemini: {e}")


def _montar_contexto(alvo, portas, cves, subdominios, dns):
    """Monta o contexto formatado para enviar ao Gemini."""

    # Informações DNS
    ip = dns.get("ip", "N/A") if isinstance(dns, dict) else "N/A"
    reverse_dns = dns.get("reverse_dns", "N/A") if isinstance(dns, dict) else "N/A"
    whois = dns.get("whois", []) if isinstance(dns, dict) else []

    contexto = f"""
=== ALVO ===
Domínio: {alvo}
IP: {ip}
Reverse DNS: {reverse_dns}
WHOIS: {chr(10).join(whois) if whois else 'N/A'}

=== PORTAS ABERTAS ({len(portas)}) ===
"""

    if portas:
        for p in portas:
            contexto += f"- Porta {p['porta']}: {p['servico']}\n"
    else:
        contexto += "Nenhuma porta aberta encontrada.\n"

    contexto += f"\n=== CVEs ENCONTRADAS ({len(cves)}) ===\n"

    if cves:
        for c in cves:
            contexto += (
                f"- {c['id']} | Severidade: {c['severidade']} | "
                f"Score: {c['score']}\n"
                f"  Descrição: {c['descricao'][:200]}\n"
            )
    else:
        contexto += "Nenhuma CVE encontrada.\n"

    contexto += f"\n=== SUBDOMÍNIOS ({len(subdominios)}) ===\n"

    if subdominios:
        for s in subdominios:
            contexto += f"- {s['subdominio']} -> {s['ip']}\n"
    else:
        contexto += "Nenhum subdomínio encontrado.\n"

    return contexto


def _montar_prompt(contexto):
    """Monta o prompt que será enviado ao Gemini."""

    return f"""
Você é um especialista sênior em cibersegurança analisando resultados de uma ferramenta de reconhecimento automatizada.

Abaixo estão os resultados de um scan de segurança contra um alvo. Analise todos os dados e retorne sua análise no formato JSON especificado.

{contexto}

Retorne EXATAMENTE este formato JSON (sem markdown, sem ```json, apenas o JSON puro):

{{
  "risco_geral": "<CRITICO|ALTO|MEDIO|BAIXO>",
  "resumo": "<resumo executivo de 3-5 frases sobre a postura de segurança do alvo>",
  "vulnerabilidades_priorizadas": [
    {{
      "id": "<ID da CVE ou descricao da vulnerabilidade>",
      "severidade": "<CRITICO|ALTO|MEDIO|BAIXO>",
      "risco": "<descrição do risco real para este alvo>",
      "remediacao": "<ação concreta para corrigir>"
    }}
  ],
  "portas_criticas": [
    {{
      "porta": <numero>,
      "servico": "<nome>",
      "risco": "<por que essa porta representa risco>",
      "recomendacao": "<o que fazer>"
    }}
  ],
  "recomendacoes": [
    "<recomendação 1>",
    "<recomendação 2>",
    "<recomendação 3>"
  ],
  "proximos_passos": [
    "<próximo teste ou ação sugerida 1>",
    "<próximo teste ou ação sugerida 2>"
  ]
}}

Seja específico e técnico. Considere:
1. Portas abertas que são conhecidas vetores de ataque
2. CVEs com score alto que podem ser exploradas remotamente
3. Serviços que não deveriam estar expostos publicamente
4. Configurações padrão que representam risco
5. Subdomínios que podem revelar infraestrutura interna
6. Considere CVEs mesmo que o serviço detectado seja apenas o nome genérico (ex: HTTP pode ser Apache, nginx, IIS — sugira verificar a versão exata)

Responda APENAS com o JSON, nada mais.
"""


def _extrair_json(texto):
    """Tenta extrair JSON de uma resposta que pode conter texto adicional."""
    try:
        # Tentar direto
        return json.loads(texto)
    except json.JSONDecodeError:
        pass

    try:
        # Tentar encontrar JSON no texto
        inicio = texto.find("{")
        ultimo = texto.rfind("}")

        if inicio != -1 and ultimo != -1:
            json_str = texto[inicio:ultimo + 1]
            return json.loads(json_str)
    except json.JSONDecodeError:
        pass

    return None


def _resposta_erro(mensagem):
    """Retorna uma estrutura de resposta de erro."""
    print(f"  [ERRO] {mensagem}")
    return {
        "risco_geral": "ERRO",
        "resumo": mensagem,
        "vulnerabilidades_priorizadas": [],
        "portas_criticas": [],
        "recomendacoes": [],
        "proximos_passos": [],
        "analise_completa": mensagem,
    }


def _exibir_analise(analise):
    """Exibe a análise formatada no terminal."""
    risco = analise.get("risco_geral", "N/A")
    resumo = analise.get("resumo", "N/A")

    cor_risco = {
        "CRITICO": "\033[91m",  # vermelho
        "ALTO": "\033[93m",     # amarelo
        "MEDIO": "\033[33m",    # laranja
        "BAIXO": "\033[92m",    # verde
    }
    reset = "\033[0m"
    cor = cor_risco.get(risco, "")

    print(f"  {cor}╔═══════════════════════════════════════════════════╗{reset}")
    print(f"  {cor}║  RISCO GERAL: {risco:<36}║{reset}")
    print(f"  {cor}╚═══════════════════════════════════════════════════╝{reset}")
    print()
    print(f"  RESUMO:")
    print(f"  {resumo}")
    print()

    vulns = analise.get("vulnerabilidades_priorizadas", [])
    if vulns:
        print(f"  VULNERABILIDADES PRIORIZADAS:")
        for i, v in enumerate(vulns, 1):
            print(f"    {i}. [{v.get('severidade', 'N/A')}] {v.get('id', 'N/A')}")
            print(f"       Risco: {v.get('risco', 'N/A')}")
            print(f"       Remediação: {v.get('remediacao', 'N/A')}")
            print()

    portas_criticas = analise.get("portas_criticas", [])
    if portas_criticas:
        print(f"  PORTAS CRÍTICAS:")
        for p in portas_criticas:
            print(f"    - Porta {p.get('porta', '?')} ({p.get('servico', '?')}): {p.get('risco', 'N/A')}")
            print(f"      Recomendação: {p.get('recomendacao', 'N/A')}")
        print()

    recomendacoes = analise.get("recomendacoes", [])
    if recomendacoes:
        print(f"  RECOMENDAÇÕES:")
        for i, r in enumerate(recomendacoes, 1):
            print(f"    {i}. {r}")
        print()

    proximos = analise.get("proximos_passos", [])
    if proximos:
        print(f"  PRÓXIMOS PASSOS:")
        for i, p in enumerate(proximos, 1):
            print(f"    {i}. {p}")
        print()


def _exibir_analise_texto(texto):
    """Exibe análise em texto puro quando não é possível extrair JSON."""
    print(f"\n  {'='*55}")
    print(f"  [*] ANÁLISE DO GEMINI")
    print(f"  {'='*55}\n")
    print(texto)
    print()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: python ai_analyzer.py <GEMINI_API_KEY>")
        print("Obtenha sua chave em: https://aistudio.google.com/apikey")
        sys.exit(1)

    api_key = sys.argv[1]
    configurar(api_key)

    # Teste com dados fictícios
    analisar_achados(
        alvo="exemplo.com",
        portas=[{"porta": 22, "servico": "SSH"}, {"porta": 80, "servico": "HTTP"}],
        cves=[{"id": "CVE-2024-0001", "descricao": "Teste", "score": 9.8, "severidade": "CRITICAL", "referencias": []}],
        subdominios=[],
        dns={"ip": "1.2.3.4", "reverse_dns": "N/A", "whois": []},
    )
