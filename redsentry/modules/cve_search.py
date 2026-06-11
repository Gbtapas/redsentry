"""
Módulo de Busca de CVEs
Consulta a API do NVD (National Vulnerability Database) para buscar
vulnerabilidades conhecidas de um produto ou serviço.
"""

import requests
import time


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def buscar_cves(produto, max_resultados=5):
    """
    Busca CVEs conhecidas para um produto ou serviço.

    Args:
        produto (str): Nome do produto ou serviço (ex: "Apache", "OpenSSH", "nginx").
        max_resultados (int): Número máximo de CVEs a retornar.

    Returns:
        list: Lista de dicionários com informações das CVEs.
              Cada dicionário contém: id, descricao, score, severidade, referencias.
    """
    print(f"\n  [*] Buscando CVEs para: {produto}")

    params = {
        "keywordSearch": produto,
        "resultsPerPage": max_resultados,
    }

    headers = {
        "User-Agent": "RedSentry-SecurityTool/1.0",
    }

    try:
        response = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=30,
        )

        if response.status_code == 200:
            data = response.json()
            vulnerabilidades = data.get("vulnerabilities", [])
            resultados = []

            for vuln in vulnerabilidades:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "N/A")
                descricoes = cve_data.get("descriptions", [])
                descricao = "Sem descrição disponível."

                for desc in descricoes:
                    if desc.get("lang") == "en":
                        descricao = desc.get("value", descricao)
                        break

                # Limitar descrição a 300 caracteres
                if len(descricao) > 300:
                    descricao = descricao[:300] + "..."

                # Extrair score CVSS
                metrics = cve_data.get("metrics", {})
                score = "N/A"
                severidade = "N/A"

                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0].get("cvssData", {})
                    score = cvss.get("baseScore", "N/A")
                    severidade = cvss.get("baseSeverity", "N/A")
                elif "cvssMetricV30" in metrics:
                    cvss = metrics["cvssMetricV30"][0].get("cvssData", {})
                    score = cvss.get("baseScore", "N/A")
                    severidade = cvss.get("baseSeverity", "N/A")
                elif "cvssMetricV2" in metrics:
                    cvss = metrics["cvssMetricV2"][0].get("cvssData", {})
                    score = cvss.get("baseScore", "N/A")
                    severidade = metrics["cvssMetricV2"][0].get("baseSeverity", "N/A")

                # Extrair referências
                refs = []
                for ref in cve_data.get("references", [])[:3]:
                    refs.append(ref.get("url", ""))

                resultados.append({
                    "id": cve_id,
                    "descricao": descricao,
                    "score": score,
                    "severidade": str(severidade).upper(),
                    "referencias": refs,
                })

                # Exibir no terminal
                cor = _cor_severidade(str(severidade))
                print(f"  [{cor}] {cve_id} | Score: {score} | {severidade}")
                print(f"         {descricao[:100]}...")

            if not resultados:
                print(f"  [INFO] Nenhuma CVE encontrada para '{produto}'.")

            # Respeitar rate limit da API do NVD (5 req/30 seg sem API key)
            time.sleep(1)

            return resultados

        elif response.status_code == 403:
            print(f"  [ERRO] Rate limit da API do NVD atingido. Aguarde 30 segundos.")
            return []
        else:
            print(f"  [ERRO] Requisição falhou com status: {response.status_code}")
            return []

    except requests.exceptions.Timeout:
        print(f"  [ERRO] Timeout ao conectar com a API do NVD.")
        return []
    except requests.exceptions.ConnectionError:
        print(f"  [ERRO] Sem conexão com a API do NVD.")
        return []
    except Exception as e:
        print(f"  [ERRO] Erro inesperado: {e}")
        return []


def _cor_severidade(severidade):
    """Retorna indicador visual baseado na severidade."""
    cores = {
        "CRITICAL": "CRITICO",
        "HIGH": "ALTO",
        "MEDIUM": "MEDIO",
        "LOW": "BAIXO",
    }
    return cores.get(severidade.upper(), "N/A")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: python cve_search.py <produto>")
        print("Exemplo: python cve_search.py 'Apache httpd'")
        sys.exit(1)

    produto = " ".join(sys.argv[1:])
    buscar_cves(produto, max_resultados=10)
