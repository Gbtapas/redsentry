"""
Módulo de Coleta de Informações DNS
Coleta registros DNS, IP, reverse DNS e informações WHOIS de um domínio.
"""

import socket
import subprocess
import platform


def dns_info(dominio):
    """
    Coleta informações DNS completas de um domínio.

    Args:
        dominio (str): Domínio ou IP alvo.

    Returns:
        dict: Dicionário com informações coletadas:
              - dominio: domínio analisado
              - ip: endereço IP resolvido
              - reverse_dns: hostname via reverse DNS
              - whois: lista de linhas relevantes do WHOIS
              - ipv6: endereço IPv6 (se disponível)
    """
    print(f"\n{'='*50}")
    print(f"  [*] DNS COLLECTOR")
    print(f"  [*] Alvo: {dominio}")
    print(f"{'='*50}\n")

    info = {
        "dominio": dominio,
        "ip": "Não resolvido",
        "reverse_dns": "N/A",
        "ipv6": "N/A",
        "whois": [],
    }

    # --- Resolver IP ---
    try:
        ip = socket.gethostbyname(dominio)
        info["ip"] = ip
        print(f"  [IP]          {ip}")
    except socket.gaierror:
        print(f"  [ERRO] Não foi possível resolver: {dominio}")

    # --- Resolver IPv6 ---
    try:
        resultados = socket.getaddrinfo(dominio, None, socket.AF_INET6)
        if resultados:
            ipv6 = resultados[0][4][0]
            info["ipv6"] = ipv6
            print(f"  [IPv6]        {ipv6}")
    except (socket.gaierror, IndexError, OSError):
        pass

    # --- Reverse DNS ---
    if info["ip"] != "Não resolvido":
        try:
            hostname = socket.gethostbyaddr(info["ip"])
            info["reverse_dns"] = hostname[0]
            print(f"  [Reverse DNS] {hostname[0]}")
        except (socket.herror, socket.gaierror):
            info["reverse_dns"] = "N/A"
            print(f"  [Reverse DNS] Não disponível")

    # --- WHOIS ---
    linhas_whois = _coletar_whois(dominio)
    info["whois"] = linhas_whois

    if linhas_whois:
        print(f"\n  [WHOIS] Informações relevantes:")
        for linha in linhas_whois:
            print(f"         {linha}")
    else:
        print(f"  [WHOIS] Informações não disponíveis")

    print()
    return info


def _coletar_whois(dominio):
    """
    Executa o comando whois e extrai informações relevantes.

    Args:
        dominio (str): Domínio para consulta WHOIS.

    Returns:
        list: Lista de strings com informações relevantes do WHOIS.
    """
    chaves_relevantes = [
        "registrar",
        "registrant",
        "name server",
        "creation date",
        "registry expiry",
        "updated date",
        "registrant country",
        "registrant organization",
        "dnssec",
        "status",
        "domain name",
    ]

    try:
        # Verificar se whois está disponível
        sistema = platform.system().lower()
        comando = ["whois", dominio]

        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            timeout=15,
        )

        if resultado.returncode != 0:
            return []

        linhas_filtradas = []

        for linha in resultado.stdout.split("\n"):
            linha_limpa = linha.strip()
            if not linha_limpa or linha_limpa.startswith("%") or linha_limpa.startswith("#"):
                continue

            for chave in chaves_relevantes:
                if chave in linha_limpa.lower():
                    # Evitar duplicatas
                    if linha_limpa not in linhas_filtradas:
                        linhas_filtradas.append(linha_limpa)
                    break

        return linhas_filtradas[:15]  # Limitar a 15 linhas

    except FileNotFoundError:
        # Comando whois não instalado
        return ["Comando 'whois' não encontrado no sistema."]
    except subprocess.TimeoutExpired:
        return ["Timeout na consulta WHOIS."]
    except Exception as e:
        return [f"Erro na consulta WHOIS: {e}"]


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: python dns_collector.py <dominio>")
        print("Exemplo: python dns_collector.py example.com")
        sys.exit(1)

    dominio = sys.argv[1]
    dns_info(dominio)
