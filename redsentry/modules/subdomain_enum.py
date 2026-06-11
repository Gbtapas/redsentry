"""
Módulo de Enumeração de Subdominios
Descobre subdominios de um domínio alvo testando uma wordlist de nomes comuns.
"""

import socket


WORDLIST_PADRAO = [
    # Serviços comuns
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "ns1", "ns2", "mx", "dns", "vpn", "remote", "ssh",
    # Desenvolvimento
    "dev", "staging", "test", "beta", "alpha", "hml", "uat",
    "api", "app", "portal", "web", "site", "blog", "shop",
    "store", "cdn", "static", "media", "assets",
    # Administração
    "admin", "painel", "panel", "dashboard", "console",
    "cpanel", "plesk", "whm", "manage", "manager",
    # DevOps e CI/CD
    "git", "gitlab", "github", "jenkins", "ci", "cd",
    "jira", "confluence", "bitbucket", "sonar", "nexus",
    "docker", "k8s", "kubernetes", "grafana", "prometheus",
    # Monitoramento e Logs
    "monitor", "monitoring", "grafana", "kibana", "elastic",
    "elasticsearch", "logstash", "zabbix", "nagios",
    "status", "health", "metrics",
    # Banco de Dados
    "db", "database", "mysql", "postgres", "postgresql",
    "redis", "mongo", "mongodb", "mssql", "oracle",
    # Redes e Segurança
    "firewall", "waf", "proxy", "gateway", "lb", "loadbalancer",
    "auth", "sso", "ldap", "radius", "certs",
    # Comunicação
    "chat", "meet", "teams", "slack", "zoom",
    # Outros
    "backup", "archive", "files", "download", "upload",
    "intranet", "extranet", "helpdesk", "support", "help",
    "crm", "erp", "sap", "hr", "finance",
]


def enum_subdominios(dominio, wordlist=None, timeout=2):
    """
    Enumera subdominios de um domínio testando nomes da wordlist.

    Args:
        dominio (str): Domínio alvo (ex: "exemplo.com").
        wordlist (list): Lista de prefixos para testar. Se None, usa WORDLIST_PADRAO.
        timeout (float): Timeout em segundos para cada resolução DNS.

    Returns:
        list: Lista de dicionários com subdominios encontrados.
              Cada dicionário contém: subdominio, ip.
    """
    if wordlist is None:
        wordlist = WORDLIST_PADRAO

    print(f"\n{'='*50}")
    print(f"  [*] SUBDOMAIN ENUMERATION")
    print(f"  [*] Domínio: {dominio}")
    print(f"  [*] Wordlist: {len(wordlist)} entradas")
    print(f"{'='*50}\n")

    encontrados = []
    timeout_original = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    for prefixo in wordlist:
        subdominio = f"{prefixo}.{dominio}"
        try:
            ip = socket.gethostbyname(subdominio)
            print(f"  [ENCONTRADO] {subdominio:<35} -> {ip}")
            encontrados.append({
                "subdominio": subdominio,
                "ip": ip,
            })
        except socket.gaierror:
            # Subdomínio não existe — silencioso
            pass
        except socket.timeout:
            print(f"  [TIMEOUT]    {subdominio}")

    socket.setdefaulttimeout(timeout_original)

    print(f"\n  [+] Enumeração concluída.")
    print(f"  [+] Subdomínios encontrados: {len(encontrados)}/{len(wordlist)}\n")

    return encontrados


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: python subdomain_enum.py <dominio>")
        print("Exemplo: python subdomain_enum.py example.com")
        sys.exit(1)

    dominio = sys.argv[1]
    enum_subdominios(dominio)
