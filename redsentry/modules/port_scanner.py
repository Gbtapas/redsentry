"""
Módulo de Scan de Portas TCP
Escaneia portas comuns e identifica serviços associados.
"""

import socket
from datetime import datetime


PORTAS_COMUNS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1433, 1521, 3306, 3389,
    5432, 5900, 5985, 8000, 8080, 8443, 8888, 9090
]


def _descobrir_servico(porta):
    """Tenta identificar o serviço associado a uma porta."""
    mapa_servicos = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPCbind",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        5985: "WinRM",
        8000: "HTTP-Alt",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        8888: "HTTP-Alt2",
        9090: "Web-Console",
    }

    if porta in mapa_servicos:
        return mapa_servicos[porta]

    try:
        return socket.getservbyport(porta)
    except OSError:
        return "Desconhecido"


def port_scan(alvo, portas=None, timeout=1.5):
    """
    Escaneia as portas TCP de um alvo.

    Args:
        alvo (str): Endereço IP ou hostname do alvo.
        portas (list): Lista de portas para escanear. Se None, usa PORTAS_COMUNS.
        timeout (float): Timeout em segundos para cada conexão.

    Returns:
        list: Lista de dicionários com portas abertas.
              Cada dicionário contém: porta, servico.
    """
    if portas is None:
        portas = PORTAS_COMUNS

    print(f"\n{'='*50}")
    print(f"  [*] PORT SCANNER")
    print(f"  [*] Alvo: {alvo}")
    print(f"  [*] Portas: {len(portas)}")
    print(f"  [*] Inicio: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    print(f"{'='*50}\n")

    portas_abertas = []

    for porta in portas:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            resultado = sock.connect_ex((alvo, porta))

            if resultado == 0:
                servico = _descobrir_servico(porta)
                print(f"  [ABERTA]  Porta {porta:<6} | Servico: {servico}")
                portas_abertas.append({
                    "porta": porta,
                    "servico": servico,
                })

            sock.close()

        except socket.gaierror:
            print(f"  [ERRO] Nao foi possivel resolver o hostname: {alvo}")
            return []
        except socket.error as e:
            print(f"  [ERRO] Erro de socket na porta {porta}: {e}")

    print(f"\n  [+] Scan concluido. Portas abertas: {len(portas_abertas)}/{len(portas)}")
    print(f"  [+] Fim: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")

    return portas_abertas


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: python port_scanner.py <alvo>")
        sys.exit(1)

    alvo = sys.argv[1]
    port_scan(alvo)
