"""
RedSentry - Módulos de automação para Red Team
"""

from .port_scanner import port_scan
from .cve_search import buscar_cves
from .subdomain_enum import enum_subdominios
from .dns_collector import dns_info
from .report_gen import gerar_relatorio

__all__ = [
    "port_scan",
    "buscar_cves",
    "enum_subdominios",
    "dns_info",
    "gerar_relatorio",
]

# Importação condicional do módulo de IA
try:
    from .ai_analyzer import configurar as configurar_gemini
    from .ai_analyzer import analisar_achados as analisar_com_ia
    __all__.extend(["configurar_gemini", "analisar_com_ia"])
except ImportError:
    pass
