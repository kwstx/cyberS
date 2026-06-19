import asyncio
import logging
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod

logger = logging.getLogger("DiscoveryEngine")

class AbstractReconnaissance(ABC):
    """
    Abstract interface for passive reconnaissance.
    In a production system, these would hook into external OSINT APIs (e.g., SecurityTrails, Censys).
    Due to safety constraints, we only implement mock methods.
    """
    @abstractmethod
    async def get_dns_records(self, domain: str) -> List[str]:
        pass
    
    @abstractmethod
    async def get_whois_data(self, domain: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def query_ct_logs(self, domain: str) -> List[str]:
        pass

class MockReconnaissance(AbstractReconnaissance):
    async def get_dns_records(self, domain: str) -> List[str]:
        await asyncio.sleep(0.1)  # Simulate network latency
        return [f"192.168.1.{len(domain)}", f"mail.{domain}"]
    
    async def get_whois_data(self, domain: str) -> Dict[str, Any]:
        await asyncio.sleep(0.1)
        return {"registrar": "MockRegistrar LLC", "creation_date": "2020-01-01"}

    async def query_ct_logs(self, domain: str) -> List[str]:
        await asyncio.sleep(0.1)
        return [f"*.{domain}", domain]


class AbstractActiveScanner(ABC):
    """
    Abstract interface for active infrastructure scanning.
    Strictly mocked out to prevent unauthorized probing.
    """
    @abstractmethod
    async def scan_ports(self, ip: str) -> List[int]:
        pass
    
    @abstractmethod
    async def get_cves_from_services(self, ip: str, ports: List[int]) -> List[str]:
        pass

class MockActiveScanner(AbstractActiveScanner):
    async def scan_ports(self, ip: str) -> List[int]:
        await asyncio.sleep(0.1)
        return [80, 443] if "192" in ip else []

    async def get_cves_from_services(self, ip: str, ports: List[int]) -> List[str]:
        await asyncio.sleep(0.1)
        if 443 in ports:
            return ["CVE-2023-0286"] # Mock OpenSSL vulnerability
        return []


class SCAIntegration:
    """
    Simulates fetching Software Composition Analysis (SBOMs) to build 4th-party chains.
    """
    async def fetch_dependencies(self, vendor: str) -> List[Dict[str, Any]]:
        await asyncio.sleep(0.2)
        # Mock dependency tree mapping
        mock_tree = {
            "AcmeCorp": [{"type": "vendor", "name": "BetaCorp"}, {"type": "component", "name": "OpenSSL", "version": "1.1.1t"}],
            "BetaCorp": [{"type": "vendor", "name": "GammaLLC"}, {"type": "component", "name": "Log4j", "version": "2.14.0"}],
            "GammaLLC": [{"type": "component", "name": "SpringCore", "version": "5.3.10"}]
        }
        return mock_tree.get(vendor, [])


class DiscoveryOrchestrator:
    """
    Orchestrates the discovery phase starting from seed vendors and traversing to N-th parties.
    """
    def __init__(self):
        self.recon = MockReconnaissance()
        self.scanner = MockActiveScanner()
        self.sca = SCAIntegration()
        self.discovered_topology = []

    async def recursive_traverse(self, seed_vendor: str, max_depth: int = 3, current_depth: int = 0):
        if current_depth >= max_depth:
            return

        logger.info(f"Traversing level {current_depth}: {seed_vendor}")
        
        # 1. Passive Recon
        dns = await self.recon.get_dns_records(seed_vendor)
        
        # 2. Simulated Active Scan on discovered infra
        discovered_cves = []
        for ip in dns:
            ports = await self.scanner.scan_ports(ip)
            cves = await self.scanner.get_cves_from_services(ip, ports)
            discovered_cves.extend(cves)
            
        # 3. Supply Chain Composition
        dependencies = await self.sca.fetch_dependencies(seed_vendor)
        
        node_data = {
            "vendor_name": seed_vendor,
            "depth": current_depth,
            "infrastructure": {"dns": dns, "cves": discovered_cves},
            "dependencies": dependencies
        }
        self.discovered_topology.append(node_data)
        
        # Recursively map N-th party vendors
        for dep in dependencies:
            if dep["type"] == "vendor":
                await self.recursive_traverse(dep["name"], max_depth, current_depth + 1)

    def get_topology(self) -> List[Dict[str, Any]]:
        return self.discovered_topology
