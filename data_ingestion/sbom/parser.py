from typing import List, Optional, Dict, Any
from pydantic import BaseModel
import json
import logging

logger = logging.getLogger("SBOMParser")

class NormalizedComponent(BaseModel):
    name: str
    version: str
    purl: Optional[str] = None
    bom_ref: Optional[str] = None
    supplier: Optional[str] = None

class NormalizedSBOM(BaseModel):
    format: str
    spec_version: str
    serial_number: Optional[str] = None
    vendor: str
    components: List[NormalizedComponent]

class SBOMParser:
    """Parses Software Bill of Materials (SBOM) in CycloneDX or SPDX formats."""
    
    @staticmethod
    def parse(payload: Dict[str, Any]) -> NormalizedSBOM:
        if "bomFormat" in payload and payload["bomFormat"].lower() == "cyclonedx":
            return SBOMParser._parse_cyclonedx(payload)
        elif "spdxVersion" in payload:
            return SBOMParser._parse_spdx(payload)
        else:
            logger.warning("Unknown SBOM format. Defaulting to basic extraction.")
            return SBOMParser._parse_generic(payload)

    @staticmethod
    def _parse_cyclonedx(payload: Dict[str, Any]) -> NormalizedSBOM:
        components = []
        for comp in payload.get("components", []):
            components.append(
                NormalizedComponent(
                    name=comp.get("name", "unknown"),
                    version=comp.get("version", "0.0.0"),
                    purl=comp.get("purl"),
                    bom_ref=comp.get("bom-ref"),
                    supplier=comp.get("supplier", {}).get("name")
                )
            )
        
        metadata = payload.get("metadata", {})
        vendor = metadata.get("component", {}).get("name", "Unknown Vendor")
        
        return NormalizedSBOM(
            format="CycloneDX",
            spec_version=payload.get("specVersion", "unknown"),
            serial_number=payload.get("serialNumber"),
            vendor=vendor,
            components=components
        )

    @staticmethod
    def _parse_spdx(payload: Dict[str, Any]) -> NormalizedSBOM:
        components = []
        for pkg in payload.get("packages", []):
            # Extract external refs for PURL
            purl = None
            for ref in pkg.get("externalRefs", []):
                if ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator")
                    break
                    
            components.append(
                NormalizedComponent(
                    name=pkg.get("name", "unknown"),
                    version=pkg.get("versionInfo", "0.0.0"),
                    purl=purl,
                    bom_ref=pkg.get("SPDXID"),
                    supplier=pkg.get("supplier")
                )
            )
            
        return NormalizedSBOM(
            format="SPDX",
            spec_version=payload.get("spdxVersion", "unknown"),
            serial_number=payload.get("documentNamespace"),
            vendor=payload.get("name", "Unknown Vendor"),
            components=components
        )

    @staticmethod
    def _parse_generic(payload: Dict[str, Any]) -> NormalizedSBOM:
        return NormalizedSBOM(
            format="Unknown",
            spec_version="Unknown",
            vendor="Unknown",
            components=[]
        )
