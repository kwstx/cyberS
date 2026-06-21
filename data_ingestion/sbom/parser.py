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
    def _sanitize_str(val: Any, max_len: int = 1024) -> str:
        if val is None:
            return ""
        val_str = str(val)
        if len(val_str) > max_len:
            logger.warning(f"Field exceeds maximum length of {max_len}. Truncating.")
            return val_str[:max_len]
        return val_str

    @staticmethod
    def parse(payload: Dict[str, Any]) -> NormalizedSBOM:
        if not isinstance(payload, dict):
            logger.error("Invalid payload type. Expected a dictionary.")
            raise ValueError("Payload must be a dictionary")
            
        try:
            if "bomFormat" in payload and isinstance(payload.get("bomFormat"), str) and payload["bomFormat"].lower() == "cyclonedx":
                return SBOMParser._parse_cyclonedx(payload)
            elif "spdxVersion" in payload:
                return SBOMParser._parse_spdx(payload)
            else:
                logger.warning("Unknown SBOM format. Defaulting to basic extraction.")
                return SBOMParser._parse_generic(payload)
        except Exception as e:
            logger.error(f"Critical error parsing SBOM: {e}", exc_info=True)
            raise ValueError(f"Failed to parse SBOM: {e}")

    @staticmethod
    def _parse_cyclonedx(payload: Dict[str, Any]) -> NormalizedSBOM:
        components = []
        raw_components = payload.get("components")
        if not isinstance(raw_components, list):
            logger.warning("CycloneDX 'components' is not a list. Skipping components parsing.")
            raw_components = []

        for comp in raw_components:
            if not isinstance(comp, dict):
                logger.warning("Component item is not a dictionary. Skipping.")
                continue
            try:
                supplier_data = comp.get("supplier")
                supplier_name = ""
                if isinstance(supplier_data, dict):
                    supplier_name = SBOMParser._sanitize_str(supplier_data.get("name"))
                elif isinstance(supplier_data, str):
                    supplier_name = SBOMParser._sanitize_str(supplier_data)

                components.append(
                    NormalizedComponent(
                        name=SBOMParser._sanitize_str(comp.get("name", "unknown")),
                        version=SBOMParser._sanitize_str(comp.get("version", "0.0.0")),
                        purl=SBOMParser._sanitize_str(comp.get("purl")) if comp.get("purl") is not None else None,
                        bom_ref=SBOMParser._sanitize_str(comp.get("bom-ref")) if comp.get("bom-ref") is not None else None,
                        supplier=supplier_name if supplier_name else None
                    )
                )
            except Exception as ce:
                logger.warning(f"Failed parsing individual component: {ce}. Skipping component.")
        
        metadata = payload.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        metadata_comp = metadata.get("component", {})
        if not isinstance(metadata_comp, dict):
            metadata_comp = {}
        vendor = SBOMParser._sanitize_str(metadata_comp.get("name", "Unknown Vendor"))
        
        return NormalizedSBOM(
            format="CycloneDX",
            spec_version=SBOMParser._sanitize_str(payload.get("specVersion", "unknown")),
            serial_number=SBOMParser._sanitize_str(payload.get("serialNumber")) if payload.get("serialNumber") is not None else None,
            vendor=vendor,
            components=components
        )

    @staticmethod
    def _parse_spdx(payload: Dict[str, Any]) -> NormalizedSBOM:
        components = []
        packages = payload.get("packages")
        if not isinstance(packages, list):
            logger.warning("SPDX 'packages' is not a list. Skipping packages parsing.")
            packages = []

        for pkg in packages:
            if not isinstance(pkg, dict):
                logger.warning("Package item is not a dictionary. Skipping.")
                continue
            try:
                # Extract external refs for PURL
                purl = None
                raw_refs = pkg.get("externalRefs")
                if isinstance(raw_refs, list):
                    for ref in raw_refs:
                        if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                            purl = SBOMParser._sanitize_str(ref.get("referenceLocator"))
                            break
                            
                components.append(
                    NormalizedComponent(
                        name=SBOMParser._sanitize_str(pkg.get("name", "unknown")),
                        version=SBOMParser._sanitize_str(pkg.get("versionInfo", "0.0.0")),
                        purl=purl,
                        bom_ref=SBOMParser._sanitize_str(pkg.get("SPDXID")) if pkg.get("SPDXID") is not None else None,
                        supplier=SBOMParser._sanitize_str(pkg.get("supplier")) if pkg.get("supplier") is not None else None
                    )
                )
            except Exception as pe:
                logger.warning(f"Failed parsing individual package: {pe}. Skipping package.")
            
        return NormalizedSBOM(
            format="SPDX",
            spec_version=SBOMParser._sanitize_str(payload.get("spdxVersion", "unknown")),
            serial_number=SBOMParser._sanitize_str(payload.get("documentNamespace")) if payload.get("documentNamespace") is not None else None,
            vendor=SBOMParser._sanitize_str(payload.get("name", "Unknown Vendor")),
            components=components
        )

    @staticmethod
    def _parse_generic(payload: Dict[str, Any]) -> NormalizedSBOM:
        return NormalizedSBOM(
            format="Unknown",
            spec_version="Unknown",
            vendor=SBOMParser._sanitize_str(payload.get("vendor", "Unknown")),
            components=[]
        )
