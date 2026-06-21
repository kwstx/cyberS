import logging
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

logger = logging.getLogger("MBOMParser")

class TrainingDataset(BaseModel):
    name: str
    size_gb: Optional[float] = None
    license: Optional[str] = None
    hash_sha256: Optional[str] = None
    source_url: Optional[str] = None

class ModelArchitecture(BaseModel):
    name: str
    parameters_count: Optional[int] = None  # e.g., 7000000000 (7B)
    layers_count: Optional[int] = None
    framework: Optional[str] = None  # PyTorch, JAX, TensorFlow

class ModelDependency(BaseModel):
    package_name: str
    version: str
    purl: Optional[str] = None
    license: Optional[str] = None

class NormalizedMBOM(BaseModel):
    model_name: str
    version: str
    architecture: ModelArchitecture
    datasets: List[TrainingDataset] = Field(default_factory=list)
    dependencies: List[ModelDependency] = Field(default_factory=list)
    signature_verified: bool = False

class MBOMParser:
    """
    Parses Model Bills of Materials (MBOMs) tracking AI model architectures, training datasets, and libraries.
    """
    @staticmethod
    def _sanitize_str(val: Any, max_len: int = 1024) -> str:
        if val is None:
            return ""
        val_str = str(val)
        if len(val_str) > max_len:
            logger.warning(f"MBOM field exceeds maximum length of {max_len}. Truncating.")
            return val_str[:max_len]
        return val_str

    @staticmethod
    def parse(payload: Dict[str, Any]) -> NormalizedMBOM:
        if not isinstance(payload, dict):
            logger.error("Invalid MBOM payload type. Expected a dictionary.")
            raise ValueError("MBOM payload must be a dictionary")
            
        logger.info("Parsing Model Bill of Materials (MBOM)...")
        
        try:
            # Extract model metadata
            model_name = MBOMParser._sanitize_str(payload.get("model_name", payload.get("name", "unknown_model")))
            version = MBOMParser._sanitize_str(payload.get("version", "0.0.0"))
            
            # Extract architecture properties
            arch_data = payload.get("architecture")
            if not isinstance(arch_data, dict):
                logger.warning("MBOM architecture field is missing or not a dictionary. Using defaults.")
                arch_data = {}
                
            try:
                architecture = ModelArchitecture(
                    name=MBOMParser._sanitize_str(arch_data.get("name", "unknown_arch")),
                    parameters_count=arch_data.get("parameters_count") or arch_data.get("parameters"),
                    layers_count=arch_data.get("layers_count") or arch_data.get("layers"),
                    framework=MBOMParser._sanitize_str(arch_data.get("framework", "PyTorch"))
                )
            except Exception as ae:
                logger.warning(f"Error parsing model architecture: {ae}. Falling back to default architecture.")
                architecture = ModelArchitecture(name="unknown_arch", framework="PyTorch")
            
            # Extract datasets
            datasets = []
            raw_datasets = payload.get("datasets")
            if isinstance(raw_datasets, list):
                for ds in raw_datasets:
                    if not isinstance(ds, dict):
                        logger.warning("Dataset item is not a dictionary. Skipping.")
                        continue
                    try:
                        datasets.append(
                            TrainingDataset(
                                name=MBOMParser._sanitize_str(ds.get("name", "unknown_dataset")),
                                size_gb=ds.get("size_gb"),
                                license=MBOMParser._sanitize_str(ds.get("license")) if ds.get("license") is not None else None,
                                hash_sha256=MBOMParser._sanitize_str(ds.get("hash_sha256") or ds.get("hash")) if (ds.get("hash_sha256") or ds.get("hash")) is not None else None,
                                source_url=MBOMParser._sanitize_str(ds.get("source_url")) if ds.get("source_url") is not None else None
                            )
                        )
                    except Exception as de:
                        logger.warning(f"Failed parsing individual dataset: {de}. Skipping.")
            else:
                logger.warning("MBOM 'datasets' is not a list. Skipping datasets parsing.")
                
            # Extract software dependencies of the model execution environment
            dependencies = []
            raw_dependencies = payload.get("dependencies")
            if isinstance(raw_dependencies, list):
                for dep in raw_dependencies:
                    if not isinstance(dep, dict):
                        logger.warning("Dependency item is not a dictionary. Skipping.")
                        continue
                    try:
                        dependencies.append(
                            ModelDependency(
                                package_name=MBOMParser._sanitize_str(dep.get("package_name") or dep.get("name", "unknown")),
                                version=MBOMParser._sanitize_str(dep.get("version", "0.0.0")),
                                purl=MBOMParser._sanitize_str(dep.get("purl")) if dep.get("purl") is not None else None,
                                license=MBOMParser._sanitize_str(dep.get("license")) if dep.get("license") is not None else None
                            )
                        )
                    except Exception as dpe:
                        logger.warning(f"Failed parsing model dependency: {dpe}. Skipping.")
            else:
                logger.warning("MBOM 'dependencies' is not a list. Skipping dependencies parsing.")
                
            # Optional signature verification status
            signature_verified = bool(payload.get("signature_verified", False))
            
            return NormalizedMBOM(
                model_name=model_name,
                version=version,
                architecture=architecture,
                datasets=datasets,
                dependencies=dependencies,
                signature_verified=signature_verified
            )
        except Exception as e:
            logger.error(f"Critical error parsing MBOM: {e}", exc_info=True)
            raise ValueError(f"Failed to parse MBOM: {e}")
