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
    def parse(payload: Dict[str, Any]) -> NormalizedMBOM:
        logger.info("Parsing Model Bill of Materials (MBOM)...")
        
        # Extract model metadata
        model_name = payload.get("model_name", payload.get("name", "unknown_model"))
        version = payload.get("version", "0.0.0")
        
        # Extract architecture properties
        arch_data = payload.get("architecture", {})
        architecture = ModelArchitecture(
            name=arch_data.get("name", "unknown_arch"),
            parameters_count=arch_data.get("parameters_count") or arch_data.get("parameters"),
            layers_count=arch_data.get("layers_count") or arch_data.get("layers"),
            framework=arch_data.get("framework", "PyTorch")
        )
        
        # Extract datasets
        datasets = []
        for ds in payload.get("datasets", []):
            datasets.append(
                TrainingDataset(
                    name=ds.get("name", "unknown_dataset"),
                    size_gb=ds.get("size_gb"),
                    license=ds.get("license"),
                    hash_sha256=ds.get("hash_sha256") or ds.get("hash"),
                    source_url=ds.get("source_url")
                )
            )
            
        # Extract software dependencies of the model execution environment
        dependencies = []
        for dep in payload.get("dependencies", []):
            dependencies.append(
                ModelDependency(
                    package_name=dep.get("package_name") or dep.get("name", "unknown"),
                    version=dep.get("version", "0.0.0"),
                    purl=dep.get("purl"),
                    license=dep.get("license")
                )
            )
            
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
