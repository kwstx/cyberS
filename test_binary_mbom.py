import asyncio
import logging
from data_ingestion.mbom import MBOMParser
from data_ingestion.binary_analysis import ReversingLabsClient, MLMalwareDetector
from semantic_fusion.graph_client import GraphClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TestBinaryMBOM")

def test_mbom_parser():
    logger.info("=== Testing MBOM Parser ===")
    mbom_payload = {
        "model_name": "Llama-3-8B-Instruct",
        "version": "1.0.0",
        "architecture": {
            "name": "TransformerDecoder",
            "parameters_count": 8000000000,
            "layers_count": 32,
            "framework": "PyTorch"
        },
        "datasets": [
            {
                "name": "RedPajama-V2",
                "size_gb": 5000.0,
                "license": "Apache-2.0",
                "hash_sha256": "abc123dataset"
            }
        ],
        "dependencies": [
            {
                "package_name": "torch",
                "version": "2.2.0",
                "purl": "pkg:pypi/torch@2.2.0"
            }
        ],
        "signature_verified": True
    }
    
    parsed = MBOMParser.parse(mbom_payload)
    assert parsed.model_name == "Llama-3-8B-Instruct"
    assert parsed.architecture.layers_count == 32
    assert len(parsed.datasets) == 1
    assert parsed.datasets[0].name == "RedPajama-V2"
    assert parsed.dependencies[0].package_name == "torch"
    assert parsed.signature_verified is True
    logger.info("MBOM Parser Test: PASSED")

async def test_binary_analysis():
    logger.info("=== Testing Binary Analysis (ReversingLabs & ML) ===")
    rl_client = ReversingLabsClient()
    ml_detector = MLMalwareDetector()
    
    # 1. Clean check
    clean_rl = await rl_client.check_hash("clean_hash_123")
    assert clean_rl["status"] == "CLEAN"
    
    clean_ml = ml_detector.analyze_binary({
        "entropy": 4.2,
        "num_imports": 15,
        "num_sections": 4,
        "packer_detected": False,
        "signature_valid": True
    })
    assert clean_ml["malware_detected"] is False
    assert clean_ml["malware_probability"] < 0.5
    
    # 2. Malicious check
    mal_rl = await rl_client.check_hash("compromised_hash_999")
    assert mal_rl["status"] == "MALICIOUS"
    
    mal_ml = ml_detector.analyze_binary({
        "entropy": 7.9,
        "num_imports": 90,
        "num_sections": 8,
        "packer_detected": True,
        "signature_valid": False
    })
    assert mal_ml["malware_detected"] is True
    assert mal_ml["malware_probability"] > 0.5
    logger.info("Binary Analysis Test: PASSED")

async def test_graph_prioritization():
    logger.info("=== Testing Graph Client Prioritization ===")
    client = GraphClient()
    await client.connect() # fallbacks to mock
    
    # Add an identity vendor
    await client.create_identity("AI-Vendor-Inc", security_score=80)
    
    # Add a normal SoftwareComponent (SBOM component)
    await client.add_component(
        identity_name="AI-Vendor-Inc",
        name="crypto-helper",
        version="1.0.0",
        purl="pkg:generic/crypto-helper@1.0.0"
    )
    # Link a vulnerability
    await client.link_vulnerabilities_to_component(
        purl="pkg:generic/crypto-helper@1.0.0",
        vulnerabilities=["CVE-2024-9999"],
        exploit_score=0.8,
        severity="HIGH"
    )
    
    # Add an AIModel
    await client.add_ai_model(
        identity_name="AI-Vendor-Inc",
        model_name="SmartPredictor",
        version="2.1.0",
        architecture={"name": "Transformer", "parameters_count": 100000000},
        signature_verified=False
    )
    
    # Add Dataset
    await client.add_dataset(
        model_purl="pkg:ml/SmartPredictor@2.1.0",
        dataset_name="sensitive-customer-interactions",
        size_gb=12.5,
        license="Proprietary"
    )
    
    # Add binary malware report to crypto-helper
    await client.add_binary_analysis_report(
        target_purl="pkg:generic/crypto-helper@1.0.0",
        hash_val="malicious_sha256_hash",
        status="MALICIOUS",
        threat_name="Trojan.Simulated",
        trust_factor=0,
        malware_prob=0.92,
        is_malicious=True
    )
    
    # Link a device to crypto-helper
    await client.add_device_and_vulnerabilities("10.0.0.12", [80, 443], ["CVE-2024-9999"])
    await client.link_device_to_component("10.0.0.12", "pkg:generic/crypto-helper@1.0.0", ["CVE-2024-9999"])
    
    # Prioritize risks
    risks = await client.get_prioritized_risks()
    logger.info(f"Prioritized Risks: {risks}")
    
    assert len(risks) >= 2
    # The component with malicious report + device impact + vuln exploit score should be ranked first
    assert risks[0]["purl"] == "pkg:generic/crypto-helper@1.0.0"
    assert risks[0]["malicious_detected"] is True
    assert risks[0]["priority_score"] == 100.0  # (0.8 * 50 = 40) + 20 (no signature verified property explicitly set) + 100 (malicious) + 30 (1 device) = 190, capped at 100
    
    # SmartPredictor should have signature verified false (+20) and exploit score 0, total 20 priority score
    assert risks[1]["purl"] == "pkg:ml/SmartPredictor@2.1.0"
    assert risks[1]["priority_score"] == 20.0
    
    logger.info("Graph Client Prioritization Test: PASSED")

if __name__ == "__main__":
    test_mbom_parser()
    asyncio.run(test_binary_analysis())
    asyncio.run(test_graph_prioritization())
