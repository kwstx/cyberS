import structlog
from typing import List, Tuple, Optional
import base64

try:
    import tenseal as ts
    TENSEAL_AVAILABLE = True
except ImportError:
    TENSEAL_AVAILABLE = False

logger = structlog.get_logger(__name__)

class HEEngine:
    """
    Homomorphic Encryption Engine for Privacy-Preserving Risk Inference.
    Utilizes TenSEAL (CKKS scheme) for evaluating risk metrics over encrypted data.
    """
    def __init__(self, poly_modulus_degree: int = 8192, coeff_mod_bit_sizes: List[int] = [60, 40, 40, 60]):
        self.context = self._create_context(poly_modulus_degree, coeff_mod_bit_sizes)
        self.context.global_scale = 2 ** 40
        logger.info("HEEngine initialized", poly_modulus_degree=poly_modulus_degree, tenseal_available=TENSEAL_AVAILABLE)

    def _create_context(self, poly_modulus_degree: int, coeff_mod_bit_sizes: List[int]):
        """Creates the TenSEAL context for the CKKS scheme."""
        if not TENSEAL_AVAILABLE:
            logger.warning("TenSEAL not available. HEEngine will operate in simulation mode.")
            return None
        
        context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=poly_modulus_degree,
            coeff_mod_bit_sizes=coeff_mod_bit_sizes
        )
        context.generate_galois_keys()
        return context

    def get_public_context_bytes(self) -> bytes:
        """Returns the serialized public context for client encryption."""
        if not TENSEAL_AVAILABLE:
            return b"simulated_public_context"
        
        # Serialize only the public part
        return self.context.serialize(save_public_key=True, save_secret_key=False, save_galois_keys=True, save_relin_keys=True)

    def encrypt_vector(self, vector: List[float]) -> str:
        """Encrypts a plaintext vector into a CKKS ciphertext, returning base64 encoded string."""
        if not TENSEAL_AVAILABLE:
            return base64.b64encode(str(vector).encode()).decode()

        encrypted_vector = ts.ckks_vector(self.context, vector)
        return base64.b64encode(encrypted_vector.serialize()).decode()

    def decrypt_vector(self, b64_ciphertext: str) -> List[float]:
        """Decrypts a base64 encoded ciphertext back to a plaintext vector."""
        if not TENSEAL_AVAILABLE:
            return eval(base64.b64decode(b64_ciphertext).decode())

        ciphertext_bytes = base64.b64decode(b64_ciphertext)
        encrypted_vector = ts.ckks_vector_from(self.context, ciphertext_bytes)
        return encrypted_vector.decrypt()

    def evaluate_risk_model(self, b64_encrypted_features: str, model_weights: List[float]) -> str:
        """
        Evaluates a linear risk model (dot product) securely on encrypted data.
        Returns the encrypted result.
        """
        if not TENSEAL_AVAILABLE:
            features = self.decrypt_vector(b64_encrypted_features)
            result = sum(f * w for f, w in zip(features, model_weights))
            return self.encrypt_vector([result])

        ciphertext_bytes = base64.b64decode(b64_encrypted_features)
        encrypted_features = ts.ckks_vector_from(self.context, ciphertext_bytes)
        
        # Homomorphic dot product
        encrypted_result = encrypted_features.dot(model_weights)
        
        return base64.b64encode(encrypted_result.serialize()).decode()

# Global instance for the service
he_engine = HEEngine()
