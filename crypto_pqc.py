import logging
import base64
import os
import json

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DARIP-PQC")

# Attempt to load pyoqs (Python wrapper for liboqs)
try:
    import oqs
    HAS_PYOQS = True
    logger.info("Found native liboqs/pyoqs. Post-quantum cryptographic operations enabled.")
except ImportError:
    HAS_PYOQS = False
    logger.warning("native liboqs/pyoqs not found. Falling back to simulated post-quantum cryptographic primitives (Ed25519 & AES-GCM).")

# If HAS_PYOQS is False, we will use cryptography package for fallback
if not HAS_PYOQS:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class PQCSigner:
    """
    Dilithium-based Digital Signature class for authenticating message exchange and zero-trust tokens.
    Uses Dilithium3 (standard strength) or Dilithium5 (high strength).
    """
    def __init__(self, alg_name: str = "Dilithium3"):
        self.alg_name = alg_name
        self.public_key = None
        self._private_key = None
        
        if HAS_PYOQS:
            # Native liboqs Dilithium initialization
            # Verify the algorithm is supported by pyoqs
            if alg_name not in oqs.get_enabled_sig_mechanisms():
                fallback_alg = "Dilithium3" if "Dilithium3" in oqs.get_enabled_sig_mechanisms() else oqs.get_enabled_sig_mechanisms()[0]
                logger.warning(f"Signature mechanism {alg_name} not enabled. Falling back to {fallback_alg}")
                self.alg_name = fallback_alg
            self.signer = oqs.Signature(self.alg_name)
        else:
            # Fallback asymmetric cryptography (Ed25519)
            self.signer = None

    def generate_keypair(self):
        """Generates a keypair and returns (public_key_bytes, private_key_bytes)"""
        if HAS_PYOQS:
            public_key = self.signer.generate_keypair()
            self.public_key = public_key
            self._private_key = self.signer.export_secret_key()
            return public_key, self._private_key
        else:
            # Generate Ed25519 keypair
            self._private_key = ed25519.Ed25519PrivateKey.generate()
            self.public_key = self._private_key.public_key()
            pub_bytes = self.public_key.public_bytes_raw()
            priv_bytes = self._private_key.private_bytes_raw()
            return pub_bytes, priv_bytes

    def sign(self, message: bytes, private_key_bytes: bytes = None) -> bytes:
        """Signs a message using the private key"""
        if HAS_PYOQS:
            local_signer = self.signer
            if private_key_bytes:
                # In pyoqs, to use an external secret key, we must instantiate a new Signature object
                # or set the secret key. If using native, we recreate/load.
                local_signer = oqs.Signature(self.alg_name, secret_key=private_key_bytes)
            elif self._private_key:
                local_signer = oqs.Signature(self.alg_name, secret_key=self._private_key)
            else:
                raise ValueError("No secret key available to sign.")
            return local_signer.sign(message)
        else:
            if private_key_bytes:
                priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
            elif isinstance(self._private_key, ed25519.Ed25519PrivateKey):
                priv_key = self._private_key
            else:
                raise ValueError("No secret key available to sign.")
            return priv_key.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
        """Verifies a signature using the public key"""
        if HAS_PYOQS:
            verifier = oqs.Signature(self.alg_name)
            try:
                return verifier.verify(message, signature, public_key_bytes)
            except Exception as e:
                logger.error(f"PQC verification failed: {e}")
                return False
        else:
            try:
                pub_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
                pub_key.verify(signature, message)
                return True
            except Exception:
                return False


class PQCKeyEncapsulator:
    """
    Kyber-based Key Encapsulation Mechanism (KEM) for secure hybrid-quantum key exchange.
    Uses Kyber768 (equivalent to AES-192 security level).
    """
    def __init__(self, alg_name: str = "Kyber768"):
        self.alg_name = alg_name
        self.public_key = None
        self._private_key = None

        if HAS_PYOQS:
            if alg_name not in oqs.get_enabled_kem_mechanisms():
                fallback_alg = "Kyber768" if "Kyber768" in oqs.get_enabled_kem_mechanisms() else oqs.get_enabled_kem_mechanisms()[0]
                logger.warning(f"KEM mechanism {alg_name} not enabled. Falling back to {fallback_alg}")
                self.alg_name = fallback_alg
            self.kem = oqs.KeyEncapsulation(self.alg_name)
        else:
            self.kem = None

    def generate_keypair(self):
        """Generates a keypair and returns (public_key_bytes, private_key_bytes)"""
        if HAS_PYOQS:
            public_key = self.kem.generate_keypair()
            self.public_key = public_key
            self._private_key = self.kem.export_secret_key()
            return public_key, self._private_key
        else:
            # For fallback, simulate a KEM using static AES key wrapping or Ed25519/X25519
            # In simulation, we will generate a key pair
            # Let's generate a random 32-byte key
            self._private_key = os.urandom(32)
            self.public_key = b"SIMULATED_KYBER_PUBLIC_KEY:" + self._private_key
            return self.public_key, self._private_key

    def encapsulate(self, public_key_bytes: bytes) -> tuple[bytes, bytes]:
        """
        Encrypts a randomly generated symmetric key with the receiver's public key.
        Returns (ciphertext, shared_secret)
        """
        if HAS_PYOQS:
            kem = oqs.KeyEncapsulation(self.alg_name)
            ciphertext, shared_secret = kem.encap_secret(public_key_bytes)
            return ciphertext, shared_secret
        else:
            # Simulation: shared_secret is derived from the simulated public key
            if public_key_bytes.startswith(b"SIMULATED_KYBER_PUBLIC_KEY:"):
                extracted_priv = public_key_bytes[len(b"SIMULATED_KYBER_PUBLIC_KEY:"):]
                shared_secret = AESGCM.generate_key(bit_length=256)
                # Create a simple encrypted envelope containing the shared secret
                aesgcm = AESGCM(extracted_priv)
                nonce = os.urandom(12)
                ciphertext = nonce + aesgcm.encrypt(nonce, shared_secret, b"KYBER_AD")
                return ciphertext, shared_secret
            else:
                # If invalid public key, return random bytes
                return os.urandom(48), os.urandom(32)

    def decapsulate(self, ciphertext: bytes, private_key_bytes: bytes = None) -> bytes:
        """
        Decrypts the ciphertext with the receiver's private key to extract the shared symmetric key.
        Returns shared_secret
        """
        if HAS_PYOQS:
            local_priv = private_key_bytes if private_key_bytes else self._private_key
            kem = oqs.KeyEncapsulation(self.alg_name, secret_key=local_priv)
            shared_secret = kem.decap_secret(ciphertext)
            return shared_secret
        else:
            # Simulation decapsulation
            local_priv = private_key_bytes if private_key_bytes else self._private_key
            try:
                nonce = ciphertext[:12]
                encrypted_payload = ciphertext[12:]
                aesgcm = AESGCM(local_priv)
                shared_secret = aesgcm.decrypt(nonce, encrypted_payload, b"KYBER_AD")
                return shared_secret
            except Exception as e:
                logger.error(f"Simulated Kyber decapsulation failed: {e}")
                raise ValueError("Kyber decapsulation failed.")

# Helper utilities for JSON payload wrapping
def secure_json_encrypt(data: dict, shared_secret: bytes) -> str:
    """Encrypts data dict into a secure string using AES-GCM and the Kyber shared secret."""
    aesgcm = AESGCM(shared_secret)
    nonce = os.urandom(12)
    payload_bytes = json.dumps(data).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, payload_bytes, None)
    # Combine nonce + ciphertext and base64 encode
    return base64.b64encode(nonce + ciphertext).decode("utf-8")

def secure_json_decrypt(encrypted_str: str, shared_secret: bytes) -> dict:
    """Decrypts secure string back into a dictionary using AES-GCM and the Kyber shared secret."""
    payload_bytes = base64.b64decode(encrypted_str.encode("utf-8"))
    nonce = payload_bytes[:12]
    ciphertext = payload_bytes[12:]
    aesgcm = AESGCM(shared_secret)
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(decrypted_bytes.decode("utf-8"))
