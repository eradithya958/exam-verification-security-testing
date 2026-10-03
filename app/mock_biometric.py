import hashlib
import time
from typing import Tuple

def verify_student_biometrics(student_id: str, biometric_data: str) -> Tuple[bool, float, str]:
    """
    Simulates a biometric verification service (facial recognition / ID match).
    Returns:
        (is_verified: bool, confidence_score: float, biometric_reference: str)
    """
    if not biometric_data or len(biometric_data) < 5:
        return False, 0.25, "INVALID_BIOMETRIC_DATA"
    
    # Deterministic or mock scoring
    hash_digest = hashlib.sha256(f"{student_id}:{biometric_data}".encode()).hexdigest()
    # Compute mock confidence from hash
    confidence = 0.70 + (int(hash_digest[:4], 16) % 30) / 100.0
    
    # Specific test string for simulated rejection
    if "spoofed_biometric" in biometric_data.lower() or "reject" in biometric_data.lower():
        return False, 0.35, f"BIO_FAIL_{hash_digest[:8]}"
        
    is_verified = confidence >= 0.75
    return is_verified, round(confidence, 3), f"BIO_REF_{hash_digest[:12]}"
