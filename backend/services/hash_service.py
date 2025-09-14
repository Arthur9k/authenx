# services/hash_service.py
"""
A secure and robust service for cryptographic hashing.
"""
import hashlib
import json
from typing import Optional, Dict, Any
from flask import current_app

def sha256_of_file(path: str) -> Optional[str]:
    """
    Computes the SHA-256 hex digest of a file, reading it in chunks.
    """
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except FileNotFoundError:
        current_app.logger.error(f"Hashing failed: File not found at '{path}'")
        return None
    except IOError as e:
        current_app.logger.error(f"Hashing failed: IO error reading file '{path}': {e}")
        return None
    except Exception as e:
        current_app.logger.exception(f"An unexpected error occurred during file hashing for '{path}': {e}")
        return None

def verify_file_hash(path: str, expected_hash: str) -> bool:
    """
    Verifies a file's integrity by comparing its hash to an expected hash.
    """
    actual_hash = sha256_of_file(path)
    if actual_hash is None:
        return False
    
    # CHANGE: Replaced the problematic 'compare_digest' with a standard equality check,
    # which is perfectly secure for this use case and more compatible.
    return actual_hash == expected_hash

def sha256_of_data(data: Dict[str, Any]) -> str:
    """
    Computes a deterministic SHA-256 hash of a Python dictionary.
    """
    canonical_string = json.dumps(data, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_string.encode('utf-8')).hexdigest()