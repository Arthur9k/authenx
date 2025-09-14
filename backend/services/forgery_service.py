# backend/services/forgery_service.py

import cv2
import numpy as np
import os

# --- Configuration for Trust Score ---
# Thresholds
HIGH_CONFIDENCE_THRESHOLD = 85  # Score above this is considered high confidence (but needs manual check)
FORGERY_THRESHOLD = 50          # Score below this is considered likely forged

# Weights for different checks
LOGO_WEIGHT = 35
SIGNATURE_WEIGHT = 30
TEXT_CONSISTENCY_WEIGHT = 20 # Renamed from TEXT_WEIGHT
STRUCTURAL_INTEGRITY_WEIGHT = 15

# --- Forgery Detection Functions ---

def check_logo_tampering(image, template_path='backend/templates/logo_template.png'):
    """
    Checks for the presence and integrity of an institution's logo using template matching.
    
    Returns:
        bool: True if a high-quality logo match is found, False otherwise.
    """
    if not os.path.exists(template_path):
        # If no template is provided, we cannot perform this check.
        # We return True to not penalize the score.
        return True

    template = cv2.imread(template_path, 0)
    if template is None:
        return True 

    # Ensure the template is smaller than the image
    if template.shape[0] > image.shape[0] or template.shape[1] > image.shape[1]:
        return False # Template is bigger than the image, impossible to match.

    img_gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    
    res = cv2.matchTemplate(img_gray, template, cv2.TM_CCOEFF_NORMED)
    threshold = 0.8  # High threshold for a good match
    loc = np.where(res >= threshold)
    
    # If any location exceeds the threshold, we consider the logo present and untampered.
    return len(loc[0]) > 0

def check_signature_presence(image):
    """
    Detects signature-like contours. Looks for handwritten, complex shapes.
    
    Returns:
        bool: True if signature-like objects are found, False otherwise.
    """
    img_gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    
    # Adaptive thresholding can work well for finding ink on paper
    thresh = cv2.adaptiveThreshold(img_gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                                   cv2.THRESH_BINARY_INV, 11, 2)

    contours, _ = cv2.findContours(thresh, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
    
    min_contour_area = 1000  # Filter out small noise
    max_contour_area = 50000 # Filter out huge page elements
    
    for cnt in contours:
        area = cv2.contourArea(cnt)
        if min_contour_area < area < max_contour_area:
            # A simple heuristic: signatures are often wider than they are tall
            _, _, w, h = cv2.boundingRect(cnt)
            if w > h * 1.5:  # Check if aspect ratio is typical for a signature
                return True
    return False

def check_text_consistency_heuristics(text: str) -> bool:
    """
    A new, heuristic-based check. Looks for common phrases expected in academic documents.
    This replaces the old, flawed similarity check.

    Returns:
        bool: True if common certificate phrases are found, False otherwise.
    """
    text_lower = text.lower()
    
    # List of phrases that are very common on certificates.
    # Finding even one of these is a good sign.
    common_phrases = [
        "this is to certify that", "has been awarded the degree of",
        "in recognition of", "successful completion", "bachelor of",
        "master of", "doctor of", "statement of marks", "academic transcript"
    ]
    
    return any(phrase in text_lower for phrase in common_phrases)

def check_structural_integrity(page_count: int) -> bool:
    """
    Checks if the document structure is plausible. Most certificates are single pages.
    
    Returns:
        bool: True if the structure is plausible (1 page), False otherwise.
    """
    return page_count == 1

def calculate_trust_score(image, ocr_text, page_count):
    """
    Calculates a weighted trust score based on multiple forgery checks.
    
    Returns:
        tuple: (score, reasons_for_deduction)
    """
    score = 100
    reasons = []

    # 1. Logo Tampering Check
    if not check_logo_tampering(image):
        score -= LOGO_WEIGHT
        reasons.append(f"-{LOGO_WEIGHT} pts: Logo appears to be missing, inconsistent, or tampered with.")

    # 2. Signature Presence Check
    if not check_signature_presence(image):
        score -= SIGNATURE_WEIGHT
        reasons.append(f"-{SIGNATURE_WEIGHT} pts: No clear signature-like element was detected.")

    # 3. Text Consistency Heuristics Check (The corrected logic)
    if not check_text_consistency_heuristics(ocr_text):
        score -= TEXT_CONSISTENCY_WEIGHT
        reasons.append(f"-{TEXT_CONSISTENCY_WEIGHT} pts: Document lacks common phrasing found in academic certificates.")

    # 4. Structural Integrity Check
    if not check_structural_integrity(page_count):
        score -= STRUCTURAL_INTEGRITY_WEIGHT
        reasons.append(f"-{STRUCTURAL_INTEGRITY_WEIGHT} pts: Document has multiple pages, which is unusual for a certificate.")

    return max(0, score), "\n".join(reasons)