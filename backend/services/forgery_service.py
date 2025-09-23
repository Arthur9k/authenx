# backend/services/forgery_service.py

import cv2
import numpy as np
import os
from PIL import Image, ImageChops, ImageEnhance
import io
import pandas as pd
from collections import Counter
import pytesseract

# --- Configuration for Trust Score ---
# Thresholds
HIGH_CONFIDENCE_THRESHOLD = 85  # Score above this is considered high confidence (but needs manual check)
FORGERY_THRESHOLD = 50          # Score below this is considered likely forged

# Weights for different checks
WEIGHTS = {
    'LOGO': 25,
    'SIGNATURE': 20,
    'FONT_CONSISTENCY': 30,
    'PIXEL_INCONSISTENCY': 15,
    'TEXT_CONSISTENCY': 5,
    'STRUCTURAL_INTEGRITY': 5
}

# --- Forgery Detection Functions ---
def check_font_consistency(image):
    """
    Analyzes font consistency using a more robust "block-by-block" method.
    It assesses the consistency of each text block independently and averages the scores.
    """
    try:
        # 1. Get the detailed data and prepare it
        rgb_image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        data = pytesseract.image_to_data(rgb_image, output_type=pytesseract.Output.DATAFRAME)

        data['conf'] = pd.to_numeric(data['conf'], errors='coerce').fillna(-1)
        data = data[data.conf > 30]

        if len(data) < 10: return 1.0

        for col in ['height', 'top', 'line_num', 'block_num']:
            data[col] = pd.to_numeric(data[col], errors='coerce')
        data.dropna(subset=['height', 'top', 'line_num', 'block_num'], inplace=True)

        block_scores = []
        
        # 2. Loop through each text BLOCK on the page
        for block_num in data['block_num'].unique():
            block_data = data[data['block_num'] == block_num]
            
            # Skip small, irrelevant blocks
            if len(block_data) < 5: continue

            # --- 3. Run consistency checks WITHIN this block ---
            
            # Height consistency for the block
            height_counts = Counter(block_data['height'])
            if not height_counts: continue
            most_common_height = height_counts.most_common(1)[0][0]
            height_outliers = block_data[~block_data['height'].between(most_common_height - 1, most_common_height + 1)]
            height_outlier_percentage = len(height_outliers) / len(block_data)

            # Alignment consistency for the block
            alignment_outliers = 0
            for line_num in block_data['line_num'].unique():
                line_data = block_data[block_data['line_num'] == line_num]
                if len(line_data) < 2: continue
                top_counts = Counter(line_data['top'])
                if not top_counts: continue
                most_common_top = top_counts.most_common(1)[0][0]
                misaligned_words = line_data[~line_data['top'].between(most_common_top - 2, most_common_top + 2)]
                alignment_outliers += len(misaligned_words)
            
            alignment_outlier_percentage = alignment_outliers / len(block_data)

            # Calculate a score for this block
            total_error_percentage = (height_outlier_percentage * 1.5) + alignment_outlier_percentage
            block_score = max(0.0, 1.0 - total_error_percentage)
            block_scores.append(block_score)

        # 4. Calculate the final score as an average of all block scores
        if not block_scores:
            return 1.0  # Return a safe score if no valid blocks were found

        final_score = sum(block_scores) / len(block_scores)
        return final_score

    except Exception as e:
        logger.exception("Font consistency check failed.")
        return 1.0
def check_logo_tampering(image, structured_data):
    """
    Detects a logo using ORB feature matching, which is robust to scale
    and rotation changes. Returns a score based on the quality of the match.
    """
    university_name = structured_data.get('university')
    if not university_name:
        return 0.5 # Neutral score if university name is not found

    template_path = f'backend/templates/logos/{university_name}.png'
    if not os.path.exists(template_path):
        return 0.5 # Neutral score if we don't have a logo template for this uni

    try:
        template = cv2.imread(template_path, 0)
        if template is None: return 0.0

        gray_image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

        # 1. Initialize the ORB detector
        orb = cv2.ORB_create(nfeatures=1000)

        # 2. Find key "clues" (keypoints & descriptors) in both the template and the document
        kp1, des1 = orb.detectAndCompute(template, None)
        kp2, des2 = orb.detectAndCompute(gray_image, None)

        if des1 is None or des2 is None or len(des1) < 2 or len(des2) < 2:
            return 0.0 # Not enough features to compare

        # 3. Match the clues between the two images
        bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
        matches = bf.match(des1, des2)

        # 4. Sort the matches by how good they are
        matches = sorted(matches, key=lambda x: x.distance)

        # 5. Consider a "good" match to be at least 15 solid feature matches.
        # This number can be tuned.
        good_matches = len(matches)
        
        # 6. Calculate a score. We'll say 30 matches is an excellent score (1.0).
        # This creates a score that scales with the quality of the match.
        score = min(good_matches / 30.0, 1.0)

        return score

    except Exception as e:
        print(f"Error during feature matching: {e}")
        return 0.0 # Return a failing score if any error occurs

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
        "master of", "doctor of", "statement of marks", "academic transcript",

        "semester examination", "session", "grade awarded", "sgpa",
        "roll no", "name of student", "issued on", "authorized signatory",
        "seal of the institution", "board of education", "university",  "college"

    ]
    
    return any(phrase in text_lower for phrase in common_phrases)

def check_structural_integrity(page_count: int) -> bool:
    """
    Checks if the document structure is plausible. Most certificates are single pages.
    
    Returns:
        bool: True if the structure is plausible (1 page), False otherwise.
    """
    return page_count == 1

def check_pixel_inconsistency_ela(image):
    """
    Performs Error Level Analysis (ELA) to find parts of the image
    with different compression levels, which can indicate forgery.
    Returns a score from 0 (very inconsistent) to 1 (very consistent).
    """
    # 1. Re-save the image in memory to get a baseline compression
    temp_buffer = io.BytesIO()
    # Convert numpy array (OpenCV) to PIL Image
    pil_image = Image.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))
    pil_image.convert('RGB').save(temp_buffer, 'JPEG', quality=95)
    # ADD THIS LINE to "rewind the tape" before reading
    temp_buffer.seek(0)
    # 2. Load the re-saved image
    resaved_image = Image.open(temp_buffer)
    
    # 3. Find the difference between the original and the re-saved version
    ela_image = ImageChops.difference(pil_image, resaved_image)
    
    # 4. Enhance the difference to make it visible
    # In a real image, the difference is almost black. In a forged one, it's brighter.
    extrema = ela_image.getextrema()
    max_diff = max([ex[1] for ex in extrema])
    
    # 5. Calculate a score. If the max difference is very low, it's a good sign.
    # A low max_diff (e.g., < 20) means the image is uniform. A high one is suspicious.
    score = 1 - (max_diff / 255) # Normalize to 0-1 range
    
    # We return a less harsh score to avoid penalizing noisy scans too much
    return max(0, score) ** 2

# In calculate_trust_score()
def calculate_trust_score(image, ocr_text, page_count, structured_data):
    """
    Calculates a normalized, weighted trust score based on multiple forgery checks.
    """
    reasons = []
    total_penalty = 0.0

    # 1. Logo Tampering Check
    logo_score = check_logo_tampering(image, structured_data)
    if logo_score < 0.7:
        penalty = WEIGHTS['LOGO'] * (1 - logo_score)
        total_penalty += penalty
        reasons.append(f"-{penalty:.0f} pts: Logo mismatch detected (Score: {logo_score:.2f}).")

    # 2. Signature Presence Check
    if not check_signature_presence(image):
        total_penalty += WEIGHTS['SIGNATURE']
        reasons.append(f"-{WEIGHTS['SIGNATURE']} pts: No clear signature was detected.")

    # 3. Font Consistency Check
    font_score = check_font_consistency(image)
    if font_score < 0.8:
        penalty = WEIGHTS['FONT_CONSISTENCY'] * (1 - font_score)
        total_penalty += penalty
        reasons.append(f"-{penalty:.0f} pts: Font or alignment inconsistencies found (Score: {font_score:.2f}).")

    # 4. Pixel Inconsistency Check (ELA)
    pixel_score = check_pixel_inconsistency_ela(image)
    if pixel_score < 0.75:
        penalty = WEIGHTS['PIXEL_INCONSISTENCY'] * (1 - pixel_score)
        total_penalty += penalty
        reasons.append(f"-{penalty:.0f} pts: Potential pixel inconsistency detected (ELA Score: {pixel_score:.2f}).")

    # 5. Text Consistency Check
    if not check_text_consistency_heuristics(ocr_text):
        total_penalty += WEIGHTS['TEXT_CONSISTENCY']
        reasons.append(f"-{WEIGHTS['TEXT_CONSISTENCY']} pts: Document lacks common phrasing.")

    # 6. Structural Integrity Check
    if not check_structural_integrity(page_count):
        total_penalty += WEIGHTS['STRUCTURAL_INTEGRITY']
        reasons.append(f"-{WEIGHTS['STRUCTURAL_INTEGRITY']} pts: Unusual page count.")

    # Final score is 100 minus the sum of all calculated penalties
    final_score = int(100 - total_penalty)
    return max(0, final_score), "\n".join(reasons)