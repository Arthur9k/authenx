# services/document_classifier.py

import re

# Expanded keywords with Hindi to correctly identify a wider range of academic documents
CERTIFICATE_KEYWORDS = [
    'certificate', 'diploma', 'degree', 'completion', 
    'marksheet', 'statement of marks', 'transcript', 'academic record',
    'provisional', 'credential',
    # Hindi Keywords from your sample and common usage
    'प्रमाण पत्र',  # Praman Patra (Certificate)
    'विवरणिका',   # Vivranika (Statement/Sheet)
    'बोर्ड',        # Board
    'माध्यमिक'    # Madhyamik (Secondary)
]

def is_certificate(text: str) -> bool:
    """
    Classifies if the document is a certificate based on keywords.
    This check is case-insensitive.
    """
    if not text or len(text) < 50: # Ignore very short or empty OCR results
        return False
        
    text_lower = text.lower()
    
    # Use regex to find whole words to avoid partial matches
    for keyword in CERTIFICATE_KEYWORDS:
        if re.search(r'\b' + re.escape(keyword) + r'\b', text_lower, re.IGNORECASE):
            return True
            
    return False