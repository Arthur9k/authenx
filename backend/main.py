# main.py

import cv2
import services.ocr_service as ocr_service
import services.document_classifier as document_classifier
from pprint import pprint

def process_document(image_path: str):
    """
    Main function to process an uploaded document. It follows a two-step approach:
    1. Classify the document using a quick OCR scan.
    2. If valid, perform a full OCR scan and extract structured data.
    """
    print(f"Processing document: {image_path}")
    
    # Read the image using OpenCV
    # Using cv2.imdecode to handle potential path issues with non-ASCII characters
    with open(image_path, "rb") as f:
        image_bytes = f.read()
    image = cv2.imdecode(cv2.np.frombuffer(image_bytes, cv2.np.uint8), cv2.IMREAD_COLOR)

    if image is None:
        print("Error: Could not read the image file.")
        return

    # --- STEP 1: Get raw text for classification ---
    print("Step 1: Performing quick scan for classification...")
    classification_text = ocr_service.get_text_for_classification(image)

    # --- STEP 2: Classify the document ---
    print("Step 2: Classifying document...")
    if document_classifier.is_certificate(classification_text):
        print("✅ Success: Document identified as an academic certificate or marksheet.")
        
        # --- STEP 3: If classification is successful, extract structured data ---
        print("\nStep 3: Performing deep scan and extracting structured data...")
        structured_data = ocr_service.extract_structured_data(image)
        
        print("\n--- Extracted Data ---")
        pprint(structured_data)
        print("----------------------")
        
    else:
        print("\n❌ Error: Unsupported Document Type")
        print("Score Analysis:")
        print("Document could not be identified as an academic certificate or marksheet.")

if __name__ == '__main__':
    # Replace 'New.jpg' with the path to your document image
    document_path = 'New.jpg' 
    process_document(document_path)