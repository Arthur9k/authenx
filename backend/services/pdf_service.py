# backend/services/pdf_service.py

import pypdfium2 as pdfium
import cv2
import numpy as np
import os

def pdf_to_image(file_path: str):
    """
    Converts the first page of a PDF or loads an image file into an OpenCV image object.
    This version uses a try...finally block to ensure the PDF file is always closed.
    """
    file_extension = os.path.splitext(file_path)[1].lower()

    if file_extension == '.pdf':
        pdf = None  # Initialize pdf to None
        try:
            # Open the PDF document
            pdf = pdfium.PdfDocument(file_path)
            page_count = len(pdf)
            
            # Render the first page
            page = pdf.get_page(0) 
            pil_image = page.render(scale=2).to_pil()
            
            # Convert to OpenCV format - THIS LINE IS NOW CORRECTED
            image = cv2.cvtColor(np.array(pil_image), cv2.COLOR_RGB2BGR)
            return image, page_count
        
        except Exception as e:
            print(f"Error processing file {file_path}: {e}")
            return None, 0
        
        finally:
            # This 'finally' block ALWAYS runs, ensuring the file is closed.
            if pdf:
                pdf.close()

    elif file_extension in ['.png', '.jpg', '.jpeg']:
        try:
            image = cv2.imread(file_path)
            if image is None:
                raise ValueError("Could not read the image file. It may be corrupted.")
            return image, 1
        except Exception as e:
            print(f"Error processing file {file_path}: {e}")
            return None, 0
    
    else:
        # Unsupported file type
        return None, 0