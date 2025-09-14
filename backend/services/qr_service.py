# services/qr_service.py
"""
A robust service for generating and reading QR codes for certificate verification.

Features:
- Generates QR codes that encode a public verification URL.
- Reads QR codes from images to extract embedded data.
"""
import os
from typing import Optional
from flask import current_app
import qrcode
from qrcode.image.pil import PilImage

# NEW: Import libraries for reading QR codes.
try:
    from pyzbar.pyzbar import decode
    from PIL import Image
    QR_READING_AVAILABLE = True
except ImportError:
    QR_READING_AVAILABLE = False

def generate_verification_qr(cert_id: str, data_hash: str, output_dir: str) -> Optional[str]:
    """
    Generates a QR code containing a public verification URL and saves it as an image.

    IMPROVEMENT: Encodes a user-friendly URL instead of just a raw hash.
    
    Args:
        cert_id: The unique identifier of the certificate.
        data_hash: The certificate's data fingerprint (from hash_service).
        output_dir: The directory where the QR code image will be saved.
        
    Returns:
        The full path to the saved QR code image, or None on failure.
    """
    try:
        base_url = current_app.config.get("BASE_VERIFICATION_URL", "http://127.0.0.1:5000")
        # Construct the verification URL with query parameters.
        verification_url = f"{base_url}/api/public-verify?cert_id={cert_id}&hash={data_hash}"
        
        # Ensure the output directory exists.
        os.makedirs(output_dir, exist_ok=True)
        
        # Define the output path for the QR code image.
        output_path = os.path.join(output_dir, f"QR_{cert_id.replace('/', '-')}.png")

        # Configure the QR code properties.
        qr = qrcode.QRCode(
            version=1, # Keep it simple
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(verification_url)
        qr.make(fit=True)

        img: PilImage = qr.make_image(fill_color="black", back_color="white")
        img.save(output_path)
        
        current_app.logger.info(f"Successfully generated QR code for '{cert_id}' at '{output_path}'")
        return output_path
    except Exception as e:
        current_app.logger.exception(f"Failed to generate QR code for cert_id '{cert_id}': {e}")
        return None

def read_qr_from_image(image_path: str) -> Optional[str]:
    """
    NEW FEATURE: Decodes a QR code from an image file.
    
    Args:
        image_path: The full path to the image containing a QR code.
        
    Returns:
        The decoded data (e.g., the verification URL) as a string, or None if
        no QR code is found or an error occurs.
    """
    if not QR_READING_AVAILABLE:
        current_app.logger.error("QR code reading is unavailable. Please install pyzbar and Pillow.")
        return None

    try:
        with Image.open(image_path) as img:
            decoded_objects = decode(img)
            if not decoded_objects:
                current_app.logger.warning(f"No QR code found in image '{image_path}'")
                return None
            
            # Return the data from the first QR code found.
            decoded_data = decoded_objects[0].data.decode("utf-8")
            current_app.logger.info(f"Successfully decoded QR code from '{image_path}'")
            return decoded_data
    except Exception as e:
        current_app.logger.exception(f"Failed to read QR code from image '{image_path}': {e}")
        return None