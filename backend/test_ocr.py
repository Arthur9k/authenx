# test_ocr.py
# A unittest-based test suite for services.pdf_service and services.ocr_service.
# - Ensures required test PDFs are generated before running.
# - Runs multiple test cases with known, expected outcomes.
# - Asserts that the extracted fields match the expected values.
# - Provides clear pass/fail results.

import os
import unittest
# IMPROVEMENT: Use the generator to ensure test files are always available.
from sample_generator import generate_seed_files
from services import pdf_service, ocr_service

# --- Test Configuration ---
# IMPROVEMENT: Define structured test cases with file paths and expected results.
# This makes it easy to add more tests in the future.
TEST_CASES = [
    {
        "file_path": os.path.join("backend/sample_pdfs", "good_cert.pdf"),
        "description": "Test with a standard, valid certificate PDF.",
        "expected_fields": {
            "name": "Priya Sharma",
            "cert_id": "BITM/2025/001",
            "roll": "BTECH/10051/21",
            "course": "Computer Science Engineering",
            "marks": "9.2 CGPA"
        }
    },
    {
        "file_path": os.path.join("backend/sample_pdfs", "revoked_cert.pdf"),
        "description": "Test with another valid certificate layout.",
        "expected_fields": {
            "name": "Sunita Williams",
            "cert_id": "BITM/2024/078",
            "roll": "IMSC/40012/19",
            "course": "Physics",
            "marks": "8.8 CGPA"
        }
    }
]

# --- Unittest Test Suite ---
# IMPROVEMENT: Refactored the script into a unittest.TestCase for structured testing.
class TestOcrService(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        A class method that runs once before all tests.
        It ensures that the PDF files needed for testing are generated.
        """
        print("--- Setting up OCR Test Suite ---")
        print("Generating required sample PDFs...")
        generate_seed_files()
        print("Setup complete.\n")

    def test_extract_and_parse_fields_from_pdfs(self):
        """
        The main test method. It iterates through TEST_CASES and verifies OCR results.
        """
        for case in TEST_CASES:
            file_path = case["file_path"]
            expected_fields = case["expected_fields"]
            
            # IMPROVEMENT: Use subtests to run each file as an independent test.
            # If one file fails, the others will still run and be reported.
            with self.subTest(msg=f"Processing file: {os.path.basename(file_path)}"):
                print(f"\n--- Testing: {os.path.basename(file_path)} ---")
                
                # 1. Check if the file exists
                self.assertTrue(os.path.exists(file_path), f"PDF file not found at {file_path}")

                # 2. Extract raw text using the service logic (text extraction with OCR fallback)
                raw_text = pdf_service.extract_text_from_pdf(file_path, save_fallback_image=True)
                
                if not raw_text:
                    print("No text layer found. Attempting OCR fallback...")
                    base, _ = os.path.splitext(file_path)
                    fallback_image = f"{base}_page1.png"
                    self.assertTrue(os.path.exists(fallback_image), "Fallback image was not created by pdf_service")
                    raw_text = ocr_service.ocr_image_to_text(fallback_image)
                    print("Raw text from OCR:\n", raw_text)
                else:
                    print("Raw text from PDF layer:\n", raw_text)

                self.assertIsNotNone(raw_text, "Raw text extraction failed completely.")
                self.assertGreater(len(raw_text), 0, "Extracted raw text is empty.")

                # 3. Parse fields from the extracted text
                extracted_fields = ocr_service.extract_fields_from_text(raw_text)
                print("\nParsed Fields:")
                for k, v in extracted_fields.items():
                    print(f"  - {k}: {v}")
                
                # 4. Assert that the extracted fields contain the expected values
                # IMPROVEMENT: Using `assertIn` is more robust for OCR testing than `assertEqual`,
                # as it accounts for minor extra characters or whitespace.
                print("\nVerifying fields...")
                for key, expected_value in expected_fields.items():
                    self.assertIn(key, extracted_fields, f"Expected field '{key}' was not found in parsed output.")
                    extracted_value = extracted_fields[key]
                    self.assertIn(
                        expected_value, 
                        extracted_value, 
                        f"Field '{key}' mismatch. Expected to find '{expected_value}' but got '{extracted_value}'"
                    )
                    print(f"  ✅ Verified: {key}")

if __name__ == "__main__":
    """
    This allows the test to be run from the command line with `python backend/test_ocr.py`.
    """
    print("=============================================")
    print("= Running FakeCert OCR Service Test Suite =")
    print("=============================================\n")
    unittest.main(verbosity=2)