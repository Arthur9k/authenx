# debug_model.py
import sys
from backend.app import create_app
from backend.models import MockCertificate

print("--- Starting Final Diagnostic Test ---")

# Add the project's root directory to the Python path to ensure imports work
# This is not always needed but is a good practice for scripts.
sys.path.insert(0, '.')

# Create a Flask app instance to get the database context
app = create_app()

with app.app_context():
    print("Successfully connected to the application context.")
    
    # The certificate ID we are testing
    test_cert_id = "2408292039"
    print(f"Attempting to find MockCertificate with cert_id: '{test_cert_id}'")

    # Query the database directly
    cert_from_db = MockCertificate.query.filter_by(cert_id=test_cert_id).first()

    if not cert_from_db:
        print("\n" + "="*40)
        print(">>> DIAGNOSIS: The certificate was NOT found in the database.")
        print(">>> REASON: This means 'add_test_data.py' or 'seed-db' is failing to save the record.")
        print("="*40 + "\n")
    else:
        print("SUCCESS: Found the certificate object in the database.")
        print(f"  -> Stored File Hash: '{cert_from_db.file_hash}'")
        
        print("\nNow, testing the to_dict() method on this object...")
        
        try:
            # Call the to_dict() method from your models.py
            data_dict = cert_from_db.to_dict()
            
            print("\n" + "="*40)
            print(">>> DIAGNOSIS: The to_dict() method executed.")
            print(">>> Dictionary content:", data_dict)
            
            # Final, definitive check
            if 'file_hash' in data_dict and data_dict['file_hash'] is not None:
                print("\nCONCLUSION: ✅ The `file_hash` key IS PRESENT and has a value.")
                print("This proves the `models.py` code is correct AND the data is saved correctly.")
            else:
                print("\nCONCLUSION: ❗ CRITICAL ERROR: The `file_hash` key is MISSING or its value is NULL.")
                print("This proves the `models.py` code being run by the server is an old version, or the hash is not being saved.")

        except Exception as e:
            print(f"\n" + "="*40)
            print(f">>> DIAGNOSIS: CRITICAL ERROR calling to_dict(): {e}")
            print(">>> REASON: This means there is a syntax error in your models.py file.")
            
print("--- Test Complete ---")