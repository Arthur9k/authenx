import requests

# Base URL of your Flask app
BASE_URL = "http://127.0.0.1:5000/api/mock-digilocker"

# Sample certificate data
cert_data = {
    "institution": "ABC University",
    "cert_id": "CERT126753",
    "name": "Rahul Kumar",
    "roll": "12345",
    "file_hash": "abcd1234"
}

# 1️⃣ Upload certificate
print("Uploading certificate...")
upload_resp = requests.post(f"{BASE_URL}/upload", json=cert_data)
print("Upload Status:", upload_resp.status_code)
print("Upload Response:", upload_resp.json())

# 2️⃣ Verify certificate
print("\nVerifying certificate...")
verify_resp = requests.get(f"{BASE_URL}/verify", params={"cert_id": cert_data["cert_id"]})
print("Verify Status:", verify_resp.status_code)
print("Verify Response:", verify_resp.json())
