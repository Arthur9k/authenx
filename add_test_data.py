# add_test_data.py
import requests
import json
import time

API_URL = "http://127.0.0.1:5000/api/mock/digilocker/upload"
MOCK_API_KEY = "9eda06651ca2d856a419b809ba4f37c02f31a386fc7343f0" # Mock API key

# --- ADD ALL YOUR TEST CERTIFICATES HERE ---
certificates_to_add = [
    {
        "institution": "Khwaja Moinuddin Chishti Language University",
        "cert_id": "2408292039",
        "name": "MOHD ASIF",
        "roll": "2408292039",
        "file_hash": "8d41187b5c2b5528b9e0c73b01263217005932f80c136aafde797080d091eed8"
    },
    {
        "institution": "Central Board of Secondary Education",
        "cert_id": "23226443",
        "name": "MOHD NASAR",
        "roll": "23226443",
        "file_hash": "ef8ec5edf42315cc4dacc52c533b4d8c5c318fa98ea17aa3f5f8c9ae501a7181"
    },
    # To add another certificate, just copy the block above and paste it here
    # {
    #     "institution": "Another University",
    #     "cert_id": "99999999",
    #     "name": "JANE DOE",
    #     "roll": "99999999",
    #     "file_hash": "hash_for_jane"
    # }
]

headers = {
    "Content-Type": "application/json",
    "X-API-KEY": MOCK_API_KEY
}

# Loop through each certificate and send it to the API
for cert_data in certificates_to_add:
    print(f"Sending data for cert_id: {cert_data['cert_id']}...")
    try:
        response = requests.post(API_URL, headers=headers, data=json.dumps(cert_data))
        print(f"-> Server responded with Status Code: {response.status_code}")
        print("-> Response Body:", response.json())
        time.sleep(0.5) # Pause briefly between requests
    except requests.exceptions.ConnectionError:
        print("\n--- CONNECTION ERROR ---")
        print("Could not connect. Please make sure your Flask app is running.")
        break
    print("-" * 20)