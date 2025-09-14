import requests

url = "http://127.0.0.1:5000/verify/api/verify"

pdf_files = [
    r"sample_pdfs\good_cert.pdf",
    r"sample_pdfs\tampered_cert.pdf"
]

for pdf_path in pdf_files:
    print(f"\nTesting {pdf_path} ...")
    with open(pdf_path, "rb") as f:
        files = {"file": f}
        data = {"institution_id": "1"}  # optional
        response = requests.post(url, files=files, data=data)

    print("Status Code:", response.status_code)
    try:
        print("Response JSON:", response.json())
    except requests.JSONDecodeError:
        print("Response is not JSON. Text returned:")
        print(response.text)
