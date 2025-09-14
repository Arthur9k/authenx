from services.hash_service import sha256_of_file
from services.qr_service import generate_qr

# Step 1: generate hash of a file
h = sha256_of_file("sample_pdfs/good_cert.pdf")
print("hash:", h)

# Step 2: generate QR code image using hash
generate_qr(h, "static/qr/good_cert_qr.png")
print("✅ QR saved at static/qr/good_cert_qr.png")
