## ⚡ Project Overview

> **Problem:** Academic certificate forgery is a growing concern, undermining trust in education, jobs, and governance.
> **Solution:** **Fake Certificate Detector** is an automated verification system that uses **OCR, PDF parsing, QR/Hash validation, and mock DigiLocker integration** to detect fake/forged certificates.
> Built for **SIH**, it ensures a **secure, scalable, and transparent verification workflow**.

---

## ✅ Features

* 📂 Upload & Verify Certificates (PDF scans)
* 🔍 OCR Extraction with **Tesseract**
* 🔒 QR / Hash Validation
* 📡 Mock DigiLocker Integration (future-ready for real API)
* 📊 Admin Dashboard for monitoring & blacklisting

---

## 📁 Folder Structure

```text
fakecert-sih/
├── backend/
│   ├── app.py              # Flask app entry
│   ├── config.py           # Configurations
│   ├── models.py           # Database models
│   ├── seed.py             # Seed DB with demo data
│   ├── sample_generator.py # Generate sample certs (good/tampered)
│   ├── test_ocr.py         # OCR test script
│   ├── routes/             # API routes (verify, auth, mock_digilocker)
│   ├── services/           # OCR, PDF, QR, Hash services
│   ├── templates/          # Jinja2 templates (index, admin)
│   ├── uploads/            # Uploaded files
│   └── static/qr/          # QR codes
│
├── frontend/
│   ├── index.html          # Upload/verification page
│   └── admin.html          # Admin dashboard
│
├── requirements.txt        # Dependencies
├── .env                    # Environment variables
└── README.md               # Project docs
```

---

## 🛠️ Tech Stack

* **Backend:** Python (Flask)
* **Database:** SQLite (default), PostgreSQL (optional)
* **Frontend:** HTML + TailwindCSS
* **OCR:** pytesseract
* **PDF Parsing:** PyPDF2
* **QR/Hash:** qrcode, pyzbar, hashlib
* **Integration:** Mock DigiLocker API

---

## 🚀 Installation

1. **Clone repo**

   ```bash
   git clone https://github.com/USERNAME/fakecert-sih.git
   cd fakecert-sih
   ```
2. **Create & activate venv**

   ```bash
   python -m venv venv
   source venv/bin/activate   # Mac/Linux
   venv\Scripts\activate      # Windows
   ```
3. **Install requirements**

   ```bash
   pip install -r requirements.txt
   ```
4. **Set environment vars**

   * Create `.env` file (DB URI, SECRET\_KEY, etc.).
5. **Seed demo database**

   ```bash
   python backend/seed.py
   ```
6. **Run server**

   ```bash
   python backend/app.py
   ```

---

## 🔎 Usage

* Open `frontend/index.html` → Upload a PDF certificate.
* System runs OCR + PDF parsing → validates via DB / hash / QR.
* Results:

  * ✅ **Valid Certificate**
  * ❌ **Tampered/Fake**
  * 🚫 **Not Found**
* Admins: Open `frontend/admin.html` → View flagged history & logs.

---

## 🎬 Demo Flow (SIH Judges)

1. Upload **good\_cert.pdf** → System: ✅ Verified.
2. Upload **tampered\_cert.pdf** → System: ❌ Flagged.
3. Show **Admin Dashboard** → history of verification attempts.
4. Explain **Mock DigiLocker** (demo now, real API later).

---

## 🌱 Future Enhancements

* 🔗 Blockchain-based certificate registry
* 🤖 AI forgery & image tampering detection
* 🏛️ Direct DigiLocker & University ERP APIs

---

## 🤝 Contributing

Contributions welcome!

* Fork → Branch → Commit → PR.

---

## 🔒 License

This project is licensed under the **MIT License**.
