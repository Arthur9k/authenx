# sample_generator.py
# Script to generate sample PDF certificates using reportlab and Faker.

import os
import random
from datetime import datetime
from faker import Faker
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm

OUTPUT_DIR = "backend/sample_pdfs"
FAKE = Faker('en_IN')

INSTITUTIONS = [
    "Birla Institute of Technology, Mesra",
    "Indian Institute of Technology, Dhanbad",
    "National Institute of Technology, Jamshedpur"
]
COURSES = [
    "Computer Science Engineering", "Mechanical Engineering", "Civil Engineering",
    "Electrical Engineering", "Physics", "Chemistry", "Mathematics"
]

class CertificateGenerator:
    def __init__(self, output_dir=OUTPUT_DIR):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def _create_base_canvas(self, path: str, institution_name: str):
        width, height = A4
        c = canvas.Canvas(path, pagesize=A4)
        margin = 20 * mm
        c.setLineWidth(2)
        c.rect(margin, margin, width - 2 * margin, height - 2 * margin)
        
        c.setFont("Helvetica-Bold", 24)
        c.drawCentredString(width / 2, height - 50 * mm, "Certificate of Completion")
        c.setFont("Helvetica", 14)
        c.drawCentredString(width / 2, height - 60 * mm, f"Issued by: {institution_name}")
        return c

    def _draw_fields(self, c: canvas.Canvas, fields: dict):
        width, height = A4
        margin = 20 * mm
        start_x, start_y, line_gap = margin + 15 * mm, height - 85 * mm, 12 * mm

        field_map = {
            "Name": fields.get("name"), "Certificate ID": fields.get("cert_id"),
            "Roll No.": fields.get("roll"), "Course": fields.get("course"),
            "Marks/Grade": fields.get("marks")
        }

        y_pos = start_y
        for label, value in field_map.items():
            if value:
                c.setFont("Helvetica-Bold", 12)
                c.drawString(start_x, y_pos, f"{label}:")
                c.setFont("Helvetica", 12)
                c.drawString(start_x + 45 * mm, y_pos, str(value))
                y_pos -= line_gap

        footer_y = margin + 30 * mm
        c.setFont("Helvetica", 10)
        c.drawString(start_x, footer_y + 10, "This is a sample certificate generated for testing purposes.")
        c.line(width - margin - 60 * mm, footer_y, width - margin - 10 * mm, footer_y)
        c.drawString(width - margin - 60 * mm, footer_y - 15, "Authorized Signature")
        
        c.showPage()
        c.save()

    def create_certificate(self, path: str, fields: dict):
        institution = fields.get("institution", "Sample University")
        canvas_obj = self._create_base_canvas(path, institution)
        self._draw_fields(canvas_obj, fields)

    def generate_random_pair(self):
        genuine_fields = {
            "institution": random.choice(INSTITUTIONS),
            "name": FAKE.name(),
            "course": random.choice(COURSES),
            "cert_id": f"JH/{random.randint(2023, 2025)}/{random.randint(100, 999)}",
            "roll": f"BTECH/{random.randint(10000, 20000)}/{random.randint(21, 23)}",
            "marks": f"{random.randint(7, 9)}.{random.randint(0, 9)} CGPA"
        }
        tampered_fields = genuine_fields.copy()
        tamper_mode = random.choice(['marks', 'name', 'id'])
        
        if tamper_mode == 'marks':
            tampered_fields['marks'] = f"9.{random.randint(5, 9)} CGPA"
            tamper_desc = "marks_altered"
        elif tamper_mode == 'name':
            tampered_fields['name'] = FAKE.name()
            tamper_desc = "name_mismatch"
        else:
            tampered_fields['cert_id'] = f"JH/{random.randint(2023, 2025)}/FAKE{random.randint(10, 99)}"
            tamper_desc = "id_forged"

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        genuine_path = os.path.join(self.output_dir, f"genuine_{timestamp}.pdf")
        tampered_path = os.path.join(self.output_dir, f"tampered_{tamper_desc}_{timestamp}.pdf")
        
        print(f"Generating genuine file: {genuine_path}")
        self.create_certificate(genuine_path, genuine_fields)
        
        print(f"Generating tampered file: {tampered_path}")
        self.create_certificate(tampered_path, tampered_fields)

def generate_seed_files():
    """
    Generates the specific, static PDFs needed by `seed.py`.
    """
    generator = CertificateGenerator()
    print("Generating static PDFs required for database seeding...")
    
    # CHANGE: The data in this PDF now perfectly matches the data in seed.py
    good_fields = {
        "institution": "Birla Institute of Technology, Mesra",
        "name": "Priya Sharma",
        "cert_id": "BITM/2025/001",
        "roll": "BTECH/10051/21",
        "course": "Computer Science Engineering",
        "marks": "9.2 CGPA"
    }
    generator.create_certificate(os.path.join(OUTPUT_DIR, "good_cert.pdf"), good_fields)

    revoked_fields = {
        "institution": "Birla Institute of Technology, Mesra",
        "name": "Sunita Williams",
        "cert_id": "BITM/2024/078",
        "roll": "IMSC/40012/19",
        "course": "Physics",
        "marks": "8.8 CGPA"
    }
    generator.create_certificate(os.path.join(OUTPUT_DIR, "revoked_cert.pdf"), revoked_fields)

def main():
    """Main execution entry point when script is run directly."""
    print("--- Dynamic PDF Test Pair Generator ---")
    generator = CertificateGenerator()
    generator.generate_random_pair()
    print(f"\n✅ Done. New random PDF pair saved in '{OUTPUT_DIR}'")

if __name__ == "__main__":
    main()