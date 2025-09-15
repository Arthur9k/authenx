# seed.py
# Script to seed the database with comprehensive demo data.

from datetime import date
from flask.cli import with_appcontext
import click
from hashlib import sha256
import os

from backend.sample_generator import generate_seed_files
from backend.models import db, Role, User, Institution, Certificate, VerificationLog, MockCertificate, CertificateStatus, VerificationResult
from backend.services import hash_service, qr_service

def sha256_of_file(file_path):
    h = sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def seed_roles():
    roles = [
        {'name': 'Admin', 'description': 'Full administrative access to the system.'},
        {'name': 'Verifier', 'description': 'Can verify certificates (e.g., an employer).'},
        {'name': 'Institution', 'description': 'Can manage their own institution\'s certificates.'}
    ]
    for role_data in roles:
        if not Role.query.filter_by(name=role_data['name']).first():
            role = Role(**role_data)
            db.session.add(role)
    db.session.commit()
    print("✅ Roles seeded.")

# def seed_users():
#     admin_role = Role.query.filter_by(name='Admin').first()
#     verifier_role = Role.query.filter_by(name='Verifier').first()
#     institution_role = Role.query.filter_by(name='Institution').first()
#     users = [
#         {'username': 'admin', 'email': 'admin@fakecert.com', 'password': 'admin_password', 'roles': [admin_role]},
#         {'username': 'employer_inc', 'email': 'hr@employer.com', 'password': 'verifier_password', 'roles': [verifier_role]},
#         {'username': 'bit_mesra', 'email': 'registrar@bitmesra.ac.in', 'password': 'institution_password', 'roles': [institution_role]}
#     ]
#     for user_data in users:
#         if not User.query.filter_by(username=user_data['username']).first():
#             user = User(username=user_data['username'], email=user_data['email'], roles=user_data['roles'])
#             user.set_password(user_data['password'])
#             db.session.add(user)
#     db.session.commit()
#     print("✅ Users seeded.")

# def seed_institutions():
#     institution_admin = User.query.filter_by(username='bit_mesra').first()
#     institutions = [
#         {'name': 'Birla Institute of Technology, Mesra', 'admin_user_id': institution_admin.id},
#         {'name': 'Indian Institute of Technology, Dhanbad'},
#         {'name': 'National Institute of Technology, Jamshedpur'}
#     ]
#     for inst_data in institutions:
#         if not Institution.query.filter_by(name=inst_data['name']).first():
#             institution = Institution(**inst_data)
#             db.session.add(institution)
#     db.session.commit()
#     print("✅ Institutions seeded.")

# def seed_certificates():
#     bit_mesra = Institution.query.filter_by(name='Birla Institute of Technology, Mesra').first()
#     good_cert_hash = sha256_of_file('backend/sample_pdfs/good_cert.pdf')
#     revoked_cert_hash = sha256_of_file('backend/sample_pdfs/revoked_cert.pdf')
#     cert1_data = {
#         'institution_id': bit_mesra.id, 'cert_id': 'BITM/2025/001', 'name': 'Priya Sharma',
#         'roll': 'BTECH/10051/21', 'course': 'Computer Science Engineering', 'marks': '9.2 CGPA',
#         'issued_date': date(2025, 5, 20), 'file_hash': good_cert_hash, 'status': CertificateStatus.VALID,
#         'certificate_metadata': {'ocr_confidence': 0.98, 'verified_by': 'Registrar Office'}
#     }
#     cert1_data['data_hash'] = hash_service.sha256_of_data({"cert_id": cert1_data["cert_id"], "name": cert1_data["name"], "roll": cert1_data["roll"], "marks": cert1_data["marks"]})
#     cert2_data = {
#         'institution_id': bit_mesra.id, 'cert_id': 'BITM/2025/002', 'name': 'Amit Singh',
#         'roll': 'BTECH/10052/21', 'course': 'Mechanical Engineering', 'marks': '8.5 CGPA',
#         'issued_date': date(2025, 5, 20), 'file_hash': None, 'status': CertificateStatus.VALID,
#         'blockchain_tx_hash': '0xabcde12345fghij67890klmno12345pqrst67890uvwxy12345z123456789'
#     }
#     cert2_data['data_hash'] = hash_service.sha256_of_data({"cert_id": cert2_data["cert_id"], "name": cert2_data["name"], "roll": cert2_data["roll"], "marks": cert2_data["marks"]})
#     cert3_data = {
#         'institution_id': bit_mesra.id, 'cert_id': 'BITM/2024/078', 'name': 'Sunita Williams',
#         'roll': 'IMSC/40012/19', 'course': 'Physics', 'marks': '8.8 CGPA',
#         'issued_date': date(2024, 6, 15), 'file_hash': revoked_cert_hash, 'status': CertificateStatus.REVOKED,
#         'certificate_metadata': {'revocation_reason': 'Academic Misconduct'}
#     }
#     cert3_data['data_hash'] = hash_service.sha256_of_data({"cert_id": cert3_data["cert_id"], "name": cert3_data["name"], "roll": cert3_data["roll"], "marks": cert3_data["marks"]})
#     certificates = [cert1_data, cert2_data, cert3_data]
#     for cert_data in certificates:
#         if not Certificate.query.filter_by(cert_id=cert_data['cert_id']).first():
#             cert = Certificate(**cert_data)
#             db.session.add(cert)
#     db.session.commit()
#     print("✅ Certificates seeded.")

# def seed_logs():
#     """Seeds the VerificationLog table with sample log entries."""
#     cert1 = Certificate.query.filter_by(cert_id='BITM/2025/001').first()
#     cert3 = Certificate.query.filter_by(cert_id='BITM/2024/078').first()
#     verifier = User.query.filter_by(username='employer_inc').first()

#     # CHANGE: Use the new, correct enum names from models.py
#     logs = [
#         {
#             'certificate_id': cert1.id, 'user_id': verifier.id, 'result': VerificationResult.VERIFIED_VIA_REGISTRY,
#             'reasons': 'All fields matched with database record.', 'verifier_ip_address': '202.54.10.2'
#         },
#         {
#             'certificate_id': cert3.id, 'user_id': verifier.id, 'result': VerificationResult.LIKELY_FORGED,
#             'reasons': 'Certificate has been marked as REVOKED by the issuing institution.', 'verifier_ip_address': '202.54.10.2'
#         },
#         {
#             'certificate_id': None, 'user_id': verifier.id, 'result': VerificationResult.NOT_FOUND_IN_REGISTRY,
#             'reasons': 'Certificate ID XYZ/999/999 not found in database.', 'verifier_ip_address': '115.98.45.1'
#         }
#     ]
#     for log_data in logs:
#         log = VerificationLog(**log_data)
#         db.session.add(log)
#     db.session.commit()
#     print("✅ Verification Logs seeded.")

# def seed_mock_digilocker():
#     good_cert_hash = sha256_of_file('backend/sample_pdfs/good_cert.pdf')
#     if not MockCertificate.query.filter_by(cert_id='BITM/2025/001').first():
#         mock_cert = MockCertificate(institution='Birla Institute of Technology, Mesra', cert_id='BITM/2025/001', name='Priya Sharma', roll='BTECH/10051/21', file_hash=good_cert_hash)
#         db.session.add(mock_cert)
#         db.session.commit()
#     print("✅ Mock DigiLocker seeded.")

@click.command('seed-db')
@with_appcontext
def seed_command():
    """Main command to seed the entire database and generate assets."""
    print("Generating base PDF files for seeding...")
    generate_seed_files()
    print("Base PDF files generated.")
    print("Starting database seeding process...")
    db.drop_all()
    db.create_all()
    print("Database tables dropped and recreated.")
    
    seed_roles()
    # seed_users()
    # seed_institutions()
    # seed_certificates()
    # seed_logs()
    # seed_mock_digilocker()
    
    good_cert = Certificate.query.filter_by(cert_id='BITM/2025/001').first()
    if good_cert:
        print("Generating QR code for valid certificate...")
        qr_service.generate_verification_qr(
            cert_id=good_cert.cert_id,
            data_hash=good_cert.data_hash,
            output_dir="backend/static/qr"
        )

    print("🎉 Database seeding and asset generation completed successfully! 🎉")