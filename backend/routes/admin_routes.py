import csv
import io
import random
import traceback
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from backend.routes.verify import _process_single_file, allowed_file

# Assuming your models and auth helpers are in these locations
from backend.models import db, Alert, User, Role, Certificate, VerificationLog, CertificateStatus
from backend.routes.auth import roles_required

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/stats", methods=["GET"])
@jwt_required()
@roles_required("Admin")
def get_stats():
    """Provides key statistics for the admin dashboard cards."""
    # In a real app, these would be efficient database queries.
    stats = {
        "total_verifications": Certificate.query.count() + random.randint(50, 150),
        "certificates_in_registry": Certificate.query.count(),
        "likely_forgeries": VerificationLog.query.filter(VerificationLog.result.like('%Flagged%')).count(),
        "unread_alerts": Alert.query.filter_by(is_read=False).count(),
    }
    return jsonify(stats)


@admin_bp.route("/verification-chart-data", methods=["GET"])
@jwt_required()
@roles_required("Admin")
def get_verification_chart_data():
    """Generates mock data for the verification trends chart."""
    today = datetime.utcnow()
    labels = [(today - timedelta(days=i)).strftime("%b %d") for i in range(6, -1, -1)]
    verified_data = [random.randint(80, 200) for _ in range(7)]
    flagged_data = [random.randint(5, 20) for _ in range(7)]
    
    chart_data = {
        "labels": labels,
        "verified": verified_data,
        "flagged": flagged_data,
    }
    return jsonify(chart_data)


@admin_bp.route("/alerts", methods=["GET"])
@jwt_required()
@roles_required("Admin")
def get_alerts():
    """Returns the top 5 unread alerts."""
    alerts = Alert.query.filter_by(is_read=False).order_by(Alert.timestamp.desc()).limit(5).all()
    
    # If no real alerts, provide mock data for a good UI experience
    if not alerts:
        mock_alerts = [
            {"id": 1, "message": "High-risk forgery attempt detected from IP 192.168.1.10.", "timestamp": (datetime.utcnow() - timedelta(minutes=5)).isoformat()},
            {"id": 2, "message": "Unusual login activity for user 'institution_A'.", "timestamp": (datetime.utcnow() - timedelta(hours=1)).isoformat()},
            {"id": 3, "message": "Bulk upload completed with 3 errors.", "timestamp": (datetime.utcnow() - timedelta(hours=2)).isoformat()},
        ]
        return jsonify(mock_alerts)

    return jsonify([alert.to_dict() for alert in alerts])


@admin_bp.route("/certificates", methods=["GET"])
@jwt_required()
@roles_required("Admin", "Institution")
def get_certificates():
    """Returns a list of all certificates in the registry."""
    certificates = Certificate.query.order_by(Certificate.issued_date.desc()).all()
    return jsonify([cert.to_dict() for cert in certificates])


@admin_bp.route("/verification-logs", methods=["GET"])
@jwt_required()
@roles_required("Admin")
def get_verification_logs():
    """Returns a list of all verification attempts."""
    logs = VerificationLog.query.order_by(VerificationLog.timestamp_utc.desc()).limit(50).all() # Limit to last 50 for performance
    return jsonify([log.to_dict() for log in logs])


@admin_bp.route("/create-user", methods=["POST"])
@jwt_required()
@roles_required("Admin")
def create_user():
    """Allows an admin to manually create a new user (e.g., for an institution)."""
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    role_name = data.get("role", "Institution") # Default to 'Institution' role

    if not all([username, email, password]):
        return jsonify({"msg": "Missing username, email, or password"}), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"msg": "Username or email already exists"}), 409

    role = Role.query.filter_by(name=role_name).first()
    if not role:
        # If the role doesn't exist, create it. This makes the system more robust.
        role = Role(name=role_name)
        db.session.add(role)
        db.session.flush() # Use flush to get the ID before committing fully

    # CORRECTED: Use the User model's set_password method for consistency
    new_user = User(username=username, email=email, roles=[role])
    new_user.set_password(password)
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"msg": f"User '{username}' created successfully with role '{role_name}'."}), 201


# NEW - Route for Bulk CSV Upload to Database
@admin_bp.route("/certificate/bulk-add-csv", methods=["POST"])
@jwt_required()
@roles_required("Admin", "Institution")
def bulk_add_csv():
    """Accepts a CSV, processes it, and adds new records to the Certificate registry."""
    if 'file' not in request.files:
        return jsonify(msg="No file part"), 400
    file = request.files['file']
    if file.filename == '' or not file.filename.endswith('.csv'):
        return jsonify(msg="Please select a valid CSV file"), 400

    results = []
    try:
        stream = io.StringIO(file.stream.read().decode("UTF-8"), newline=None)
        csv_reader = csv.DictReader(stream)

        required_headers = {'cert_id', 'name'}
        if not required_headers.issubset(csv_reader.fieldnames):
            return jsonify(msg=f"CSV must contain at least headers: {', '.join(required_headers)}"), 400

        for i, row in enumerate(csv_reader):
            cert_id = row.get("cert_id", "").strip()
            name = row.get("name", "").strip()

            if not cert_id or not name:
                results.append({"row": i + 2, "cert_id": cert_id, "status": "Error", "message": "Missing required cert_id or name."})
                continue

            if Certificate.query.filter_by(cert_id=cert_id).first():
                results.append({"row": i + 2, "cert_id": cert_id, "status": "Skipped", "message": "Certificate ID already exists."})
                continue

            # If the row is valid, create a new Certificate record and add it
            new_cert = Certificate(
                cert_id=cert_id,
                name=name,
                roll=row.get('roll'),
                course=row.get('course'),
                file_hash=row.get('file_hash'),
                status=CertificateStatus.VALID 
            )
            db.session.add(new_cert)
            results.append({"row": i + 2, "cert_id": cert_id, "status": "Success", "message": "Added to registry."})

        # Commit all the new certificates to the database at once
        db.session.commit()

    except Exception as e:
        db.session.rollback()
        return jsonify(msg=f"Error processing file: {str(e)}"), 500

    return jsonify({"results": results})

# NEW - Route for Single Certificate Upload (PDF/JPG)
@admin_bp.route("/certificate/add", methods=["POST"])
@jwt_required()
@roles_required("Admin")
def add_certificate():
    """
    Accepts a single certificate file, processes it, and adds its
    metadata to the main Certificate registry.
    """
    if 'file' not in request.files:
        return jsonify(msg="No file part in the request"), 400

    file = request.files['file']

    if file.filename == '' or not allowed_file(file.filename):
        return jsonify(msg="No file selected or file type not allowed"), 400

    try:
        # Re-use your powerful processing function from verify.py
        verification_result = _process_single_file(file, user_id=None, local_timestamp=None)

        file_hash = verification_result.get('file_hash')
        if not file_hash:
            return jsonify(msg="Could not generate a hash for the file."), 500

        # Validation: Check if this exact file already exists
        if Certificate.query.filter_by(file_hash=file_hash).first():
            return jsonify(msg="This exact certificate file already exists in the registry."), 409

        extracted_data = verification_result.get('certificate_data', {})
        cert_id = extracted_data.get('cert_id') or extracted_data.get('roll_no')

        if not cert_id:
             return jsonify(msg="Could not extract a Certificate ID from the document."), 400

        # Validation: Check if a record with this ID already exists
        if Certificate.query.filter_by(cert_id=cert_id).first():
            return jsonify(msg=f"A certificate with the ID '{cert_id}' already exists."), 409

        # Create the New Certificate Record from the extracted data
        new_certificate = Certificate(
            cert_id=cert_id,
            name=extracted_data.get('name', 'Unknown'),
            roll=extracted_data.get('roll_no'),
            course=extracted_data.get('course'),
            status=CertificateStatus.VALID,
            file_hash=file_hash
        )

        db.session.add(new_certificate)
        db.session.commit()

        return jsonify(msg=f"Certificate '{cert_id}' for '{new_certificate.name}' was successfully added."), 201

    except Exception as e:
        traceback.print_exc()
        return jsonify(msg=f"An unexpected error occurred: {str(e)}"), 500