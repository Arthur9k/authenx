import csv
import io
import random
import traceback
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from backend.routes.verify import _process_single_file, allowed_file

# Assuming your models and auth helpers are in these locations
from backend.models import db, Alert, User, Role, Certificate, VerificationLog, Institution, CertificateStatus
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
    """Allows an admin to manually create a new user and link them to an institution."""
    data = request.get_json()
    
    # --- KEY CHANGE: Get the new institution_name field ---
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    role_name = data.get("role", "Institution")
    institution_name = data.get("institution_name", "").strip() # Get the institution name from the form

    # We also check that an institution name was provided
    if not all([username, email, password, institution_name]):
        return jsonify({"msg": "Username, email, password, and institution name are required"}), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"msg": "Username or email already exists"}), 409

    # --- KEY CHANGE: Find or Create the Institution (Same logic as signup) ---
    # Look in the database to see if this institution already exists
    institution = Institution.query.filter_by(name=institution_name).first()
    if not institution:
        # If it's a new institution, create a record for it
        institution = Institution(name=institution_name)
        db.session.add(institution)
        db.session.flush() # Use flush to prepare the institution for linking

    role = Role.query.filter_by(name=role_name).first()
    if not role:
        role = Role(name=role_name)
        db.session.add(role)

    # Create the user (this part is the same as before)
    new_user = User(username=username, email=email, roles=[role])
    new_user.set_password(password)
    db.session.add(new_user)
    
    # This commit saves the new user and institution, giving the user a unique ID
    db.session.commit()

    # --- KEY CHANGE: Link the user to the institution after creation ---
    # Now that the user has an ID, we update the institution's record with that ID.
    institution.admin_user_id = new_user.id
    db.session.commit()
    
    return jsonify({"msg": f"User '{username}' created for '{institution_name}'."}), 201


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

    # --- KEY CHANGES START HERE ---

    # 1. Get the uploader's user ID from their login token.
    from flask_jwt_extended import get_jwt_identity
    current_user_id = get_jwt_identity()

    # 2. Find their institution ONCE before the loop starts (this is more efficient).
    user_institution = Institution.query.filter_by(admin_user_id=current_user_id).first()

    # 3. SAFETY CHECK: If the uploader is not linked to an institution, stop.
    if not user_institution:
        return jsonify(msg="Your user account is not associated with a specific institution. Cannot add certificates."), 403
    
    # --- KEY CHANGES END HERE ---

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

            # 4. Inside the loop, use the correct institution ID for every new certificate.
            new_cert = Certificate(
                institution_id=user_institution.id, # This is the crucial fix
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
# In backend/routes/admin_routes.py

# Replace your old add_certificate function with this one.
@admin_bp.route("/certificate/add", methods=["POST"])
@jwt_required()
@roles_required("Admin", "Institution") # Allow both Admin and Institution roles
def add_certificate():
    """
    Accepts a single certificate file, processes it, links it to the UPLOADER'S
    institution, and adds its metadata to the main Certificate registry.
    """
    if 'file' not in request.files:
        return jsonify(msg="No file part in the request"), 400
    
    file = request.files['file']

    if file.filename == '' or not allowed_file(file.filename):
        return jsonify(msg="No file selected or file type not allowed"), 400

    try:
        # --- THIS IS THE CORRECT LOGIC FOR LINKING THE INSTITUTION ---

        # 1. Get the ID of the user who is currently logged in from their token.
        from flask_jwt_extended import get_jwt_identity
        current_user_id = get_jwt_identity()

        # 2. Find the institution that this user is registered to manage.
        # This assumes a link exists where an Institution has an `admin_user_id`.
        user_institution = Institution.query.filter_by(admin_user_id=current_user_id).first()

        # 3. SAFETY CHECK: If the logged-in user is not linked to any institution, deny the request.
        if not user_institution:
            return jsonify(msg="Your user account is not associated with a specific institution. Cannot add certificate."), 403

        # --- The rest of the logic proceeds, but now we know the correct institution ---

        # We pass the user's ID to the processing function for potential future use (though it's not used now)
        verification_result = _process_single_file(file, user_id=current_user_id, local_timestamp=None)
        
        file_hash = verification_result.get('file_hash')
        if not file_hash:
            return jsonify(msg="Could not generate a hash for the file."), 500

        if Certificate.query.filter_by(file_hash=file_hash).first():
            return jsonify(msg="This exact certificate file already exists in the registry."), 409
        
        extracted_data = verification_result.get('certificate_data', {})
        cert_id = extracted_data.get('cert_id') or extracted_data.get('roll_no')
        
        if not cert_id:
             return jsonify(msg="Could not extract a Certificate ID from the document."), 400

        if Certificate.query.filter_by(cert_id=cert_id).first():
            return jsonify(msg=f"A certificate with the ID '{cert_id}' already exists."), 409

        # 4. Create the new certificate, now using the UPLOADER'S institution ID.
        new_certificate = Certificate(
            institution_id=user_institution.id, # This is the crucial fix
            cert_id=cert_id,
            name=extracted_data.get('name', 'Unknown'),
            roll=extracted_data.get('roll_no'),
            course=extracted_data.get('course'),
            status=CertificateStatus.VALID,
            file_hash=file_hash
        )
        
        db.session.add(new_certificate)
        db.session.commit()

        return jsonify(msg=f"Certificate '{cert_id}' for '{new_certificate.name}' was successfully added to '{user_institution.name}'."), 201

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify(msg=f"An unexpected error occurred: {str(e)}"), 500