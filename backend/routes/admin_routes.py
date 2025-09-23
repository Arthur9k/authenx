import csv
import io
import random
import traceback
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from backend.routes.verify import _process_single_file, allowed_file
from dateutil import parser

# Assuming your models and auth helpers are in these locations
from backend.models import db, Alert, User, Role, Certificate, VerificationLog, Institution, CertificateStatus,VerificationResult
from backend.routes.auth import roles_required

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/stats", methods=["GET"])
@jwt_required()
@roles_required("Admin", "SuperAdmin")
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
@roles_required("Admin", "SuperAdmin")
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
@roles_required("Admin", "SuperAdmin")
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
@roles_required("Admin", "Institution", "SuperAdmin") # Add SuperAdmin to allowed roles
def get_certificates():
    """
    Returns a list of certificates.
    - SuperAdmins see ALL certificates.
    - Other users see only their OWN certificates.
    """
    claims = get_jwt()
    user_roles = claims.get("roles", [])
    current_user_id = get_jwt_identity()

    if "SuperAdmin" in user_roles:
        # If the user is a SuperAdmin, get ALL certificates from the database.
        certificates = Certificate.query.order_by(Certificate.created_at.desc()).all()
    else:
        # Otherwise, get only the certificates created by the current user.
        certificates = Certificate.query.filter_by(created_by_user_id=current_user_id).order_by(Certificate.created_at.desc()).all()

    return jsonify([cert.to_dict() for cert in certificates])


@admin_bp.route("/verification-logs", methods=["GET"])
@jwt_required()
@roles_required("Admin", "SuperAdmin") # Add SuperAdmin to allowed roles
def get_verification_logs():
    """
    Returns a list of verification logs.
    - SuperAdmins see ALL logs.
    - Other users see only their OWN logs.
    """
    claims = get_jwt()
    user_roles = claims.get("roles", [])
    current_user_id = get_jwt_identity()

    if "SuperAdmin" in user_roles:
        # If the user is a SuperAdmin, get ALL logs from the database.
        logs = VerificationLog.query.order_by(VerificationLog.timestamp_utc.desc()).limit(100).all()
    else:
        # Otherwise, get only the logs created by the current user.
        logs = VerificationLog.query.filter_by(user_id=current_user_id).order_by(VerificationLog.timestamp_utc.desc()).limit(100).all()

    return jsonify([log.to_dict() for log in logs])


@admin_bp.route("/create-user", methods=["POST"])
@jwt_required()
@roles_required("Admin", "SuperAdmin")
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
@roles_required("Admin", "Institution", "SuperAdmin")
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
    local_timestamp = request.form.get('localTimestamp')
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
            # First, look for an 'issued_date' column in the CSV row and parse it
            parsed_date = None
            date_string = row.get('issued_date')
            if date_string:
                try:
                    # Use our date tool to understand the date text
                    parsed_date = parser.parse(date_string).date()
                except (parser.ParserError, TypeError):
                    pass # If the date is invalid, we safely ignore it

            # Now, create the new certificate, including the date
            new_cert = Certificate(
                institution_id=user_institution.id, # This uses the correct institution ID
                created_by_user_id=current_user_id,  # Link the certificate to the uploader
                cert_id=cert_id,
                name=name,
                roll=row.get('roll'),
                course=row.get('course'),
                file_hash=row.get('file_hash'),
                status=CertificateStatus.VALID,
                issued_date=parsed_date # <-- This is the crucial new line for the date
            )
            db.session.add(new_cert)
            results.append({"row": i + 2, "cert_id": cert_id, "status": "Success", "message": "Added to registry."})
            # Now, create a log entry for this successful administrative action
            admin_log_entry = VerificationLog(
                user_id=current_user_id,
                certificate_id=new_cert.id, # We will link this after committing
                result=VerificationResult.UPLOADED_TO_REGISTRY,
                reasons=f"Record for '{name}' added via bulk CSV upload.",
                verifier_ip_address=request.remote_addr,
                filename=file.filename, # Log the name of the CSV file
                trust_score=None,
                source="Admin Bulk Upload",
                timestamp_local=local_timestamp # Use the timestamp we got earlier
            )
            db.session.add(admin_log_entry)
        # Commit all the new certificates to the database at once
        db.session.flush() 
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
@roles_required("Admin", "Institution", "SuperAdmin") # Allow Admin, Institution, and SuperAdmin roles
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
        local_timestamp = request.form.get('localTimestamp')
        verification_result = _process_single_file(file, user_id=current_user_id, local_timestamp=local_timestamp, create_log=False)
        
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
        # First, get the correctly parsed date that verify.py prepared for us
        parsed_date = extracted_data.get("parsed_issue_date")

        # Now, create the new certificate record, including the date
        new_certificate = Certificate(
            institution_id=user_institution.id, # This uses the correct institution ID
            created_by_user_id=current_user_id,  # Link the certificate to the uploader
            cert_id=cert_id,
            name=extracted_data.get('name', 'Unknown'),
            roll=extracted_data.get('roll_no'),
            course=extracted_data.get('course'),
            status=CertificateStatus.VALID,
            file_hash=file_hash,
            issued_date=parsed_date # <-- This is the crucial new line for the date
        )
        
        db.session.add(new_certificate)
        db.session.commit()
        # --- ADD THIS ENTIRE NEW BLOCK ---
        # Now, create our own, more accurate log entry for the upload action
        admin_log_entry = VerificationLog(
            user_id=current_user_id,
            certificate_id=new_certificate.id, # Link the log to the new certificate
            result=VerificationResult.UPLOADED_TO_REGISTRY, # Use our new "Uploaded" status
            reasons=f"Admin user '{User.query.get(current_user_id).username}' added this record to the registry.",
            verifier_ip_address=request.remote_addr,
            filename=file.filename,
            file_hash=file_hash,
            trust_score=None, # Set score to None, which will show as N/A
            source="Admin Upload", # Set a clear source for the action
            timestamp_local=local_timestamp
        )
        db.session.add(admin_log_entry)
        db.session.commit() # Commit the new log entry

        return jsonify(msg=f"Certificate '{cert_id}' for '{new_certificate.name}' was successfully added to '{user_institution.name}'."), 201

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify(msg=f"An unexpected error occurred: {str(e)}"), 500
    # In backend/routes/admin_routes.py

# ADD THIS ENTIRE NEW FUNCTION TO THE END OF THE FILE
@admin_bp.route("/certificates/delete", methods=["POST"])
@jwt_required()
@roles_required("Admin", "SuperAdmin")
def delete_certificates():
    """Accepts a list of certificate IDs and deletes them from the database."""
    data = request.get_json()
    cert_ids_to_delete = data.get('ids', [])

    if not cert_ids_to_delete:
        return jsonify(msg="No certificate IDs provided."), 400

    # This query finds all certificates whose 'cert_id' is in the list we received.
    certificates = Certificate.query.filter(Certificate.cert_id.in_(cert_ids_to_delete)).all()
    
    deleted_count = 0
    for cert in certificates:
        db.session.delete(cert)
        deleted_count += 1
        
    db.session.commit()
    
    return jsonify(msg=f"Successfully deleted {deleted_count} certificate(s).")

# In backend/routes/admin_routes.py

# ADD THIS SECOND NEW FUNCTION TO THE END OF THE FILE
@admin_bp.route("/certificates/revoke", methods=["POST"])
@jwt_required()
@roles_required("Admin", "Institution", "SuperAdmin")
def revoke_certificates():
    """Accepts a list of certificate IDs and updates their status to 'REVOKED'."""
    data = request.get_json()
    cert_ids_to_revoke = data.get('ids', [])

    if not cert_ids_to_revoke:
        return jsonify(msg="No certificate IDs provided."), 400

    # This query finds all certificates to be updated.
    # The `with_for_update()` is a safety measure to prevent conflicts if multiple admins act at once.
    certificates = db.session.query(Certificate).filter(Certificate.cert_id.in_(cert_ids_to_revoke)).with_for_update().all()
    
    revoked_count = 0
    for cert in certificates:
        cert.status = CertificateStatus.REVOKED
        revoked_count += 1
        
    db.session.commit()
    
    return jsonify(msg=f"Successfully revoked {revoked_count} certificate(s).")