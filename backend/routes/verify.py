# backend/routes/verify.py

import os
import uuid
import csv
import io
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from werkzeug.utils import secure_filename
import requests
import traceback 
from dateutil import parser

# Your existing service imports
from backend.services import (
    hash_service,
    pdf_service,
    ocr_service,
    forgery_service,
    document_classifier as document_classifier_service, # This line will now work
    qr_service
)
from backend.models import db, Certificate, VerificationLog, CertificateStatus, VerificationResult, GuestVerification, User, Alert

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'csv'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def _compare_ocr_with_registry_data(ocr_data, registry_data):
    """
    Compares key fields from OCR with data from a registry.
    Returns True if the data is consistent.
    """
    if not ocr_data or not registry_data:
        return False

    # Normalize and compare key fields. We use .lower() and .strip() to handle
    # minor differences in case or whitespace from OCR.
    ocr_name = ocr_data.get('name', '').lower().strip()
    registry_name = registry_data.get('name', '').lower().strip()

    ocr_roll = ocr_data.get('roll_no', '').lower().strip()
    registry_roll = registry_data.get('roll', '').lower().strip()
    
    # We consider it a match if the names are very similar and rolls match.
    # Using 'in' allows for partial name matches (e.g., "MOHD NASAR" vs "MOHD NASAR-")
    if registry_name in ocr_name and ocr_roll == registry_roll:
        return True
        
    return False

def _process_single_file(file_storage, user_id=None, local_timestamp=None, create_log=True):
    upload_folder = os.path.join(current_app.instance_path, 'uploads')
    os.makedirs(upload_folder, exist_ok=True)
    
    original_filename = file_storage.filename
    temp_filename = secure_filename(str(uuid.uuid4()) + os.path.splitext(original_filename)[1])
    filepath = os.path.join(upload_folder, temp_filename)
    
    file_storage.save(filepath)

    is_guest = user_id is None
    final_response = {}
    source = "Unknown"

    try:
        file_hash = hash_service.sha256_of_file(filepath)
        final_response['file_hash'] = file_hash

        if is_guest:
            existing_verification = GuestVerification.query.filter_by(file_hash=file_hash).first()
            if existing_verification:
                response = existing_verification.result_cache
                response['original_filename'] = original_filename
                response['file_hash'] = file_hash
                return response

        image, page_count = pdf_service.pdf_to_image(filepath)
        if image is None:
            raise Exception("Failed to convert document to image.")
        
        ### START: UPDATED OCR & CLASSIFICATION LOGIC ###

        # Step 1: Perform a quick scan to get text for classification.
        classification_text = ocr_service.get_text_for_classification(image)
        
        # Step 2: Classify the document based on the initial text.
        if not document_classifier_service.is_certificate(classification_text):
            result = VerificationResult.NOT_A_CERTIFICATE
            reasons = "Document could not be identified as an academic certificate or marksheet."
            final_response.update({"status": result.value, "details": reasons, "trust_score": 0})
        
        else:
            # Step 3: If it's a certificate, perform the deep scan and extraction.
            # This now returns both the full text and the structured data.
            full_text, structured_data = ocr_service.extract_structured_data(image)
            
            # Use roll_no as a fallback for cert_id
            cert_id = structured_data.get("cert_id") or structured_data.get("roll_no")
            # --- NEW, REFINED VERIFICATION LOGIC ---


            # GATE 1: PERFECT MATCH CHECK (Internal Database)
            certificate_by_hash = Certificate.query.filter_by(file_hash=file_hash).first()
            if certificate_by_hash:
                # ... (This gate's logic is perfect, no changes needed)
                source = "Database Registry (Hash Match)"
                if certificate_by_hash.status == CertificateStatus.REVOKED:
                    result = VerificationResult.DOCUMENT_REVOKED
                    reasons = "This certificate is on record but has been officially REVOKED."
                else:
                    result = VerificationResult.VERIFIED_VIA_REGISTRY
                    reasons = "Document is a perfect match to an official record in the registry."
                final_response.update({
                    "status": result.value, "details": reasons, "trust_score": 100, 
                    "certificate_data": certificate_by_hash.to_dict()
                })

            # GATE 2: EXTERNAL REGISTRY CHECK (Now with Data Reconciliation)
            if 'status' not in final_response and cert_id:
                try:
                    api_key = current_app.config['MOCK_API_KEY']
                    digilocker_url = f"{request.host_url}api/mock/digilocker/v1/certificate/{cert_id}"
                    response = requests.get(digilocker_url, headers={'X-API-Key': api_key})
                    
                    if response.status_code == 200:
                        digi_data = response.json()
                        certificate_data_from_api = digi_data.get('data', {})
                        hash_from_digilocker = certificate_data_from_api.get('file_hash', '') if certificate_data_from_api else ''
                        
                        # BRANCH A: Perfect hash match in DigiLocker
                        if hash_from_digilocker.strip().lower() == file_hash.strip().lower():
                            result = VerificationResult.VERIFIED_VIA_REGISTRY
                            reasons = f"Verified via external registry (DigiLocker) for Cert ID: {cert_id}."
                            source = "DigiLocker"
                            final_response.update({"status": result.value, "details": reasons, "trust_score": 100, "certificate_data": certificate_data_from_api})
                        
                        # BRANCH B: Hash mismatch, so we perform Data Reconciliation
                        else:
                            # Use our new helper function to compare OCR text vs DigiLocker data
                            if _compare_ocr_with_registry_data(structured_data, certificate_data_from_api):
                                # Data matches, so it's likely a scan/crop. Issue a warning.
                                result = VerificationResult.VERIFIED_VIA_REGISTRY
                                reasons = (f"Data Verified: The text on the document matches the external registry record for '{certificate_data_from_api.get('name')}'.\n"
                                        f"<b style='color: orange;'>Note:</b> This document is a non-original version (for example, scanned or cropped). While the content looks intact, technical checks show a different hash value due to the change in format.")
                                source = "DigiLocker (Data Match)"
                                final_response.update({"status": result.value, "details": reasons, "trust_score": 75, "certificate_data": certificate_data_from_api})
                            else:
                                # Data does NOT match. This is a confirmed forgery.
                                result = VerificationResult.LIKELY_FORGED
                                reasons = f"CRITICAL: The data on this document does NOT match the official external registry record for Cert ID {cert_id}."
                                final_response.update({"status": result.value, "details": reasons, "trust_score": 10, "certificate_data": structured_data})
                            
                except requests.exceptions.RequestException:
                    current_app.logger.warning("Could not connect to the mock DigiLocker service.")

            # GATE 3: DATA MATCH CHECK (Internal Database)
            if 'status' not in final_response and cert_id:
                # ... (This gate's logic is perfect, no changes needed)
                certificate_by_data = Certificate.query.filter_by(cert_id=cert_id).first()
                if certificate_by_data:
                    source = "Database Registry (Data Match)"
                    score, forgery_reasons = forgery_service.calculate_trust_score(image, full_text, page_count, structured_data)
                    if certificate_by_data.status == CertificateStatus.REVOKED:
                        result = VerificationResult.DOCUMENT_REVOKED
                        reasons = "Data on this document matches a record that has been REVOKED."
                    elif score < forgery_service.FORGERY_THRESHOLD:
                        result = VerificationResult.VERIFIED_VIA_REGISTRY
                        reasons = (f"Data Verified: Matches record for '{certificate_by_data.name}'.\n"
                                f"**WARNING:** The document's low trust score ({score}) suggests it may have been visually altered. Manual review is advised.\n\n"
                                f"Reasons for low score:\n{forgery_reasons}")
                    else:
                        result = VerificationResult.VERIFIED_VIA_REGISTRY
                        reasons = "Data on this document matches a valid record, and the document appears authentic."
                    final_response.update({
                        "status": result.value, "details": reasons, "trust_score": score, 
                        "certificate_data": certificate_by_data.to_dict()
                    })
            
            # If no conclusive result yet, run forgery analysis
            if 'status' not in final_response:
                # Use the high-quality 'full_text' from the deep scan for forgery analysis
                source = "Forgery Analysis" # <-- ADD THIS LINE to track the source
    # Use the high-quality 'full_text' from the deep scan for forgery analysis
                score, forgery_reasons = forgery_service.calculate_trust_score(image, full_text, page_count, structured_data)
                if score >= forgery_service.HIGH_CONFIDENCE_THRESHOLD:
                    result = VerificationResult.MANUAL_CHECK_REQUIRED
                    reasons = "High confidence, but not in any registry. Manual check recommended.\n" + forgery_reasons
                else:
                    result = VerificationResult.LIKELY_FORGED
                    reasons = "Not in any registry and failed forgery checks.\n" + forgery_reasons

                # --- ADD THIS NEW DATE LOGIC ---
                date_string = structured_data.get("issue_date")
                if date_string:
                    try:
                        # 1. The code parses the date here...
                        parsed_date = parser.parse(date_string).date()
                        # 2. ...and now it correctly ADDS THE RESULT back to the main data dictionary.
                        structured_data["parsed_issue_date"] = parsed_date
                    except (parser.ParserError, TypeError):
                        current_app.logger.warning(f"Could not parse date string: {date_string}")
            # --- END OF NEW DATE LOGIC ---

                final_response.update({"status": result.value, "details": reasons, "trust_score": score, "certificate_data": structured_data})

        ### END: UPDATED OCR & CLASSIFICATION LOGIC ###
        if create_log:
        # Your existing logging logic
            if not is_guest:
            # Only create a detailed log if the user is REGISTERED (not a guest)
                log_entry = VerificationLog(
                    user_id=user_id,
                    result=VerificationResult(final_response.get('status')), # Use the Enum object
                    reasons=final_response.get('details', ''),
                    verifier_ip_address=request.remote_addr,
                    filename=original_filename,
                    file_hash=final_response.get('file_hash'),
                    trust_score=final_response.get('trust_score'),
                    source=source,
                    timestamp_local=local_timestamp
                )
                db.session.add(log_entry)
            else:
            # For GUESTS, we only save the hash and result to speed up future checks
            # This keeps your original functionality.
                # For GUESTS, we must make sure the result is JSON-serializable.
                result_cache = final_response.copy() # Make a copy to avoid changing the original
                
                # Check if our special date object exists in the data
                if "certificate_data" in result_cache and "parsed_issue_date" in result_cache["certificate_data"]:
                    # If it exists, convert it to a simple string (YYYY-MM-DD format)
                    result_cache["certificate_data"]["parsed_issue_date"] = result_cache["certificate_data"]["parsed_issue_date"].isoformat()
                
                guest_log = GuestVerification(file_hash=file_hash, result_cache=result_cache)
                db.session.add(guest_log)

            db.session.commit()
        
    except Exception as e:
        current_app.logger.error(f"Error processing {original_filename}: {e}")
        traceback.print_exc()
        result = VerificationResult.ERROR
        final_response.update({"status": result.value, "details": "An internal error occurred during processing."})
    
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)

    final_response['original_filename'] = original_filename
    return final_response

# 1. Define the Blueprint with the URL prefix
verify_bp = Blueprint("verify_bp", __name__, url_prefix='/verify')

# ... (all your helper functions like allowed_file and _process_single_file) ...

# 2. Define the route relative to the prefix. It should be '/upload', NOT '/verify/upload'
@verify_bp.route("/upload", methods=["POST"])
def upload_for_verification():
    if 'file' not in request.files: return jsonify(error="No file part in the request"), 400
    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename): return jsonify(error="No file selected or file type not allowed"), 400

    # This is the new, safer way to check for a user
    from flask_jwt_extended import verify_jwt_in_request
    user_id = None
    try:
        # This checks for a token without crashing if one isn't there (for guests)
        verify_jwt_in_request(optional=True) 
        user_id = get_jwt_identity()
    except Exception:
        pass # Fails silently for guests, user_id stays None

    # We now also get the local timestamp that the frontend is sending
    local_timestamp = request.form.get('localTimestamp')

    result = _process_single_file(file, user_id, local_timestamp)
    return jsonify(result)


# I am omitting them here for brevity, you do not need to change them.
@verify_bp.route("/bulk-upload", methods=["POST"])
@jwt_required()
def bulk_upload_for_verification():
    if 'files' not in request.files: return jsonify(error="No files part in the request"), 400
    files = request.files.getlist('files')
    user_id = get_jwt_identity()
    results = []
    if not files or all(f.filename == '' for f in files): return jsonify(error="No files selected"), 400
    for file in files:
        if file and allowed_file(file.filename):
            result = _process_single_file(file, user_id)
            results.append(result)
    return jsonify(results=results)

@verify_bp.route("/csv-check", methods=["POST"])
@jwt_required()
def csv_check():
    if 'file' not in request.files:
        return jsonify(error="No file part in the request"), 400
    
    file = request.files['file']
    if not file or not file.filename.endswith('.csv'):
        return jsonify(error="Please upload a valid CSV file."), 400

    results = []
    user_id = get_jwt_identity()

    try:
        stream = io.StringIO(file.stream.read().decode("UTF-8"), newline=None)
        csv_reader = csv.DictReader(stream)

        for row in csv_reader:
            cert_id = row.get('cert_id')
            row_result = {"csv_row": row, "status": "Error", "reason": "Unknown issue"}

            if not cert_id:
                row_result.update({"status": "Skipped", "reason": "Missing 'cert_id' in row."})
                results.append(row_result)
                continue

            certificate = Certificate.query.filter_by(cert_id=cert_id).first()
            
            if not certificate:
                row_result.update({"status": "Not Found", "reason": "No record with this cert_id exists."})
            elif certificate.status == CertificateStatus.REVOKED:
                row_result.update({"status": "Revoked", "reason": "This certificate has been officially revoked."})
            else:
                row_result.update({"status": "Verified", "reason": "Certificate is valid and exists in the database."})
            
            results.append(row_result)

    except Exception as e:
        current_app.logger.error(f"Error processing CSV for user {user_id}: {e}")
        return jsonify(error="Failed to process CSV file.", message=str(e)), 500

    return jsonify(results=results)

@verify_bp.route("/qr", methods=["POST"])
@jwt_required()
def verify_qr_code():
    if 'file' not in request.files: return jsonify(error="No QR code image provided"), 400
    file = request.files['file']
    if not file or not allowed_file(file.filename): return jsonify(error="File type not allowed"), 400
    try:
        image_bytes = file.read()
        decoded_data = qr_service.read_qr_code(image_bytes)
        if not decoded_data: return jsonify(status="Error", message="Could not decode QR code."), 400
        cert_id = decoded_data.get('cert_id')
        data_hash = decoded_data.get('data_hash')
        if not cert_id or not data_hash: return jsonify(status="Invalid QR", message="QR code missing required data."), 400
        certificate = Certificate.query.filter_by(cert_id=cert_id, data_hash=data_hash).first()
        if not certificate: return jsonify(status="Not Found", message="No matching certificate found in the registry."), 404
        return jsonify(status="Verified", message="QR Code data matches the certificate registry.", certificate_data=certificate.to_dict()), 200
    except Exception as e:
        current_app.logger.error(f"Error processing QR code: {e}")
        return jsonify(error="An internal error occurred during QR verification."), 500