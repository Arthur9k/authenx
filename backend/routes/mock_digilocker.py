# routes/mock_digilocker.py
from flask import Blueprint, request, jsonify, current_app
from sqlalchemy.exc import IntegrityError

# CHANGE: Use '..' to go up one level to find the 'models' file.
from ..models import db, MockCertificate

mock_dl_bp = Blueprint("mock_digilocker", __name__, url_prefix='/api/mock/digilocker')

@mock_dl_bp.route("/upload", methods=["POST"])
def upload_certificate():
    api_key = request.headers.get("X-API-KEY")
    if not api_key or api_key != current_app.config.get("MOCK_API_KEY"):
        return jsonify({"error": "Unauthorized: Invalid or missing API Key"}), 401
    if not request.is_json:
        return jsonify({"error": "Request body must be JSON"}), 400
    data = request.get_json()
    required_fields = ["institution", "cert_id", "name"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": f"Missing required fields: {', '.join(required_fields)}"}), 400

    cert = MockCertificate(
        institution=data["institution"],
        cert_id=data["cert_id"],
        name=data["name"],
        roll=data.get("roll"),
        file_hash=data.get("file_hash"),
    )
    try:
        db.session.add(cert)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": f"Conflict: Certificate with cert_id '{data['cert_id']}' already exists."}), 409
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to save mock certificate")
        return jsonify({"error": "Internal server error during save operation"}), 500
    return jsonify(cert.to_dict()), 201

@mock_dl_bp.route("/v1/certificate/<string:cert_id>", methods=["GET"])
def get_certificate(cert_id):
    # The cert_id now comes directly from the URL
    cert = MockCertificate.query.filter_by(cert_id=cert_id).first()
    if not cert:
        return jsonify({
            "found": False,
            "query_cert_id": cert_id,
            "data": None
        }), 404
    return jsonify({
        "found": True,
        "query_cert_id": cert_id,
        "data": cert.to_dict()
    }), 200