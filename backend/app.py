# backend/app.py

import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from werkzeug.exceptions import NotFound

from backend.config import config
from backend.models import db, TokenBlocklist
from backend.seed import seed_command
from backend.routes.auth import auth_bp
from backend.routes.verify import verify_bp
from backend.routes.mock_digilocker import mock_dl_bp
from backend.routes.admin_routes import admin_bp

def create_app(config_name=None):
    if config_name is None:
        config_name = os.getenv('FLASK_CONFIG', 'default')

    PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    INSTANCE_FOLDER_PATH = os.path.join(PROJECT_ROOT, 'instance')

    app = Flask(__name__, instance_path=INSTANCE_FOLDER_PATH)
    app.config.from_object(config[config_name])
    
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    db.init_app(app)
    CORS(app) 
    jwt = JWTManager(app)

    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()
        return token is not None

    # CORRECTED: Added the url_prefix for the authentication blueprint
    app.register_blueprint(auth_bp, url_prefix='/auth')

    app.register_blueprint(verify_bp)
    app.register_blueprint(mock_dl_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')

    if not app.debug and not app.testing:
        log_dir = os.path.join(PROJECT_ROOT, 'logs')
        if not os.path.exists(log_dir):
            os.mkdir(log_dir)
        file_handler = RotatingFileHandler(os.path.join(log_dir, 'fakecert.log'), max_bytes=10240, backup_count=10)
        file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('CertiSure Application Startup')

    @app.errorhandler(NotFound)
    def handle_not_found(e):
        return jsonify(error="Not Found", message="The requested resource was not found."), 404

    @app.errorhandler(Exception)
    def handle_generic_error(e):
        app.logger.exception(f"An unhandled exception occurred: {e}")
        return jsonify(error="Internal Server Error", message="An unexpected error occurred."), 500

    app.cli.add_command(seed_command)

    @app.route("/")
    def index():
        return "✅ CertiSure - API Service is Running"

    return app