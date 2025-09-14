# config.py
# Manages application configuration for different environments using python-dotenv.

import os
from datetime import timedelta
from dotenv import load_dotenv

# --- ROBUST PATHING FIX ---
# NEW: Define the absolute path to the project root to avoid relative path issues.
# 'basedir' will be 'C:\...\fakecert-sih\backend'
basedir = os.path.abspath(os.path.dirname(__file__))
# 'PROJECT_ROOT' will be 'C:\...\fakecert-sih'
PROJECT_ROOT = os.path.dirname(basedir)

load_dotenv(os.path.join(PROJECT_ROOT, '.env')) # Load .env from the project root

class Config:
    """Base configuration class with settings common to all environments."""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-hard-to-guess-default-secret-key'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'a-strong-jwt-secret-key'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_TOKEN_LOCATION = ["headers"]
    MOCK_API_KEY = os.environ.get('MOCK_API_KEY') or 'my-secret-mock-api-key'
    BASE_VERIFICATION_URL = os.environ.get('BASE_VERIFICATION_URL') or 'http://127.0.0.1:5000'
     # NEW: Add a secret PIN required for new user registration.
    SIGNUP_PIN = os.environ.get('SIGNUP_PIN') or 'change-me-in-production'

    @staticmethod
    def init_app(app):
        pass

class DevelopmentConfig(Config):
    """Configuration for the development environment."""
    DEBUG = True
    # CHANGE: Use the absolute project root to construct the database URI.
    # This is a foolproof way to ensure the path is always correct.
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + os.path.join(PROJECT_ROOT, 'instance', 'data-dev.db')
    
class TestingConfig(Config):
    """Configuration for the testing environment."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or 'sqlite:///:memory:'

class ProductionConfig(Config):
    """Configuration for the production environment."""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        if not cls.SQLALCHEMY_DATABASE_URI:
            raise ValueError("DATABASE_URL is not set for the production environment.")

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}