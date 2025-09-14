from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt
from backend.models import db, User, Role, TokenBlocklist
from datetime import datetime, timezone
from functools import wraps

auth_bp = Blueprint("auth", __name__)


# --- Custom Decorator for Role-Based Access ---
def roles_required(*roles):
    """A custom decorator to verify user roles from JWT claims."""
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt()
            user_roles = claims.get("roles", [])
            
            if not any(role in user_roles for role in roles):
                return jsonify(msg=f"Admins or specific roles only! Required: {', '.join(roles)}"), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper


@auth_bp.route("/signup", methods=["POST", "OPTIONS"])
def signup():
    """Handles new user registration."""
    if request.method == "OPTIONS":
        return jsonify(message="CORS preflight successful"), 200
        
    data = request.get_json()
    pin = data.get("pin")
    
    if not pin or pin != current_app.config.get('SIGNUP_PIN'):
        return jsonify(msg="Invalid security PIN provided."), 403

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify(msg="Username, email, and password are required."), 400

    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify(msg="Username or email already exists."), 409

    ## --- KEY CHANGE HERE --- ##
    # We now look for the 'Admin' role instead of 'Verifier'.
    admin_role = Role.query.filter_by(name='Admin').first()
    # If the 'Admin' role doesn't exist in the database, we create it.
    if not admin_role:
        admin_role = Role(name='Admin')
        db.session.add(admin_role)
    ## --- END OF KEY CHANGE --- ##

    new_user = User(username=username, email=email, roles=[admin_role])
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify(msg="Admin user created successfully. Please log in."), 201


@auth_bp.route("/login", methods=["POST", "OPTIONS"])
def login():
    """Handles user login and returns a JWT access token."""
    if request.method == "OPTIONS":
        return jsonify(message="CORS preflight successful"), 200
        
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify(msg="Username and password are required."), 400

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        user_roles = [role.name for role in user.roles]
        additional_claims = {"roles": user_roles}
        
        # CORRECTED: Convert user ID to string for the token identity
        access_token = create_access_token(identity=str(user.id), additional_claims=additional_claims)
        
        return jsonify(access_token=access_token)
    
    return jsonify(msg="Bad username or password."), 401


@auth_bp.route('/logout', methods=['POST', 'OPTIONS'])
@jwt_required()
def logout():
    """Handles user logout by blocklisting the current token."""
    if request.method == "OPTIONS":
        return jsonify(message="CORS preflight successful"), 200
        
    jti = get_jwt()['jti']
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    db.session.commit()
    return jsonify(msg="Access token revoked successfully")


@auth_bp.route('/profile', methods=['GET', 'OPTIONS'])
@jwt_required()
def profile():
    """Returns the profile information of the currently logged-in user."""
    if request.method == "OPTIONS":
        return jsonify(message="CORS preflight successful"), 200
        
    # CORRECTED: Get the identity (as a string) and convert back to an integer
    current_user_id_str = get_jwt_identity()
    user = User.query.get(int(current_user_id_str))
    
    if not user:
        return jsonify(msg="User not found"), 404
        
    user_data = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.roles[0].name if user.roles else "No Role" # Updated for clarity
    }
    return jsonify(user_data)