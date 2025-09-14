# run.py
import os
from backend.app import create_app

# This script is a more reliable way to start your Flask development server,
# bypassing potential caching issues with the 'flask run' command.

if __name__ == "__main__":
    # Set environment variables reliably for this session
    os.environ['FLASK_APP'] = 'backend.app'
    os.environ['FLASK_ENV'] = 'development'
    
    app = create_app()
    
    print("="*60)
    print(">>> Starting Flask application with a reliable startup script...")
    print(">>> Any and all code changes should now be correctly loaded.")
    print("="*60)
    
    # Run the app. The 'debug=True' flag enables the auto-reloader.
    app.run(debug=True, host='0.0.0.0', port=5000)