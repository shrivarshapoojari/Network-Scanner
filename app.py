import os
import logging
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

def create_app():
    # Create the app
    app = Flask(__name__)
    app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    
    # Configure the database
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///cybersec_dashboard.db")
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }
    app.config["UPLOAD_FOLDER"] = "uploads"
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max file size
    
    # Initialize the app with the extension
    db.init_app(app)
    
    # Register blueprints
    from scanner import scanner_bp
    from analyzer import analyzer_bp
    
    app.register_blueprint(scanner_bp, url_prefix='/scanner')
    app.register_blueprint(analyzer_bp, url_prefix='/analyzer')
    
    # Main dashboard route
    @app.route('/')
    def dashboard():
        return render_template('dashboard.html')
    
    with app.app_context():
        # Import models to ensure tables are created
        import models
        db.create_all()
        
        # Create uploads directory if it doesn't exist
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    
    return app

# Create app instance
app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
