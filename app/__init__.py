import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from dotenv import load_dotenv

load_dotenv()

db = SQLAlchemy()
migrate = Migrate()  # ← Add this line

def create_app():
    app = Flask(__name__)

    # PostgreSQL connection URI
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost/pening"
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    migrate.init_app(app, db)  # ← Add this line

    from app.models import Finding  # Make sure models are imported

    from .routes import securityhub_bp
    app.register_blueprint(securityhub_bp)

    return app