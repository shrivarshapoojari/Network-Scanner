from flask import Blueprint

scanner_bp = Blueprint('scanner', __name__, template_folder='../templates/scanner')

from scanner import routes
