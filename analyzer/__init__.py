from flask import Blueprint

analyzer_bp = Blueprint('analyzer', __name__, template_folder='../templates/analyzer')

from analyzer import routes
