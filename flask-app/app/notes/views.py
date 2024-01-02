from flask import Blueprint, render_template
from flask_login import login_required

notes_bp = Blueprint('notes', __name__)

@notes_bp.route('/home')
@login_required
def home():
    return render_template('notes/home.html')