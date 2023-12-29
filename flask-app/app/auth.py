from flask import Blueprint, render_template, request, redirect
from flask_login import login_user, login_required, logout_user, current_user

from . import db
from .models import User
from .auth_module import hash_password, verify_password

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user:
            salt = user.salt
            db_password_hash = user.password
            if verify_password(db_password_hash, password, salt):
                login_user(user, remember=True)
                return redirect('/home')

    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/index')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    # TODO
    return render_template('register.html')