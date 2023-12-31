from flask import Blueprint, render_template, request, redirect
from flask_login import login_user, login_required, logout_user, current_user

from . import db
from .models import User
from .auth_module import hash_password, verify_password

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        repeat_password = request.form.get('repeat_password')

        user = User.query.filter_by(username=username).first()
        if user:
            print('Username is already taken.')
        elif len(username) < 5:
            print('Username must be at least 4 characters long.')
        elif password != repeat_password:
            print('The provided passwords do not match.')
        else:
            password_hash, salt = hash_password(password)
            new_user = User(username=username, password=password_hash, salt=salt)
            db.session.add(new_user)
            db.session.commit()

            print('Account has been created.')
            login_user(new_user, remember=True)
            return redirect('/home')
            
    return render_template('register.html')

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
                print('Correct password.')
                login_user(user, remember=True)
                return redirect('/home')
            else:
                print('Incorrect password.')
        else:
            print('User of provided username does not exist.')

    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/index')