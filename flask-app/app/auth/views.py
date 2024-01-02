from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, login_required, logout_user, current_user

from app import db
from app.models import User
from app.utils import get_b64encoded_qr_image
from app.auth.auth_module import hash_password, verify_password
from app.auth.forms import RegisterForm, LoginForm, TwoFactorForm

auth_bp = Blueprint('auth', __name__)

HOME_URL = 'notes.home'
INDEX_URL = 'index.index'
SETUP_2FA_URL = 'auth.setup_two_fa'
VERIFY_2FA_URL = 'auth.verify_two_fa'

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        if current_user.two_fa_enabled:
            flash('You are already registered.', 'info')
            return redirect(url_for(HOME_URL))
        else:
            flash('Two-factor authentication is not enabled. Please set up 2FA in order to log in.')
            return redirect(url_for(SETUP_2FA_URL))
        
    form = RegisterForm(request.form)
    if form.validate_on_submit():
        try:
            password_hash, salt = hash_password(form.password.data)
            new_user = User(username=form.username.data, password=password_hash, salt=salt)
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            flash('Registration successful. Please set up Two-factor authentication in order to log in.', 'success')

            return redirect(url_for(SETUP_2FA_URL))
        except Exception:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'danger')

    return render_template('auth/register.html', form=form)
    # if request.method == 'POST':
    #     username = request.form.get('username')
    #     password = request.form.get('password')
    #     repeat_password = request.form.get('repeat_password')

    #     user = User.query.filter_by(username=username).first()
    #     if user:
    #         print('Username is already taken.')
    #     elif len(username) < 5:
    #         print('Username must be at least 4 characters long.')
    #     elif password != repeat_password:
    #         print('The provided passwords do not match.')
    #     else:
    #         password_hash, salt = hash_password(password)
    #         new_user = User(username=username, password=password_hash, salt=salt)
    #         db.session.add(new_user)
    #         db.session.commit()

    #         print('Account has been created.')
    #         login_user(new_user, remember=True)
    #         return redirect('/home')
            
    # return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.two_fa_enabled:
            flash('You are already logged in.', 'info')
            return redirect(url_for(HOME_URL))
        else:
            flash('Two-factor authentication is not enabled. Please set up 2FA in order to log in.')
            return redirect(url_for(SETUP_2FA_URL))
        
    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            salt = user.salt
            db_password_hash = user.password
            if verify_password(db_password_hash, form.password.data, salt):
                login_user(user)
                if not current_user.two_fa_enabled:
                    flash('Two-factor authentication is not enabled. Please set up 2FA in order to log in.')
                    return redirect(url_for(SETUP_2FA_URL))
                return redirect(url_for(VERIFY_2FA_URL))
            else:
                flash('Invalid username or password.', 'danger')
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('auth/login.html', form=form)
        
    # if request.method == 'POST':
    #     username = request.form.get('username')
    #     password = request.form.get('password')

    #     user = User.query.filter_by(username=username).first()
    #     if user:
    #         salt = user.salt
    #         db_password_hash = user.password
    #         if verify_password(db_password_hash, password, salt):
    #             print('Correct password.')
    #             login_user(user, remember=True)
    #             return redirect('/home')
    #         else:
    #             print('Incorrect password.')
    #     else:
    #         print('User of provided username does not exist.')

    # return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Successfuly logged out.', 'success')
    return redirect(url_for(INDEX_URL))

@auth_bp.route('/setup-2fa')
@login_required
def setup_two_fa():
    two_fa_secret = current_user.two_fa_secret
    uri = current_user.get_two_fa_uri()
    base64_qr_image = get_b64encoded_qr_image(uri)
    return render_template('auth/setup-2fa.html', secret=two_fa_secret, qr_image=base64_qr_image)

@auth_bp.route('/verify-2fa', methods=['GET', 'POST'])
@login_required
def verify_two_fa():
    form = TwoFactorForm(request.form)
    if form.validate_on_submit():
        if current_user.is_totp_valid(form.totp.data):
            if current_user.two_fa_enabled:
                flash('2FA verified. Successfully logged in.', 'success')
                return redirect(url_for(HOME_URL))
            else:
                try:
                    # first 2FA validation after 2FA setup
                    current_user.two_fa_enabled = True
                    db.session.commit()
                    flash('2FA setup successful. Successfully logged in.', 'success')
                    return redirect(url_for(HOME_URL))
                except Exception:
                    db.session.rollback()
                    flash('2FA setup failed. Please try again.', 'danger')
                    return redirect(url_for(VERIFY_2FA_URL))
        else:
            flash('Invalid TOTP. Please try again.', 'danger')
            return redirect(url_for(VERIFY_2FA_URL))
    else:
        if not current_user.two_fa_enabled:
            flash('You have not enabled 2-Factor Authentication. Please enable it first.', 'info')
        return render_template('auth/verify-2fa.html', form=form)