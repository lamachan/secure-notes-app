from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, login_required, logout_user, current_user
from time import sleep
from datetime import datetime, timedelta

from app import db
from app.models import User
from app.utils import get_b64encoded_qr_image
from app.auth.auth_module import hash_password, verify_password
from app.auth.forms import RegisterForm, LoginForm

auth_bp = Blueprint('auth', __name__)

LOGIN_DISABLED_TIMEOUT = 300

HOME_URL = 'notes.home'
INDEX_URL = 'index.index'
LOGIN_URL = 'auth.login'
SETUP_2FA_URL = 'auth.setup_two_fa'

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        flash('You are already registered.', 'info')
        return redirect(url_for(HOME_URL))
        
    form = RegisterForm(request.form)
    if form.validate_on_submit():
        try:
            password_hash, salt = hash_password(form.password.data)
            new_user = User(username=form.username.data, password=password_hash, salt=salt)
            db.session.add(new_user)
            db.session.commit()

            session['username'] = new_user.username
            flash('Registration successful. Please set up Two-factor authentication in order to log in.', 'success')
            return redirect(url_for(SETUP_2FA_URL))
        except Exception:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'danger')
            return redirect(url_for(LOGIN_URL))

    return render_template('auth/register.html', form=form)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for(HOME_URL))
        
    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            salt = user.salt
            db_password_hash = user.password
            if user.disabled_until and user.disabled_until > datetime.utcnow():
                # login is still disabled due to too many unsuccessful login attempts
                flash(f'Login for this user is disabled. Try again after {user.disabled_until}', 'danger')
                return redirect(url_for(LOGIN_URL))
            elif not verify_password(db_password_hash, form.password.data, salt) or \
                    not user.is_totp_valid(form.totp.data):
                # invalid password or TOTP
                try:
                    user.login_tries += 1
                    db.session.commit()

                    if user.login_tries >= 10:
                        # too many unsuccessful login attempts -> disable login
                        user.disabled_until = datetime.utcnow() + timedelta(seconds=LOGIN_DISABLED_TIMEOUT)
                        user.login_tries = 0
                        db.session.commit()

                        flash(f'Account login is currently disabled due to too many unsuccessful login attempts. Try again later.', 'danger')
                        return redirect(url_for(LOGIN_URL))
                except Exception:
                    db.session.rollback()
                    flash('Login failed. Please try again.', 'danger')
                    return redirect(url_for(LOGIN_URL))

                sleep(1)
                flash('Invalid username, password or TOTP.', 'danger')
                return redirect(url_for(LOGIN_URL))
            else:
                # correct credentials
                try:
                    user.login_tries = 0
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                    flash('Login failed. Please try again.', 'danger')
                    return redirect(url_for(LOGIN_URL))

                login_user(user)

                flash('You are now logged in.', 'success')
                return redirect(url_for(HOME_URL))
        else:
            flash('Invalid username, password or TOTP.', 'danger')
            return redirect(url_for(LOGIN_URL))

    return render_template('auth/login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Successfuly logged out.', 'success')
    return redirect(url_for(INDEX_URL))

@auth_bp.route('/setup-2fa')
def setup_two_fa():
    if 'username' not in session:
        return redirect(url_for(INDEX_URL))
    
    user = User.query.filter_by(username=session['username']).first()
    del session['username']
    if user is None:
        return redirect(url_for(INDEX_URL))
    
    two_fa_secret = user.two_fa_secret
    uri = user.get_two_fa_uri()
    base64_qr_image = get_b64encoded_qr_image(uri)

    return render_template('auth/setup-2fa.html', secret=two_fa_secret, qr_image=base64_qr_image), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}