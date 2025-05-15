from flask import Blueprint, render_template, redirect, url_for, flash, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user

from app.utils import save_log_hash
from .models import User
from . import db, bcrypt
import random
from flask import session
from app import limiter


auth = Blueprint('auth', __name__)
import os
import datetime
from flask import current_app

from app import LOGS_DIR

def log_failed_mfa_attempt(user_id, wrong_code):
    log_path = os.path.join(LOGS_DIR, 'mfa', 'mfa_attempts.txt')
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_path, 'a') as f:
        f.write(f"[{timestamp}] MFA FAILED | User ID: {user_id} | Entered Code: {wrong_code}\n")
        
    save_log_hash(log_path)



@auth.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.predict'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if not user or not bcrypt.check_password_hash(user.password, password):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('auth.login'))

        # Step 1: store user ID for MFA
        session['pre_auth_user'] = user.id
        # Step 2: generate OTP
        session['otp_code'] = str(random.randint(100000, 999999))
        print("Generated MFA code:", session['otp_code'])  # for dev/testing
        return redirect(url_for('auth.mfa'))

    return render_template('login.html')


@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.predict'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('auth.register'))
            
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('auth.register'))
            
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('auth.login'))
        
    return render_template('register.html')


@auth.route('/mfa', methods=['GET', 'POST'], endpoint='mfa')
@limiter.limit("5 per minute")
def mfa():
    # Cooldown check
    locked_until = session.get('mfa_locked_until')
    if locked_until:
        now = datetime.datetime.now().timestamp()
        if now < locked_until:
            remaining = int(locked_until - now)
            flash(f'You must wait {remaining} seconds before trying again.', 'danger')
            return render_template('mfa.html')
        else:
            session.pop('mfa_locked_until')
            session['mfa_attempts'] = 0  # reset attempts

    if 'pre_auth_user' not in session:
        flash('Session expired. Please login again.', 'danger')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code = request.form.get('code')

        # Track attempts
        session['mfa_attempts'] = session.get('mfa_attempts', 0) + 1

        if code == session.get('otp_code'):
            from app.models import User
            user = User.query.get(session['pre_auth_user'])
            login_user(user)
            session.permanent = True  # This activates permanent session lifetime


            # Reset session state
            session.pop('otp_code', None)
            session.pop('pre_auth_user', None)
            session.pop('mfa_attempts', None)
            return redirect(url_for('main.predict'))

        else:
            log_failed_mfa_attempt(session['pre_auth_user'], code)
            remaining = 3 - session['mfa_attempts']
            if remaining <= 0:
                session['mfa_locked_until'] = datetime.datetime.now().timestamp() + 30  # 30 sec cooldown
                flash('Too many incorrect attempts. Please wait 30 seconds.', 'danger')
                return redirect(url_for('auth.mfa'))

            else:
                flash(f'Incorrect code. {remaining} attempts remaining.', 'warning')

    return render_template('mfa.html')



@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))