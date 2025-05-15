from flask import Blueprint, render_template, request, flash, current_app,redirect, url_for
from flask_login import login_required, current_user
from . import model, scaler,LOGS_DIR
import numpy as np
import datetime
import os
from .models import User


def is_suspicious_input(data):
    glucose, bp, bmi, age = data
    if glucose < 50 or glucose > 300:
        return True
    if bp < 40 or bp > 200:
        return True
    if bmi < 10 or bmi > 60:
        return True
    if age < 1 or age > 120:
        return True
    return False

from app.utils import save_log_hash

def log_suspicious_input(user, data):
    log_path = os.path.join(LOGS_DIR, 'prediction', 'suspicious_inputs.txt')
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    with open(log_path, 'a') as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] User: {user.username} | Input: {data}\n")

    save_log_hash(log_path)




main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/predict', methods=['GET', 'POST'])
@login_required
def predict():
    prediction = None
    suspicious = False

    if request.method == 'POST':
        try:
            features = [
                float(request.form['glucose']),
                float(request.form['bp']),
                float(request.form['bmi']),
                float(request.form['age'])
            ]
            print(f"Received features: {features}")
            if is_suspicious_input(features):
                suspicious = True
                if suspicious:
                    log_suspicious_input(current_user, features)
                    flash('Warning: Suspicious input detected. This attempt has been logged.', 'warning')
                    return render_template('predict.html', prediction=None)

            scaled_features = scaler.transform([features])
            prediction = model.predict(scaled_features)[0]

        except ValueError:
            flash('Please enter valid numbers for all fields', 'danger')
        except Exception as e:
            flash('An error occurred during prediction', 'danger')
            print(f"Prediction error: {str(e)}")

    return render_template('predict.html', prediction=prediction)

@main.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash("Access denied: Admins only", "danger")
        return redirect(url_for('main.index'))

    users = User.query.all()
    return render_template('admin_users.html', users=users)


@main.route('/logs')
@login_required
def logs():
    if not current_user.is_admin:
        flash("Access denied: Admins only", "danger")
        return render_template("index.html")

    log_path = os.path.join(LOGS_DIR, 'prediction', 'suspicious_inputs.txt')
    if not os.path.exists(log_path):
        return render_template('logs.html', log_data="Log file not found.")

    with open(log_path, 'r') as f:
        log_data = f.read()
    return render_template('logs.html', log_data=log_data)

from flask import send_file

@main.route('/download-log/<log_type>')
@login_required
def download_log(log_type):
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('main.index'))

    filename = "suspicious_inputs.txt" if log_type == "prediction" else "mfa_attempts.txt"
    log_path = os.path.abspath(os.path.join(LOGS_DIR, log_type, filename))

    if os.path.exists(log_path):
        return send_file(log_path, as_attachment=True)
    else:
        flash("Log file not found.", "warning")
        return redirect(url_for('main.index'))


@main.route('/mfa-logs')
@login_required
def mfa_logs():
    if not current_user.is_admin:
        flash("Access denied: Admins only", "danger")
        return render_template("index.html")

    log_path = os.path.join(LOGS_DIR, 'mfa', 'mfa_attempts.txt')
    if not os.path.exists(log_path):
        return render_template('logs.html', log_data="No MFA logs found.")

    with open(log_path, 'r') as f:
        log_data = f.read()
    return render_template('logs.html', log_data=log_data)


@main.route('/verify-log/<log_type>')
@login_required
def verify_log(log_type):
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('main.index'))

    filename = "suspicious_inputs.txt" if log_type == "prediction" else "mfa_attempts.txt"
    log_path = os.path.abspath(os.path.join(LOGS_DIR, log_type, filename))
    hash_path = log_path + ".hash"

    if not os.path.exists(log_path) or not os.path.exists(hash_path):
        flash("Log or hash file not found.", "warning")
        return redirect(url_for('main.index'))

    try:
        from app.utils import hash_log_file
        current_hash = hash_log_file(log_path)
        with open(hash_path, 'r') as hf:
            stored_hash = hf.read().strip()

        if current_hash == stored_hash:
            flash("✅ Log file integrity verified. No tampering detected.", "success")
        else:
            flash("❌ Warning: Log file hash mismatch. Possible tampering detected.", "danger")
    except Exception as e:
        flash(f"Error verifying log integrity: {str(e)}", "danger")

    return redirect(url_for('main.logs' if log_type == "prediction" else 'main.mfa_logs'))
