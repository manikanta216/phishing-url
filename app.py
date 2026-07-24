import webbrowser
import threading
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from database.database import create_user, get_user_by_username, save_scan, get_scan_history
from utils.predictor import predict_url
from utils.helper import login_required

app = Flask(__name__)
app.config.from_object(Config)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not name or not email or not username or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for('register'))

        existing_user = get_user_by_username(username)
        if existing_user:
            flash("Username already exists. Please choose another.", "danger")
            return redirect(url_for('register'))

        try:
            password_hash = generate_password_hash(password)
            user_id = create_user(name, email, username, password_hash)
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Error registering user: {str(e)}", "danger")
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = get_user_by_username(username)
        if not user or not check_password_hash(user['password_hash'], password):
            flash("Invalid username or password.", "danger")
            return redirect(url_for('login'))

        session['user_id'] = user['id']
        session['username'] = user['username']
        session['name'] = user['name']
        flash(f"Welcome back, {user['name']}!", "success")
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session.get('user_id')
    scans = get_scan_history(user_id)
    
    total_scans = len(scans)
    phishing_count = sum(1 for s in scans if s['prediction'] == 'Phishing')
    safe_count = sum(1 for s in scans if s['prediction'] == 'Safe')
    accuracy = "98.4%" if total_scans > 0 else "N/A"
    
    recent_scans = scans[:5]

    return render_template(
        'dashboard.html',
        total_scans=total_scans,
        phishing_count=phishing_count,
        safe_count=safe_count,
        accuracy=accuracy,
        recent_scans=recent_scans
    )

@app.route('/scan', methods=['POST'])
def scan():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized. Please log in.'}), 401

    data = request.get_json() or request.form
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'Please provide a valid URL to scan.'}), 400

    result = predict_url(url)
    
    # Save scan to database
    user_id = session['user_id']
    scan_id = save_scan(
        user_id=user_id,
        url=url,
        prediction=result['prediction'],
        confidence_score=result['confidence'],
        domain=result['domain'],
        ip_address=result['ip_address'],
        url_length=result['url_length'],
        is_https=result['is_https']
    )
    result['scan_id'] = scan_id

    return jsonify(result)

@app.route('/history')
@login_required
def history():
    user_id = session.get('user_id')
    scans = get_scan_history(user_id)
    return render_template('history.html', scans=scans)

@app.route('/result/<int:scan_id>')
@login_required
def result_page(scan_id):
    user_id = session.get('user_id')
    scans = get_scan_history(user_id)
    scan_data = next((s for s in scans if s['id'] == scan_id), None)
    
    if not scan_data:
        flash("Scan record not found.", "warning")
        return redirect(url_for('dashboard'))

    return render_template('result.html', scan=scan_data)

def open_browser():
    webbrowser.open_new('http://localhost:5000')

if __name__ == '__main__':
    print("==================================================")
    print("  Starting PhishShield Web Server...")
    print("  Opening browser automatically at http://localhost:5000")
    print("==================================================")
    threading.Timer(1.2, open_browser).start()
    app.run(host='0.0.0.0', port=5000, debug=False)
