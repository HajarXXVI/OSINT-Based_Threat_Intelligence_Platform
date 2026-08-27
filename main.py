from flask import Flask, render_template, redirect, url_for, request, flash, session, Response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from sqlalchemy import inspect, text
from config import Config
from models import db, User, ScanResult
from engine.correlator import analyze_target
import json
import socket
import threading
import uuid
import time
from datetime import datetime, timezone

app = Flask(__name__)
app.config.from_object(Config)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///threatlens.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions with the app
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# --- Async scan jobs: task_id -> {"lines": [...], "done": bool, "result_url": str} ---
SCAN_JOBS = {}


def _report_job(job_id, message):
    if job_id in SCAN_JOBS:
        SCAN_JOBS[job_id]["lines"].append(message)


def check_password(stored, candidate):
    try:
        return bcrypt.check_password_hash(stored, candidate)
    except ValueError:
        # Legacy rows stored before bcrypt migration: compare in plain text
        return stored == candidate


# --- Template Filters (Registered Before Routes) ---

@app.template_filter('parse_json_field')
def parse_json_field(json_str, field_name, full_str=None):
    if not json_str:
        return 'N/A'
    try:
        data = json.loads(json_str) if isinstance(json_str, str) else json_str
        val = data.get(field_name)
        if val is None:
            return 'N/A'
        if isinstance(val, list):
            if not val:
                return 'None detected'
            return ', '.join(map(str, val))
        return str(val)
    except Exception:
        return 'N/A'

@app.template_filter('from_json_safe')
def from_json_safe(json_str):
    try:
        return json.loads(json_str) if isinstance(json_str, str) else json_str
    except Exception:
        return {}


def validate_target(target):
    """
    Rejects targets that cannot exist before a scan runs, so a misspelled
    domain or malformed IP never produces a misleading "clean target" report.
    Returns (validated_target, error_message).
    """
    clean = str(target or '').strip()
    if not clean:
        return None, 'Please enter an IP address or domain name.'

    # Bare IPv4 literal: must be exactly 4 octets, each between 0 and 255
    if clean.replace('.', '').isdigit():
        octets = clean.split('.')
        if len(octets) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in octets):
            return clean, None
        return None, f'"{clean}" is not a valid IPv4 address.'

    # Domain: must resolve to at least one IP
    try:
        socket.gethostbyname(clean)
        return clean, None
    except Exception:
        return None, f'Domain "{clean}" could not be resolved. Check the spelling or try an IP address.'


# --- Routes ---

@app.route('/')
@login_required
def index():
    recent_scans = (ScanResult.query
                    .filter_by(user_id=current_user.id)
                    .order_by(ScanResult.scan_date.desc())
                    .limit(5).all())
    return render_template('index.html', active_page='home', recent_scans=recent_scans)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and check_password(user.password, password):
            login_user(user)
            session['username'] = user.username
            return redirect(url_for('index'))
        else:
            flash('Invalid Username or Security Cipher.', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already registered in database.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, password=bcrypt.generate_password_hash(password).decode('utf-8'))
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        session['username'] = new_user.username
        flash('Registration successful!', 'success')
        return redirect(url_for('index'))

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('Session terminated. User logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        current_user.theme = request.form.get('theme', 'cyan')
        current_user.enable_particles = 'enable_particles' in request.form
        current_user.enable_crt = 'enable_crt' in request.form

        db.session.commit()
        flash('Visual preferences updated successfully!', 'success')
        return redirect(url_for('settings'))

    return render_template('settings.html', active_page='settings')

@app.route('/settings/security', methods=['POST'])
@login_required
def settings_security():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')

    if not check_password(current_user.password, current_password):
        flash('Current password is incorrect.', 'danger')
    elif not new_password or len(new_password) < 8:
        flash('New password must be at least 8 characters long.', 'danger')
    else:
        current_user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()
        flash('Password updated successfully.', 'success')

    return redirect(url_for('settings'))

@app.route('/settings/intel', methods=['POST'])
@login_required
def settings_intel():
    current_user.virustotal_key = request.form.get('virustotal_key', '').strip()
    current_user.abuseipdb_key = request.form.get('abuseipdb_key', '').strip()
    current_user.shodan_key = request.form.get('shodan_key', '').strip()
    db.session.commit()
    flash('Threat intelligence keys saved successfully.', 'success')
    return redirect(url_for('settings'))

@app.route('/settings/alerts', methods=['POST'])
@login_required
def settings_alerts():
    current_user.alert_threshold = request.form.get('alert_threshold', 'HIGH')
    current_user.webhook_url = request.form.get('webhook_url', '').strip()
    db.session.commit()
    flash('Alert rules & webhooks saved successfully.', 'success')
    return redirect(url_for('settings'))

@app.route('/control-panel')
@login_required
def control_panel():
    if current_user.role != 'admin':
        flash('Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('control_panel.html', users=users, active_page='control_panel')

@app.route('/delete-user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Admin privileges required.', 'danger')
        return redirect(url_for('index'))

    user_to_delete = db.session.get(User, user_id)
    if not user_to_delete:
        flash('User not found.', 'danger')
    elif user_to_delete.id == current_user.id:
        flash('You cannot delete your own account.', 'warning')
    else:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f'User ID #{user_id} deleted successfully.', 'success')
    return redirect(url_for('control_panel'))

@app.route('/history')
@login_required
def history():
    scans = (ScanResult.query
             .filter_by(user_id=current_user.id)
             .order_by(ScanResult.scan_date.desc())
             .all())
    return render_template('history.html', scans=scans, active_page='history')

@app.route('/delete-scan/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan = db.session.get(ScanResult, scan_id)
    if scan and scan.user_id == current_user.id:
        db.session.delete(scan)
        db.session.commit()
        flash('Scan deleted from history.', 'success')
    return redirect(url_for('history'))

@app.route('/scan', methods=['POST'])
@login_required
def scan_target():
    target = request.form.get('target')
    validated_target, error = validate_target(target)
    if error:
        flash(error, 'danger')
        return redirect(url_for('index'))

    # Per-user API keys take priority, falling back to the .env / Config keys
    shodan_key = (current_user.shodan_key
                  or app.config.get('SHODAN_API_KEY')
                  or getattr(Config, 'SHODAN_API_KEY', None))
    vt_key = (current_user.virustotal_key
              or app.config.get('VIRUSTOTAL_API_KEY')
              or getattr(Config, 'VIRUSTOTAL_API_KEY', None))
    nvd_key = (app.config.get('NVD_API_KEY')
               or getattr(Config, 'NVD_API_KEY', None))

    # Launch the scan on a background thread so the browser can stream progress.
    job_id = uuid.uuid4().hex
    owner_id = current_user.id  # capture before the thread (thread has no request context)
    SCAN_JOBS[job_id] = {"target": validated_target, "lines": [], "done": False, "result_url": None, "error": None}

    def run_scan():
        try:
            scan_data = analyze_target(
                validated_target,
                shodan_api_key=shodan_key,
                vt_api_key=vt_key,
                nvd_api_key=nvd_key,
                progress_callback=lambda msg: _report_job(job_id, msg),
            )
            with app.app_context():
                # Save results to SQLite database
                new_scan = ScanResult(
                    user_id=owner_id,
                    target=validated_target,
                    scan_date=datetime.now(timezone.utc),
                    geolocation_data=json.dumps(scan_data['geolocation']),
                    shodan_data=json.dumps(scan_data['shodan']),
                    vt_data=json.dumps(scan_data['virustotal']),
                    whois_data=json.dumps(scan_data['whois_data']),
                    ssl_data=json.dumps(scan_data['ssl_data']),
                    dns_data=json.dumps(scan_data.get('dns_data', {})),
                    findings_data=json.dumps(scan_data.get('findings', [])),
                    risk_score=scan_data['risk_score'],
                    risk_level=scan_data['risk_level'],
                    risk_color=scan_data.get('risk_color', '#38bdf8'),
                    exposure_index=scan_data.get('exposure_index', 0.0),
                    threat_index=scan_data.get('threat_index', 0.0),
                    exposure_band=scan_data.get('exposure_band', 'LOW'),
                    threat_band=scan_data.get('threat_band', 'LOW'),
                    profile=scan_data.get('profile', 'Low Concern — Apparently Sound Resource')
                )
                db.session.add(new_scan)
                db.session.commit()
                # Background thread has no request context, so build the
                # report URL from the fixed route instead of url_for().
                SCAN_JOBS[job_id]["result_url"] = f"/scan/{new_scan.id}"
        except Exception as e:
            SCAN_JOBS[job_id]["error"] = str(e)
        finally:
            SCAN_JOBS[job_id]["done"] = True

    threading.Thread(target=run_scan, daemon=True).start()
    return redirect(url_for('scan_progress', job_id=job_id))


@app.route('/scan/progress/<job_id>')
@login_required
def scan_progress(job_id):
    if job_id not in SCAN_JOBS:
        flash('Scan job not found or already finished.', 'danger')
        return redirect(url_for('index'))
    return render_template('scan_progress.html', job_id=job_id, target=SCAN_JOBS[job_id]["target"], active_page='home')


@app.route('/scan/progress/<job_id>/stream')
@login_required
def scan_progress_stream(job_id):
    def generate():
        sent = 0
        while True:
            job = SCAN_JOBS.get(job_id)
            if job is None:
                yield "event: error\ndata: job-expired\n\n"
                return
            lines = job["lines"]
            while sent < len(lines):
                yield f"data: {json.dumps({'line': lines[sent]})}\n\n"
                sent += 1
            if job["done"]:
                if job["error"]:
                    yield f"event: error\ndata: {json.dumps({'error': job['error']})}\n\n"
                else:
                    yield f"event: done\ndata: {json.dumps({'url': job['result_url']})}\n\n"
                return
            time.sleep(0.25)

    return Response(generate(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',
        'Connection': 'keep-alive',
    })

@app.route('/scan/<int:scan_id>')
@login_required
def view_scan_details(scan_id):
    scan = db.session.get(ScanResult, scan_id)
    if not scan:
        flash('Scan result not found or expired.', 'danger')
        return redirect(url_for('index'))

    # Parse stored JSON fields safely
    def safe_json(data):
        if not data:
            return {}
        try:
            return json.loads(data) if isinstance(data, str) else data
        except Exception:
            return {}

    shodan_dict = safe_json(scan.shodan_data)
    geo_dict = safe_json(scan.geolocation_data)
    vt_dict = safe_json(scan.vt_data)
    dns_dict = safe_json(scan.dns_data)
    findings_list = safe_json(scan.findings_data)
    if not isinstance(findings_list, list):
        findings_list = []

    # Band colors for the Exposure/Threat profile bars
    profile_colors = {
        'LOW': '#28a745',
        'MEDIUM': '#ffc107',
        'HIGH': '#fd7e14',
        'CRITICAL': '#dc3545'
    }
    exposure_color = profile_colors.get(getattr(scan, 'exposure_band', None) or 'LOW', '#38bdf8')
    threat_color = profile_colors.get(getattr(scan, 'threat_band', None) or 'LOW', '#38bdf8')

    # WHOIS & SSL records only exist for domain names, not for IPs.
    # Tell the template so those widgets are hidden (not shown as N/A) for IPs.
    def _is_ip_address(target):
        clean = str(target or '').replace('https://', '').replace('http://', '').split('/')[0]
        return '.' in clean and clean.replace('.', '').isdigit()

    target_is_ip = _is_ip_address(scan.target)

    # When Shodan reports no exposed ports AND no detected CVEs, show the user
    # WHY the infrastructure score is low instead of leaving them to wonder.
    # A low passive score does not prove a host is secure — it may simply be a
    # web app whose flaws are invisible to passive OSINT (they only appear under
    # active crawling), or a host hidden behind a CDN/WAF.
    no_ports = not (shodan_dict.get('ports') or [])
    no_cves = not (shodan_dict.get('enriched_vulns') or [])
    show_osint_explainer = bool(no_ports and no_cves)

    # When nothing was detected, soften the still-shown score so the page does
    # not read as a green "this host is safe". Reuse the numeric score for
    # consistency but neutralize its color and the profile verdict.
    if show_osint_explainer:
        score_color = '#94a3b8'            # neutral slate
        score_level = 'NO SIGNAL'          # not LOW
        verdict = 'No Passive Signals Detected'
        bar_exposure_color = '#94a3b8'
        bar_threat_color = '#94a3b8'
    else:
        score_color = scan.risk_color or '#38bdf8'
        score_level = scan.risk_level or 'LOW'
        verdict = scan.profile or 'Low Concern — Apparently Sound Resource'
        bar_exposure_color = exposure_color
        bar_threat_color = threat_color

    return render_template(
        'target_details.html',
        scan=scan,
        shodan=shodan_dict,
        geolocation=geo_dict,
        virustotal=vt_dict,
        dns=dns_dict,
        findings=findings_list,
        exposure_color=bar_exposure_color,
        threat_color=bar_threat_color,
        target_is_ip=target_is_ip,
        show_osint_explainer=show_osint_explainer,
        display_score_level=score_level,
        display_score_color=score_color,
        display_verdict=verdict,
        active_page='home'
    )


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Lightweight migration: add any missing columns to existing DBs
        inspector = inspect(db.engine)
        columns = [c['name'] for c in inspector.get_columns('scan_result')]
        scan_migrations = {
            'findings_data': 'ALTER TABLE scan_result ADD COLUMN findings_data TEXT',
            'whois_data': 'ALTER TABLE scan_result ADD COLUMN whois_data TEXT',
            'ssl_data': 'ALTER TABLE scan_result ADD COLUMN ssl_data TEXT',
            'dns_data': 'ALTER TABLE scan_result ADD COLUMN dns_data TEXT',
            'risk_color': 'ALTER TABLE scan_result ADD COLUMN risk_color VARCHAR(20)',
            'exposure_index': 'ALTER TABLE scan_result ADD COLUMN exposure_index FLOAT DEFAULT 0.0',
            'threat_index': 'ALTER TABLE scan_result ADD COLUMN threat_index FLOAT DEFAULT 0.0',
            'exposure_band': "ALTER TABLE scan_result ADD COLUMN exposure_band VARCHAR(20) DEFAULT 'LOW'",
            'threat_band': "ALTER TABLE scan_result ADD COLUMN threat_band VARCHAR(20) DEFAULT 'LOW'",
            'profile': "ALTER TABLE scan_result ADD COLUMN profile VARCHAR(120) DEFAULT 'Low Concern — Apparently Sound Resource'",
        }
        for column, ddl in scan_migrations.items():
            if column not in columns:
                db.session.execute(text(ddl))
                db.session.commit()

        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            default_admin = User(
                username='admin',
                password=bcrypt.generate_password_hash('adminpassword123').decode('utf-8'),
                role='admin'
            )
            db.session.add(default_admin)
            db.session.commit()
        else:
            admin_user.role = 'admin'
            db.session.commit()

    app.run(debug=True, use_reloader=False, threaded=True)