from flask import Flask, render_template, redirect, url_for, request, flash, session, Response, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from sqlalchemy import inspect, text
from config import Config
from models import db, User, ScanResult, AuditLog
from engine.correlator import analyze_target
from engine.pdf_report import generate_pdf_report
from apis.crt_api import discover_subdomains_cached
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
        return None, (f'DNS lookup failed for "{clean}": no IP address is currently '
                      f'registered for this domain (it may be unregistered, removed, '
                      f'or temporarily unavailable). Check the spelling or try an IP address instead.')


def _is_ip_literal(target):
    clean = str(target or '').replace('https://', '').replace('http://', '').split('/')[0]
    return '.' in clean and clean.replace('.', '').isdigit()


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
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    admin_ids = [u.id for u in users if u.role == 'admin']
    # The single remaining admin is protected from deletion in the UI and API.
    last_admin_id = admin_ids[0] if len(admin_ids) == 1 else None
    return render_template('control_panel.html', users=users, audit_logs=audit_logs,
                           last_admin_id=last_admin_id, active_page='control_panel')

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
        remaining_admins = User.query.filter_by(role='admin').count()
        if user_to_delete.role == 'admin' and remaining_admins <= 1:
            flash('Cannot delete the last remaining admin account.', 'warning')
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


@app.route('/analytics')
@login_required
def analytics():
    """
    Aggregates the current user's scan history into datasets that drive
    the Chart.js dashboards: risk trend over time, risk-level distribution,
    Exposure-vs-Threat trend, top targets, scan activity and profile verdicts.
    """
    scans = (ScanResult.query
             .filter_by(user_id=current_user.id)
             .order_by(ScanResult.scan_date.asc())
             .all())

    # Empty state: still render the page with empty datasets so the user sees
    # a consistent layout prompting them to run scans.
    def date_label(dt):
        return dt.strftime('%Y-%m-%d') if dt else 'N/A'

    risk_trend = {
        "labels": [date_label(s.scan_date) for s in scans],
        "scores": [round(s.risk_score or 0) for s in scans],
        "colors": [s.risk_color or '#38bdf8' for s in scans],
        "targets": [s.target for s in scans],
        "levels": [s.risk_level or 'LOW' for s in scans],
    }

    # Distribution of risk levels
    level_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for s in scans:
        lvl = (s.risk_level or 'LOW').upper()
        level_counts[lvl] = level_counts.get(lvl, 0) + 1
    risk_distribution = {
        "labels": list(level_counts.keys()),
        "counts": list(level_counts.values()),
    }

    # Exposure vs Threat index trend
    exp_threat_trend = {
        "labels": [date_label(s.scan_date) for s in scans],
        "exposure": [round(s.exposure_index or 0) for s in scans],
        "threat": [round(s.threat_index or 0) for s in scans],
        "targets": [s.target for s in scans],
    }

    # Top targets by risk score (all-time)
    top_targets_data = {}
    for s in scans:
        tgt = s.target
        if tgt not in top_targets_data or (s.risk_score or 0) > top_targets_data[tgt][0]:
            top_targets_data[tgt] = (s.risk_score or 0, s.risk_color or '#38bdf8')
    ordered = sorted(top_targets_data.items(), key=lambda kv: kv[1][0], reverse=True)[:8]
    top_targets = {
        "labels": [t for t, _ in ordered],
        "scores": [v[0] for _, v in ordered],
        "colors": [v[1] for _, v in ordered],
    }

    # Scan activity: number of scans per day (last 14 days including empty days)
    from collections import Counter
    from datetime import timedelta
    today = datetime.now(timezone.utc).date()
    activity_days = [(today - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(13, -1, -1)]
    counter = Counter(date_label(s.scan_date) for s in scans if s.scan_date)
    activity = {
        "labels": activity_days,
        "counts": [counter.get(d, 0) for d in activity_days],
    }

    # Profile verdict distribution
    profile_counts = {}
    for s in scans:
        p = s.profile or 'Low Concern — Apparently Sound Resource'
        profile_counts[p] = profile_counts.get(p, 0) + 1
    profile_distribution = {
        "labels": list(profile_counts.keys()),
        "counts": list(profile_counts.values()),
    }

    return render_template(
        'analytics.html',
        scans=scans,
        risk_trend=risk_trend,
        risk_distribution=risk_distribution,
        exp_threat_trend=exp_threat_trend,
        top_targets=top_targets,
        activity=activity,
        profile_distribution=profile_distribution,
        active_page='analytics'
    )

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
    # AJAX scans (from the in-page modal) ask for a JSON payload with the job
    # id; classic form posts keep the old redirect-to-progress-page flow.
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    target = request.form.get('target')
    validated_target, error = validate_target(target)
    if error:
        if is_ajax:
            return jsonify({"error": error, "target": target}), 400
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

    # Capture request info for audit logging (before thread)
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    user_agent = request.headers.get('User-Agent', '')
    owner_id = current_user.id
    owner_username = current_user.username

    # Audit log: scan started
    audit = AuditLog(
        user_id=owner_id,
        username=owner_username,
        action='scan_started',
        target=validated_target,
        ip_address=client_ip,
        user_agent=user_agent,
        details=json.dumps({'method': 'ajax' if is_ajax else 'form'})
    )
    db.session.add(audit)
    db.session.commit()

    # Launch the scan on a background thread so the browser can stream progress.
    job_id = uuid.uuid4().hex
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
                # Subdomain discovery runs after the core pipeline so any
                # slowness never delays the 7 main intelligence steps. For
                # IP targets there is no listing; for domains we use the
                # 24h-cached lookup to avoid hammering rate-limited sources.
                subdomains_result = None
                if not _is_ip_literal(validated_target):
                    try:
                        _report_job(job_id, "Subdomain discovery via public certificate transparency logs...")
                        subdomains_result = discover_subdomains_cached(validated_target)
                        if subdomains_result.get('error'):
                            _report_job(job_id, f"Subdomain discovery skipped: {subdomains_result['error']}")
                        else:
                            total_subs = len(subdomains_result.get('subdomains') or [])
                            alive_subs = subdomains_result.get('alive', 0)
                            cached_note = ' (cached)' if subdomains_result.get('cached') else ''
                            _report_job(job_id, f"Subdomains: {total_subs} found, {alive_subs} alive{cached_note}")
                    except Exception as e:
                        subdomains_result = {
                            "enabled": True, "subdomains": [], "total": 0,
                            "checked": 0, "alive": 0, "error": str(e), "cached": False
                        }
                        _report_job(job_id, f"Subdomain discovery skipped: {e}")

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
                    subdomains_data=json.dumps(subdomains_result) if subdomains_result else None,
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

                # Audit log: scan completed
                audit_complete = AuditLog(
                    user_id=owner_id,
                    username=owner_username,
                    action='scan_completed',
                    target=validated_target,
                    scan_id=new_scan.id,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    details=json.dumps({
                        'risk_score': scan_data['risk_score'],
                        'risk_level': scan_data['risk_level'],
                        'findings_count': len(scan_data.get('findings', [])),
                        'subdomains_found': (subdomains_result or {}).get('total', 0)
                    })
                )
                db.session.add(audit_complete)
                db.session.commit()
        except Exception as e:
            SCAN_JOBS[job_id]["error"] = str(e)
            # Audit log: scan failed
            with app.app_context():
                audit_fail = AuditLog(
                    user_id=owner_id,
                    username=owner_username,
                    action='scan_failed',
                    target=validated_target,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    details=json.dumps({'error': str(e)})
                )
                db.session.add(audit_fail)
                db.session.commit()
        finally:
            SCAN_JOBS[job_id]["done"] = True

    threading.Thread(target=run_scan, daemon=True).start()
    if is_ajax:
        return jsonify({"job_id": job_id, "target": validated_target})
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
    subdomains_dict = safe_json(scan.subdomains_data)

    # --- Per-scan chart datasets (derived from the report's own data) ---
    # 1. Correlation findings by severity
    sev_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    sev_counts = {s: 0 for s in sev_order}
    for f in findings_list:
        sev = str(f.get('severity', 'LOW')).upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    chart_findings_by_severity = {
        "labels": sev_order,
        "counts": [sev_counts[s] for s in sev_order],
        "colors": ['#dc3545', '#fd7e14', '#ffc107', '#28a745'],
    }

    # 2. Correlation findings by category (Exposure vs Threat)
    cat_counts = {'EXPOSURE': 0, 'THREAT': 0}
    for f in findings_list:
        cat = str(f.get('category', 'exposure')).upper()
        cat_counts['THREAT' if cat == 'THREAT' else 'EXPOSURE'] += 1
    chart_findings_by_category = {
        "labels": ['EXPOSURE', 'THREAT'],
        "counts": [cat_counts['EXPOSURE'], cat_counts['THREAT']],
        "colors": ['#06b6d4', '#d946ef'],
    }

    # 3. Known CVEs by severity (from Shodan enriched_vulns)
    cve_counts = {s: 0 for s in sev_order}
    for v in (shodan_dict.get('enriched_vulns') or []):
        sev = str(v.get('severity', 'UNKNOWN')).upper()
        if sev not in cve_counts:
            cve_counts[sev] = 0
        cve_counts[sev] += 1
    # Include UNKNOWN only if present
    cve_severities = list(cve_counts.keys())
    cve_counts_ordered = cve_counts
    chart_cves_by_severity = {
        "labels": cve_severities,
        "counts": [cve_counts_ordered[s] for s in cve_severities],
        "colors": ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#64748b'],
    }

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
        subdomains=subdomains_dict,
        display_score_level=score_level,
        display_score_color=score_color,
        display_verdict=verdict,
        chart_findings_by_severity=chart_findings_by_severity,
        chart_findings_by_category=chart_findings_by_category,
        chart_cves_by_severity=chart_cves_by_severity,
        active_page='home'
    )


@app.route('/scan/<int:scan_id>/pdf')
@login_required
def download_scan_pdf(scan_id):
    """Generate and download a professional PDF report for a scan."""
    scan = db.session.get(ScanResult, scan_id)
    if not scan or scan.user_id != current_user.id:
        flash('Scan report not found or access denied.', 'danger')
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

    # Recompute chart data (same logic as view_scan_details)
    sev_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    sev_counts = {s: 0 for s in sev_order}
    for f in findings_list:
        sev = str(f.get('severity', 'LOW')).upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    chart_findings_by_severity = {
        "labels": sev_order,
        "counts": [sev_counts[s] for s in sev_order],
        "colors": ['#dc3545', '#fd7e14', '#ffc107', '#28a745'],
    }

    cat_counts = {'EXPOSURE': 0, 'THREAT': 0}
    for f in findings_list:
        cat = str(f.get('category', 'exposure')).upper()
        cat_counts['THREAT' if cat == 'THREAT' else 'EXPOSURE'] += 1
    chart_findings_by_category = {
        "labels": ['EXPOSURE', 'THREAT'],
        "counts": [cat_counts['EXPOSURE'], cat_counts['THREAT']],
        "colors": ['#06b6d4', '#d946ef'],
    }

    cve_counts = {s: 0 for s in sev_order}
    for v in (shodan_dict.get('enriched_vulns') or []):
        sev = str(v.get('severity', 'UNKNOWN')).upper()
        if sev not in cve_counts:
            cve_counts[sev] = 0
        cve_counts[sev] += 1
    cve_severities = list(cve_counts.keys())
    cve_counts_ordered = cve_counts
    chart_cves_by_severity = {
        "labels": cve_severities,
        "counts": [cve_counts_ordered[s] for s in cve_severities],
        "colors": ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#64748b'],
    }

    # Band colors
    profile_colors = {
        'LOW': '#28a745',
        'MEDIUM': '#ffc107',
        'HIGH': '#fd7e14',
        'CRITICAL': '#dc3545'
    }
    exposure_color = profile_colors.get(getattr(scan, 'exposure_band', None) or 'LOW', '#38bdf8')
    threat_color = profile_colors.get(getattr(scan, 'threat_band', None) or 'LOW', '#38bdf8')

    def _is_ip_address(target):
        clean = str(target or '').replace('https://', '').replace('http://', '').split('/')[0]
        return '.' in clean and clean.replace('.', '').isdigit()

    target_is_ip = _is_ip_address(scan.target)

    no_ports = not (shodan_dict.get('ports') or [])
    no_cves = not (shodan_dict.get('enriched_vulns') or [])
    show_osint_explainer = bool(no_ports and no_cves)

    if show_osint_explainer:
        score_color = '#94a3b8'
        score_level = 'NO SIGNAL'
        verdict = 'No Passive Signals Detected'
        bar_exposure_color = '#94a3b8'
        bar_threat_color = '#94a3b8'
    else:
        score_color = scan.risk_color or '#38bdf8'
        score_level = scan.risk_level or 'LOW'
        verdict = scan.profile or 'Low Concern — Apparently Sound Resource'
        bar_exposure_color = exposure_color
        bar_threat_color = threat_color

    # Generate PDF
    pdf_bytes = generate_pdf_report(
        scan=scan,
        shodan_dict=shodan_dict,
        geo_dict=geo_dict,
        vt_dict=vt_dict,
        dns_dict=dns_dict,
        findings_list=findings_list,
        exposure_color=exposure_color,
        threat_color=threat_color,
        target_is_ip=target_is_ip,
        display_score_level=score_level,
        display_score_color=score_color,
        display_verdict=verdict,
        chart_findings_by_severity=chart_findings_by_severity,
        chart_findings_by_category=chart_findings_by_category,
        chart_cves_by_severity=chart_cves_by_severity,
    )

    # Return PDF response
    from flask import make_response
    response = make_response(pdf_bytes)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=threatlens-report-{scan.target}-{scan.id}.pdf'
    return response


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Create audit_log table if it doesn't exist (new table migration)
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        if 'audit_log' not in tables:
            db.session.execute(text("""
                CREATE TABLE audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    username VARCHAR(80) NOT NULL,
                    action VARCHAR(50) NOT NULL,
                    target VARCHAR(100),
                    scan_id INTEGER,
                    ip_address VARCHAR(45),
                    user_agent VARCHAR(255),
                    details TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """))
            db.session.commit()

        # Lightweight migration: add any missing columns to existing DBs
        inspector = inspect(db.engine)
        columns = [c['name'] for c in inspector.get_columns('scan_result')]
        scan_migrations = {
            'findings_data': 'ALTER TABLE scan_result ADD COLUMN findings_data TEXT',
            'whois_data': 'ALTER TABLE scan_result ADD COLUMN whois_data TEXT',
            'ssl_data': 'ALTER TABLE scan_result ADD COLUMN ssl_data TEXT',
            'dns_data': 'ALTER TABLE scan_result ADD COLUMN dns_data TEXT',
            'subdomains_data': 'ALTER TABLE scan_result ADD COLUMN subdomains_data TEXT',
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

        # Migrate French profile verdicts to English
        french_to_english = {
            'Faible Pr�occupation': 'Low Concern',
            'Faible Pr\\u00e9occupation': 'Low Concern',
            'Faible Pr\u00e9occupation': 'Low Concern',
            'Faible Pr\u00e9occupation \u2014 Ressource A Priori Saine': 'Low Concern — Apparently Sound Resource',
            'Faible Pr\u00e9occupation — Ressource A Priori Saine': 'Low Concern — Apparently Sound Resource',
            'Cible Expos\u00e9e ET Acteur de Menace Potentiel': 'Exposed AND Potential Threat Actor',
            'Cible Expos�e ET Acteur de Menace Potentiel': 'Exposed AND Potential Threat Actor',
            'Cible Expos\u00e9e ET Acteur de Menace Potentiel': 'Exposed AND Potential Threat Actor',
            'Pr\u00e9occupation Mod\u00e9r\u00e9e': 'Moderate Concern',
            'Pr\u00e9occupation Mod\u00e9r\u00e9e': 'Moderate Concern',
            'Moderate Concern': 'Moderate Concern',
        }
        for fr, en in french_to_english.items():
            updated = ScanResult.query.filter(ScanResult.profile == fr).update({ScanResult.profile: en})
            if updated:
                db.session.commit()
                print(f'Migrated {updated} profile(s): "{fr}" -> "{en}"')

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