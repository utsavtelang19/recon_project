import os
import json
import socket
import subprocess
import ftplib
import csv
import io
from datetime import datetime, date, timedelta

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, Response
from config import (
    SECRET_KEY, DATABASE_URI, ACTIVE_DB_TYPE,
    ADMIN_USERNAME, ADMIN_EMAIL, ADMIN_PASSWORD,
    PLAN_LIMITS, PLAN_NAMES, PLAN_PRICING
)
from models import db, User, ScanLog
from auth import auth_bp, login_required, admin_required, get_current_user
from admin_routes import admin_bp

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_folder=os.path.join(BASE_DIR, 'static')
)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)

# Register Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)

# Context processor for templates
@app.context_processor
def inject_global_vars():
    user = get_current_user()
    return {
        'current_user': user,
        'active_db_type': ACTIVE_DB_TYPE,
        'plan_limits': PLAN_LIMITS,
        'plan_names': PLAN_NAMES,
        'plan_pricing': PLAN_PRICING
    }

def init_database():
    """Creates database tables and seeds initial administrator if absent."""
    try:
        with app.app_context():
            db.create_all()
            # Check if any admin exists
            admin = User.query.filter_by(role='admin').first()
            if not admin:
                admin = User(
                    username=ADMIN_USERNAME,
                    email=ADMIN_EMAIL,
                    role='admin',
                    plan_tier='lifetime',
                    daily_limit=PLAN_LIMITS['lifetime'],
                    checks_today=0,
                    is_active=True
                )
                admin.set_password(ADMIN_PASSWORD)
                db.session.add(admin)
                db.session.commit()
                print(f"[Init] Created default administrator: '{ADMIN_USERNAME}'.")
            else:
                print(f"[Init] Database ready. Active Admin account exists: '{admin.username}'.")
    except Exception as e:
        print(f"[Init Database Warning] {e}")

def run_command(command_list, timeout=15):
    """Safely executes a system command and returns output string."""
    try:
        result = subprocess.run(command_list, capture_output=True, text=True, timeout=timeout)
        return result.stdout if result.stdout else result.stderr
    except subprocess.TimeoutExpired:
        return "Command timed out."
    except Exception as e:
        return f"Execution error: {str(e)}"

# ==========================================
# PAGE ROUTES
# ==========================================

@app.route('/')
def home():
    user = get_current_user()
    if not user:
        return redirect(url_for('auth.login'))
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    user.reset_quota_if_new_day()
    time_info = User.get_time_until_midnight()
    
    # Recent scans for current user
    user_recent_scans = ScanLog.query.filter_by(user_id=user.id).order_by(ScanLog.created_at.desc()).limit(10).all()
    
    return render_template(
        'dashboard.html',
        user=user,
        time_info=time_info,
        recent_scans=user_recent_scans
    )

@app.route('/plans')
@login_required
def plans():
    user = get_current_user()
    return render_template('plans.html', user=user, pricing=PLAN_PRICING)

@app.route('/history')
@login_required
def history():
    user = get_current_user()
    page = request.args.get('page', 1, type=int)
    scan_type = request.args.get('type', '').strip()
    query = ScanLog.query.filter_by(user_id=user.id)
    if scan_type:
        query = query.filter_by(scan_type=scan_type)
    
    pagination = query.order_by(ScanLog.created_at.desc()).paginate(page=page, per_page=15, error_out=False)
    return render_template('history.html', user=user, pagination=pagination, current_type=scan_type)

# ==========================================
# API USER / UPGRADE ENDPOINTS
# ==========================================

@app.route('/api/user/status')
@login_required
def user_status():
    user = get_current_user()
    return jsonify(user.to_dict())

@app.route('/api/user/upgrade', methods=['POST'])
@login_required
def user_upgrade():
    user = get_current_user()
    data = request.json or {}
    tier = data.get('plan_tier', '').lower()
    
    if tier not in PLAN_LIMITS:
        return jsonify({'error': f'Invalid plan tier. Available: {list(PLAN_LIMITS.keys())}'}), 400

    user.set_plan(tier)
    return jsonify({
        'success': True,
        'message': f"Congratulations! You are now subscribed to the {PLAN_NAMES[tier]} with {user.daily_limit} IP checks/day.",
        'user': user.to_dict()
    })

@app.route('/api/history/export')
@login_required
def export_history():
    user = get_current_user()
    export_format = request.args.get('format', 'csv').lower()
    scans = ScanLog.query.filter_by(user_id=user.id).order_by(ScanLog.created_at.desc()).all()

    if export_format == 'json':
        data = [s.to_dict() for s in scans]
        return Response(
            json.dumps(data, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment;filename=recon_scan_history_{user.username}.json'}
        )
    
    # CSV default
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Timestamp', 'Target', 'Resolved IP', 'Scan Type', 'Status', 'Summary'])
    for s in scans:
        writer.writerow([s.id, s.created_at.strftime('%Y-%m-%d %H:%M:%S'), s.target, s.resolved_ip or '', s.scan_type, s.status, s.result_summary or ''])
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment;filename=recon_scan_history_{user.username}.csv'}
    )

# ==========================================
# SCAN API ENDPOINTS (AUTHENTICATED & QUOTA ENFORCED)
# ==========================================

def enforce_quota_and_log(target, scan_type, params=None):
    """
    Validates if user has remaining quota.
    If allowed: consumes 1 check and returns (True, None, resolved_ip)
    If denied: returns (False, error_response, None)
    """
    user = get_current_user()
    allowed, remaining, msg = user.can_scan()
    if not allowed:
        return False, jsonify({
            'error': msg,
            'code': 'QUOTA_EXCEEDED',
            'daily_limit': user.daily_limit,
            'checks_today': user.checks_today,
            'remaining_checks': 0,
            'reset_countdown': User.get_time_until_midnight()['countdown_str']
        }), 429

    # Consume quota
    user.consume_check()
    return True, None, None

def log_scan_result(target, resolved_ip, scan_type, parameters, status, summary, full_output):
    """Saves the scan record in database."""
    user = get_current_user()
    try:
        log = ScanLog(
            user_id=user.id,
            target=target,
            resolved_ip=resolved_ip,
            scan_type=scan_type,
            parameters=json.dumps(parameters) if parameters else None,
            status=status,
            result_summary=summary[:1000] if summary else None,
            full_output=full_output[:100000] if full_output else None
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[ScanLog Error] Failed to persist scan log: {e}")

@app.route('/api/scan/metadata', methods=['POST'])
@login_required
def scan_metadata():
    data = request.json or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'No target provided'}), 400

    can_proceed, err_resp, code = enforce_quota_and_log(target, 'metadata')
    if not can_proceed:
        return err_resp, code

    try:
        resolved_ip = socket.gethostbyname(target)
        status = 'SUCCESS'
    except Exception as e:
        resolved_ip = 'Could not resolve hostname'
        status = 'ERROR'

    user = get_current_user()
    log_scan_result(
        target=target,
        resolved_ip=resolved_ip,
        scan_type='metadata',
        parameters={'target': target},
        status=status,
        summary=f"Resolved IP: {resolved_ip}",
        full_output=f"Target: {target}\nResolved IP: {resolved_ip}"
    )

    return jsonify({
        'target': target,
        'resolved_ip': resolved_ip,
        'remaining_checks': user.get_remaining_checks(),
        'checks_today': user.checks_today,
        'daily_limit': user.daily_limit
    })

@app.route('/api/scan/dns', methods=['POST'])
@login_required
def scan_dns():
    data = request.json or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'No target provided'}), 400

    can_proceed, err_resp, code = enforce_quota_and_log(target, 'dns')
    if not can_proceed:
        return err_resp, code

    if os.name == 'nt':
        dns_command = ['nslookup', '-type=any', target]
    else:
        dns_command = ['dig', 'any', target, '+noall', '+answer']
        
    dns_info = run_command(dns_command)
    status = 'ERROR' if 'timed out' in dns_info or 'Execution error' in dns_info else 'SUCCESS'

    user = get_current_user()
    log_scan_result(
        target=target,
        resolved_ip=None,
        scan_type='dns',
        parameters={'command': dns_command},
        status=status,
        summary=f"DNS lookup completed for {target}",
        full_output=dns_info
    )

    return jsonify({
        'dns': dns_info,
        'remaining_checks': user.get_remaining_checks(),
        'checks_today': user.checks_today,
        'daily_limit': user.daily_limit
    })

@app.route('/api/scan/ping', methods=['POST'])
@login_required
def scan_ping():
    data = request.json or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'No target provided'}), 400

    can_proceed, err_resp, code = enforce_quota_and_log(target, 'ping')
    if not can_proceed:
        return err_resp, code

    ping_command = ['ping', '-n', '3', target] if os.name == 'nt' else ['ping', '-c', '3', target]
    ping_info = run_command(ping_command)
    status = 'SUCCESS' if ('bytes from' in ping_info.lower() or 'reply from' in ping_info.lower()) else 'ERROR'

    user = get_current_user()
    log_scan_result(
        target=target,
        resolved_ip=None,
        scan_type='ping',
        parameters={'command': ping_command},
        status=status,
        summary=f"Live Ping test status: {status}",
        full_output=ping_info
    )

    return jsonify({
        'ping': ping_info,
        'remaining_checks': user.get_remaining_checks(),
        'checks_today': user.checks_today,
        'daily_limit': user.daily_limit
    })

@app.route('/api/scan/ports', methods=['POST'])
@login_required
def scan_ports():
    data = request.json or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'No target provided'}), 400

    can_proceed, err_resp, code = enforce_quota_and_log(target, 'ports')
    if not can_proceed:
        return err_resp, code

    try:
        resolved_ip = socket.gethostbyname(target)
    except Exception:
        resolved_ip = 'Could not resolve hostname'

    open_ports = []
    status = 'SUCCESS'
    if resolved_ip != 'Could not resolve hostname':
        try:
            import nmap
            nm = nmap.PortScanner()
            nm.scan(hosts=resolved_ip, arguments='-p- -T4 --open')
            if resolved_ip in nm.all_hosts():
                for proto in nm[resolved_ip].all_protocols():
                    lport = nm[resolved_ip][proto].keys()
                    for port in sorted(lport):
                        state = nm[resolved_ip][proto][port]['state']
                        name = nm[resolved_ip][proto][port]['name']
                        open_ports.append({
                            'port': port,
                            'protocol': proto,
                            'state': state,
                            'service': name
                        })
        except Exception as e:
            open_ports = [f"Nmap scan failed: {str(e)}"]
            status = 'ERROR'
    else:
        open_ports = ["Skipped port scan due to unresolved IP."]
        status = 'ERROR'

    user = get_current_user()
    log_scan_result(
        target=target,
        resolved_ip=resolved_ip,
        scan_type='ports',
        parameters={'ports': 'all-open'},
        status=status,
        summary=f"Detected {len(open_ports)} open port entries" if status == 'SUCCESS' else "Port scan error",
        full_output=json.dumps(open_ports, indent=2)
    )

    return jsonify({
        'ports': open_ports,
        'remaining_checks': user.get_remaining_checks(),
        'checks_today': user.checks_today,
        'daily_limit': user.daily_limit
    })

@app.route('/api/anonymous-check', methods=['POST'])
@login_required
def anonymous_check():
    data = request.json or {}
    target = data.get('target', '').strip()
    port = data.get('port', 21)

    if not target:
        return jsonify({'error': 'No target provided'}), 400

    try:
        port = int(port)
    except ValueError:
        return jsonify({'error': 'Invalid port number'}), 400

    can_proceed, err_resp, code = enforce_quota_and_log(target, 'ftp_anonymous', {'port': port})
    if not can_proceed:
        return err_resp, code

    user = get_current_user()
    status_label = 'UNKNOWN'
    msg = ''

    if port == 21:
        try:
            with ftplib.FTP() as ftp:
                ftp.connect(target, port, timeout=5)
                ftp.login('anonymous', 'anonymous@example.com')
                status_label = 'VULNERABLE'
                msg = 'Anonymous FTP login is allowed!'
        except ftplib.error_perm:
            status_label = 'SECURE'
            msg = 'Anonymous login rejected by FTP server.'
        except Exception as e:
            status_label = 'ERROR'
            msg = f'Could not connect or check target: {str(e)}'
    else:
        status_label = 'UNKNOWN'
        msg = 'Anonymous checking is only optimized for FTP (Port 21) right now.'

    log_scan_result(
        target=target,
        resolved_ip=None,
        scan_type='ftp_anonymous',
        parameters={'port': port},
        status=status_label,
        summary=f"FTP Anonymous Check [{status_label}]: {msg}",
        full_output=f"Target: {target}:{port}\nStatus: {status_label}\nDetails: {msg}"
    )

    return jsonify({
        'status': status_label,
        'message': msg,
        'remaining_checks': user.get_remaining_checks(),
        'checks_today': user.checks_today,
        'daily_limit': user.daily_limit
    })

@app.route('/api/scan/nmap', methods=['POST'])
@login_required
def scan_nmap():
    data = request.json or {}
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'No target IP or domain provided'}), 400

    can_proceed, err_resp, code = enforce_quota_and_log(target, 'nmap')
    if not can_proceed:
        return err_resp, code

    user = get_current_user()
    command = ['nmap', '-p-', '-A', '-T4', '-v', target]
    
    try:
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            timeout=1200,
            shell=False
        )
        output = result.stdout if result.stdout else result.stderr
        status = 'SUCCESS'
        summary = f"Full Nmap scan completed on {target}"
    except subprocess.TimeoutExpired:
        output = 'The deep Nmap scan timed out (longer than 20 minutes).'
        status = 'ERROR'
        summary = 'Deep scan timed out'
    except Exception as e:
        output = f'Nmap execution failed: {str(e)}'
        status = 'ERROR'
        summary = f"Execution failed: {str(e)}"

    log_scan_result(
        target=target,
        resolved_ip=None,
        scan_type='nmap',
        parameters={'command': command},
        status=status,
        summary=summary,
        full_output=output
    )

    return jsonify({
        'status': 'success' if status == 'SUCCESS' else 'error',
        'report': output,
        'remaining_checks': user.get_remaining_checks(),
        'checks_today': user.checks_today,
        'daily_limit': user.daily_limit
    })

# Initialize the database on startup
init_database()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
