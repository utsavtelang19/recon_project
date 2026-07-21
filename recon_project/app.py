import os
import socket
import subprocess
import nmap
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

def run_command(command_list):
    """Safely executes a system command and returns the string output."""
    try:
        result = subprocess.run(command_list, capture_output=True, text=True, timeout=15)
        return result.stdout if result.stdout else result.stderr
    except subprocess.TimeoutExpired:
        return "Command timed out."
    except Exception as e:
        return f"Execution error: {str(e)}"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan_target():
    data = request.json or {}
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'No target provided'}), 400

    # 1. Resolve basic IP Address
    try:
        resolved_ip = socket.gethostbyname(target)
    except Exception:
        resolved_ip = 'Could not resolve hostname'

   # 2. DNS Enumeration (Fetches all available MX, TXT, NS, and A records)
    if os.name == 'nt':
        # Windows native configuration
        dns_command = ['nslookup', '-type=any', target]
    else:
        # Linux/macOS configuration (dig returns much cleaner, more comprehensive data)
        dns_command = ['dig', 'any', target, '+noall', '+answer']
        
    dns_info = run_command(dns_command)

    # 3. Simple Ping Check
    ping_command = ['ping', '-n', '3', target] if os.name == 'nt' else ['ping', '-c', '3', target]
    ping_info = run_command(ping_command)

    # 4. Full Port Scan with Nmap
    open_ports = []
    if resolved_ip != 'Could not resolve hostname':
        try:
            nm = nmap.PortScanner()
            # -p- scans all 65535 ports. -T4 speeds up the scan.
            # Use --open to only return ports that are actually open.
            nm.scan(hosts=resolved_ip, arguments='-p- -T4 --open')
            
            # Extract open ports from the Nmap results
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
    else:
        open_ports = ["Skipped port scan due to unresolved IP."]

    return jsonify({
        'target': target,
        'resolved_ip': resolved_ip,
        'dns': dns_info,
        'ping': ping_info,
        'ports': open_ports  # Returns a clean list of open ports
    })

@app.route('/api/anonymous-check', methods=['POST'])
def anonymous_check():
    data = request.json or {}
    target = data.get('target', '').strip()
    port = data.get('port', 21) # Defaults to FTP port 21

    if not target:
        return jsonify({'error': 'No target provided'}), 400

    try:
        # Convert port input safely to integer
        port = int(port)
    except ValueError:
        return jsonify({'error': 'Invalid port number'}), 400

    # Handle FTP Anonymous Check (Port 21)
    if port == 21:
        import ftplib
        try:
            # Set a 5-second timeout to prevent stalling the thread
            with ftplib.FTP() as ftp:
                ftp.connect(target, port, timeout=5)
                # Attempt to login using standard anonymous credentials
                ftp.login('anonymous', 'anonymous@example.com')
                return jsonify({
                    'status': 'VULNERABLE',
                    'message': 'Anonymous FTP login is allowed!'
                })
        except ftplib.error_perm:
            return jsonify({
                'status': 'SECURE',
                'message': 'Anonymous login rejected by FTP server.'
            })
        except Exception as e:
            return jsonify({
                'status': 'ERROR',
                'message': f'Could not connect or check target: {str(e)}'
            })

    # Fallback/Generic banner check or unsupported ports
    return jsonify({
        'status': 'UNKNOWN',
        'message': f'Anonymous checking is only optimized for FTP (Port 21) right now.'
    })

@app.route('/api/scan/nmap', methods=['POST'])
def scan_nmap():
    data = request.json or {}
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'No target IP or domain provided'}), 400

    # COMPREHENSIVE NMAP SCAN PROFILE:
    # -p-      : Scans ALL 65,535 available ports (instead of just the top 1000)
    # -A       : Enables OS detection, version detection, script scanning, and traceroute
    # -T4      : Speeds up execution behavior for faster results on reliable networks
    # -v       : Verbose mode (gives instant text feedback as it moves through stages)
    command = ['nmap', '-p-', '-A', '-T4', '-v', target]
    
    try:
        # shell=False ensures absolute safety against input injection
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            timeout=1200, # Increased timeout to 20 minutes for a full-range scan
            shell=False
        )
        
        output = result.stdout if result.stdout else result.stderr
        return jsonify({'status': 'success', 'report': output})
        
    except subprocess.TimeoutExpired:
        return jsonify({
            'status': 'error', 
            'report': 'The deep Nmap scan timed out. Scanning all 65,535 ports with OS detection took longer than 20 minutes.'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'report': f'Nmap execution failed: {str(e)}'})


if __name__ == '__main__':
    app.run(debug=True, port=5000)
