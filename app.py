"""
Network Security Scanner & Firewall Visualizer
Flask Application - Main Entry Point

Directory Structure:
network_scanner/
├── app.py (this file)
├── requirements.txt
├── config.py
├── scanner/
│   ├── __init__.py
│   ├── port_scanner.py
│   └── firewall_simulator.py
├── static/
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   └── main.js
│   └── images/
└── templates/
    └── index.html
"""

# app.py
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import threading
import json
from scanner.port_scanner import PortScanner
from scanner.firewall_simulator import FirewallSimulator

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize scanner and firewall
scanner = PortScanner()
firewall = FirewallSimulator()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')
    scan_type = data.get('scan_type', 'TCP SYN')
    port_range = data.get('port_range', '1-1000')
    
    if not target:
        return jsonify({'error': 'Target IP/hostname is required'}), 400
    
    # Start scan in background thread
    thread = threading.Thread(
        target=perform_scan,
        args=(target, scan_type, port_range)
    )
    thread.start()
    
    return jsonify({'message': 'Scan started', 'status': 'running'})

def perform_scan(target, scan_type, port_range):
    """Perform the actual scan and emit results via SocketIO"""
    try:
        socketio.emit('scan_status', {'status': 'scanning', 'message': f'Scanning {target}...'})
        
        results = scanner.scan(target, scan_type, port_range)
        
        for result in results:
            socketio.emit('scan_result', result)
            socketio.sleep(0.1)  # Small delay for real-time effect
        
        socketio.emit('scan_status', {'status': 'completed', 'message': 'Scan completed successfully'})
    except Exception as e:
        socketio.emit('scan_status', {'status': 'error', 'message': str(e)})

@app.route('/api/firewall/rules', methods=['GET'])
def get_firewall_rules():
    return jsonify({'rules': firewall.get_rules()})

@app.route('/api/firewall/rules', methods=['POST'])
def add_firewall_rule():
    data = request.json
    rule = firewall.add_rule(
        action=data.get('action'),
        ip=data.get('ip'),
        port=data.get('port'),
        protocol=data.get('protocol'),
        priority=data.get('priority', 100)
    )
    return jsonify({'message': 'Rule added', 'rule': rule})

@app.route('/api/firewall/rules/<int:rule_id>', methods=['DELETE'])
def delete_firewall_rule(rule_id):
    firewall.delete_rule(rule_id)
    return jsonify({'message': 'Rule deleted'})

@app.route('/api/firewall/test', methods=['POST'])
def test_firewall():
    data = request.json
    result = firewall.test_traffic(
        ip=data.get('ip'),
        port=data.get('port'),
        protocol=data.get('protocol')
    )
    return jsonify(result)

@socketio.on('connect')
def handle_connect():
    emit('connected', {'data': 'Connected to scanner'})

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)