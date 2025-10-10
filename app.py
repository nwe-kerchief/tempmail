import os
import sqlite3
import random
import string
from datetime import datetime
from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'change-this-in-production')
CORS(app)

# Configuration
DOMAIN = os.getenv('DOMAIN', 'yourdomain.com')
DB_PATH = os.getenv('DB_PATH', 'tempmail.db')
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY', '')
APP_PASSWORD = os.getenv('APP_PASSWORD', 'admin123')

# Initialize Database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            subject TEXT,
            body TEXT,
            html_body TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS temp_addresses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Database helpers
def insert_email(sender, recipient, subject, body, html_body=''):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO emails (sender, recipient, subject, body, html_body)
        VALUES (?, ?, ?, ?, ?)
    ''', (sender, recipient, subject, body, html_body))
    conn.commit()
    conn.close()

def get_emails_for_address(email):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
        SELECT sender, subject, body, html_body, timestamp
        FROM emails
        WHERE recipient = ?
        ORDER BY timestamp DESC
        LIMIT 50
    ''', (email,))
    rows = cur.fetchall()
    conn.close()
    return [
        {
            'sender': r[0],
            'subject': r[1],
            'body': r[2],
            'html_body': r[3],
            'timestamp': r[4]
        }
        for r in rows
    ]

def save_temp_address(email):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO temp_addresses (email) VALUES (?)', (email,))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Already exists
    conn.close()

def generate_random_username(length=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    password = data.get('password', '')
    if password == APP_PASSWORD:
        session['authenticated'] = True
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Invalid password'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('authenticated', None)
    return jsonify({'success': True})

@app.route('/api/domains', methods=['GET'])
def domains():
    return jsonify({'domains': [DOMAIN]})

@app.route('/api/create', methods=['POST'])
def create_email():
    if not session.get('authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    custom_name = data.get('name', '').strip()
    
    if custom_name:
        username = custom_name.lower().replace(' ', '')
    else:
        username = generate_random_username()
    
    email_address = f"{username}@{DOMAIN}"
    save_temp_address(email_address)
    
    return jsonify({'email': email_address})

@app.route('/api/emails/<path:email>', methods=['GET'])
def fetch_emails(email):
    if not session.get('authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    emails = get_emails_for_address(email)
    return jsonify({'emails': emails})

@app.route('/api/webhook/inbound', methods=['POST'])
def inbound_email_webhook():
    """
    Cloudflare Email Routing webhook endpoint
    Receives: {from, to, subject, plain_body, html_body, ...}
    """
    data = request.get_json()
    
    sender = data.get('from', '')
    recipient = data.get('to', '')
    subject = data.get('subject', '(no subject)')
    body = data.get('plain_body', '')
    html_body = data.get('html_body', '')
    
    insert_email(sender, recipient, subject, body, html_body)
    
    return ('', 204)

@app.route('/api/send', methods=['POST'])
def send_email():
    """
    Optional: Send email via SendGrid
    """
    if not session.get('authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    if not SENDGRID_API_KEY:
        return jsonify({'error': 'SendGrid not configured'}), 500
    
    data = request.get_json()
    to_email = data.get('to')
    subject = data.get('subject')
    body = data.get('body')
    from_email = data.get('from', f'noreply@{DOMAIN}')
    
    message = Mail(
        from_email=from_email,
        to_emails=to_email,
        subject=subject,
        plain_text_content=body
    )
    
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        return jsonify({'success': True, 'status_code': response.status_code})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
