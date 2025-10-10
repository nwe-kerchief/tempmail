import os
import sqlite3
import random
import string
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'change-this-in-production')
CORS(app)

# Configuration
DOMAIN = os.getenv('DOMAIN', 'yourdomain.com')
DB_PATH = os.getenv('DB_PATH', 'tempmail.db')
APP_PASSWORD = os.getenv('APP_PASSWORD', 'admin123')

# Brevo SMTP Configuration
BREVO_SMTP_HOST = 'smtp-relay.brevo.com'
BREVO_SMTP_PORT = 587
BREVO_USERNAME = os.getenv('BREVO_USERNAME', '')
BREVO_PASSWORD = os.getenv('BREVO_PASSWORD', '')

# Initialize Database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Emails table
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
    
    # Temporary addresses table
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

# Database Helper Functions
def insert_email(sender, recipient, subject, body, html_body=''):
    """Insert received email into database"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO emails (sender, recipient, subject, body, html_body)
        VALUES (?, ?, ?, ?, ?)
    ''', (sender, recipient, subject, body, html_body))
    conn.commit()
    conn.close()

def get_emails_for_address(email):
    """Get all emails for a specific temporary email address"""
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
    """Save generated temporary email address"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO temp_addresses (email) VALUES (?)', (email,))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Email already exists
    conn.close()

def generate_random_username(length=10):
    """Generate random username for temp email"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

# Routes
@app.route('/')
def index():
    """Serve main page"""
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    """Handle login authentication"""
    data = request.get_json()
    password = data.get('password', '')
    
    if password == APP_PASSWORD:
        session['authenticated'] = True
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Invalid password'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    """Handle logout"""
    session.pop('authenticated', None)
    return jsonify({'success': True})

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    """Check if user is authenticated"""
    return jsonify({'authenticated': session.get('authenticated', False)})

@app.route('/api/domains', methods=['GET'])
def domains():
    """Get available email domains"""
    return jsonify({'domains': [DOMAIN]})

@app.route('/api/create', methods=['POST'])
def create_email():
    """Create new temporary email address"""
    if not session.get('authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    custom_name = data.get('name', '').strip()
    
    # Use custom name or generate random
    if custom_name:
        username = custom_name.lower().replace(' ', '').replace('@', '')
        # Remove special characters
        username = ''.join(c for c in username if c.isalnum() or c in '-_.')
    else:
        username = generate_random_username()
    
    email_address = f"{username}@{DOMAIN}"
    save_temp_address(email_address)
    
    return jsonify({'email': email_address})

@app.route('/api/emails/<path:email>', methods=['GET'])
def fetch_emails(email):
    """Fetch emails for a specific temporary address"""
    if not session.get('authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    emails = get_emails_for_address(email)
    return jsonify({'emails': emails})

@app.route('/api/webhook/inbound', methods=['POST'])
def inbound_email_webhook():
    """
    Cloudflare Email Routing webhook endpoint
    Receives incoming emails and stores them in database
    
    Expected payload from Cloudflare:
    {
        "from": "sender@example.com",
        "to": "recipient@yourdomain.com",
        "subject": "Email subject",
        "plain_body": "Plain text body",
        "html_body": "HTML body"
    }
    """
    try:
        data = request.get_json()
        
        sender = data.get('from', '')
        recipient = data.get('to', '')
        subject = data.get('subject', '(no subject)')
        body = data.get('plain_body', '')
        html_body = data.get('html_body', '')
        
        # Store email in database
        insert_email(sender, recipient, subject, body, html_body)
        
        return ('', 204)  # Success, no content
    except Exception as e:
        print(f"Error processing webhook: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/send', methods=['POST'])
def send_email():
    """
    Send email via Brevo SMTP
    Optional feature - requires Brevo credentials
    """
    if not session.get('authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    if not BREVO_USERNAME or not BREVO_PASSWORD:
        return jsonify({'error': 'Email sending not configured'}), 500
    
    data = request.get_json()
    to_email = data.get('to')
    subject = data.get('subject')
    body = data.get('body')
    from_email = data.get('from', f'noreply@{DOMAIN}')
    
    if not to_email or not subject or not body:
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        # Create email message
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        # Connect to Brevo SMTP server
        server = smtplib.SMTP(BREVO_SMTP_HOST, BREVO_SMTP_PORT)
        server.starttls()
        server.login(BREVO_USERNAME, BREVO_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        return jsonify({'success': True, 'message': 'Email sent successfully'})
    except Exception as e:
        print(f"Error sending email: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'domain': DOMAIN,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/stats', methods=['GET'])
def stats():
    """Get statistics (optional)"""
    if not session.get('authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Count total emails
    cur.execute('SELECT COUNT(*) FROM emails')
    total_emails = cur.fetchone()[0]
    
    # Count total temp addresses
    cur.execute('SELECT COUNT(*) FROM temp_addresses')
    total_addresses = cur.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'total_emails': total_emails,
        'total_addresses': total_addresses
    })

# Error Handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
