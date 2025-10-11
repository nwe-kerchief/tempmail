from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
import sqlite3
import os
import random
import string
from datetime import datetime
import email
from email import policy
import re

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'change-this-in-production')
CORS(app)

# Configuration
APP_PASSWORD = os.getenv('APP_PASSWORD', 'admin123')
DOMAIN = os.getenv('DOMAIN', 'aungmyomyatzaw.online')

# Initialize database
def init_db():
    conn = sqlite3.connect('emails.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL,
            sender TEXT NOT NULL,
            subject TEXT,
            body TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Helper function to parse email body
def parse_email_body(raw_body):
    """Parse multipart MIME email and extract HTML or plain text body"""
    try:
        if 'Content-Type:' in raw_body:
            msg = email.message_from_string(raw_body, policy=policy.default)
            
            html_body = None
            text_body = None
            
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition", ""))
                    
                    if "attachment" in content_disposition:
                        continue
                    
                    try:
                        body_content = part.get_payload(decode=True)
                        if body_content:
                            body_content = body_content.decode('utf-8', errors='ignore')
                            
                            if content_type == 'text/html':
                                html_body = body_content
                            elif content_type == 'text/plain':
                                text_body = body_content
                    except:
                        continue
            else:
                body_content = msg.get_payload(decode=True)
                if body_content:
                    body_content = body_content.decode('utf-8', errors='ignore')
                    if msg.get_content_type() == 'text/html':
                        html_body = body_content
                    else:
                        text_body = body_content
            
            return html_body if html_body else text_body
        
        return raw_body
        
    except Exception as e:
        print(f"Email parsing error: {e}")
        return raw_body

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    password = data.get('password', '')
    
    if password == APP_PASSWORD:
        session['authenticated'] = True
        return jsonify({'success': True})
    return jsonify({'success': False}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/domains', methods=['GET'])
def get_domains():
    if not session.get('authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'domains': [DOMAIN]})

@app.route('/api/create', methods=['POST'])
def create_email():
    if not session.get('authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json() or {}
    custom_name = data.get('name', '').strip()
    
    if custom_name:
        username = custom_name.lower()
        username = ''.join(c for c in username if c.isalnum() or c in '-_')
    else:
        username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    
    email_address = f"{username}@{DOMAIN}"
    return jsonify({'email': email_address})

@app.route('/api/emails/<email_address>', methods=['GET'])
def get_emails(email_address):
    if not session.get('authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect('emails.db')
    c = conn.cursor()
    c.execute('''
        SELECT sender, subject, body, timestamp 
        FROM emails 
        WHERE recipient = ? 
        ORDER BY timestamp DESC
    ''', (email_address,))
    
    emails = []
    for row in c.fetchall():
        emails.append({
            'sender': row[0],
            'subject': row[1],
            'body': row[2],
            'timestamp': row[3]
        })
    
    conn.close()
    return jsonify({'emails': emails})

@app.route('/api/webhook/inbound', methods=['POST'])
def webhook_inbound():
    """Cloudflare Email Routing webhook - Fixed for actual Cloudflare format"""
    try:
        json_data = request.get_json(force=True, silent=True)
        
        if not json_data:
            return jsonify({'error': 'No JSON data'}), 400
        
        print("=" * 50)
        print("📧 INCOMING EMAIL")
        print("=" * 50)
        
        # Cloudflare format: from, to, subject, plain_body, html_body
        recipient = json_data.get('to', 'unknown@unknown.com')
        sender = json_data.get('from', 'unknown')
        subject = json_data.get('subject', 'No subject')
        
        # Get HTML body first, fallback to plain text
        body = json_data.get('html_body', None)
        if not body or body.strip() == '':
            body = json_data.get('plain_body', 'No content')
        
        # Clean up
        recipient = recipient.strip()
        sender = sender.strip()
        subject = subject.strip()
        body = body.strip()
        
        # Parse if still raw MIME
        if 'Content-Type:' in body and 'multipart' in body:
            body = parse_email_body(body)
        
        print(f"  ✉️  From: {sender}")
        print(f"  📬 To: {recipient}")
        print(f"  📝 Subject: {subject}")
        print(f"  📄 Body: {len(body)} chars")
        print("=" * 50)
        
        # Store in database
        timestamp = datetime.utcnow().isoformat()
        conn = sqlite3.connect('emails.db')
        c = conn.cursor()
        c.execute('''
            INSERT INTO emails (recipient, sender, subject, body, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (recipient, sender, subject, body, timestamp))
        conn.commit()
        conn.close()
        
        print(f"✅ Email stored: {sender} → {recipient}")
        return '', 204
        
    except Exception as e:
        print(f"❌ Webhook error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 400

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'domain': DOMAIN,
        'timestamp': datetime.utcnow().isoformat()
    })

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
