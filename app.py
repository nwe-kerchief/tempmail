from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
import sqlite3
import os
import random
import string
from datetime import datetime
import email
from email import policy
from email.parser import Parser
import quopri
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
    """
    Parse multipart MIME email and extract HTML or plain text body
    """
    try:
        # Try to parse as email message
        if 'Content-Type:' in raw_body:
            msg = email.message_from_string(raw_body, policy=policy.default)
            
            html_body = None
            text_body = None
            
            # Walk through email parts
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition", ""))
                    
                    # Skip attachments
                    if "attachment" in content_disposition:
                        continue
                    
                    try:
                        # Get the email body
                        body_content = part.get_payload(decode=True)
                        if body_content:
                            body_content = body_content.decode('utf-8', errors='ignore')
                            
                            if content_type == 'text/html':
                                html_body = body_content
                            elif content_type == 'text/plain':
                                text_body = body_content
                    except Exception as e:
                        print(f"Error decoding part: {e}")
                        continue
            else:
                # Single part email
                body_content = msg.get_payload(decode=True)
                if body_content:
                    body_content = body_content.decode('utf-8', errors='ignore')
                    if msg.get_content_type() == 'text/html':
                        html_body = body_content
                    else:
                        text_body = body_content
            
            # Return HTML if available, otherwise plain text
            return html_body if html_body else text_body
        
        # If not a MIME message, return as-is
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
    
    email = f"{username}@{DOMAIN}"
    return jsonify({'email': email})

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
    """
    Cloudflare Email Routing webhook endpoint with detailed logging
    """
    try:
        # Get raw body
        raw_body = request.get_data(as_text=True)
        
        # Log what we received
        print("=" * 50)
        print("📧 INCOMING EMAIL")
        print("=" * 50)
        print(f"Content-Type: {request.content_type}")
        print(f"Headers: {dict(request.headers)}")
        print(f"Raw body (first 500 chars):\n{raw_body[:500]}")
        print("=" * 50)
        
        # Try to get JSON data
        json_data = None
        try:
            json_data = request.get_json(force=True, silent=True)
            if json_data:
                print(f"✅ JSON Data received: {list(json_data.keys())}")
        except Exception as e:
            print(f"⚠️ No JSON data: {e}")
        
        # Initialize variables
        recipient = None
        sender = None
        subject = None
        body = None
        
        # Method 1: Try JSON first
        if json_data:
            print("📦 Parsing from JSON...")
            envelope = json_data.get('envelope', {})
            headers = json_data.get('headers', {})
            
            # Get recipient
            to_list = envelope.get('to', [])
            recipient = to_list[0] if to_list else None
            
            # Get sender
            sender = envelope.get('from', None)
            
            # Get subject
            subject = headers.get('Subject', None)
            
            # Get body - try HTML first, then text
            body = json_data.get('html', None)
            if not body:
                body = json_data.get('text', None)
            
            print(f"  Recipient: {recipient}")
            print(f"  Sender: {sender}")
            print(f"  Subject: {subject}")
            print(f"  Body length: {len(body) if body else 0}")
        
        # Method 2: Parse raw email if JSON failed
        if not body or not recipient:
            print("📨 Parsing from raw email...")
            try:
                msg = email.message_from_string(raw_body, policy=policy.default)
                
                if not recipient:
                    recipient = msg.get('To', None)
                    # Clean recipient (remove name part if exists)
                    if recipient and '<' in recipient:
                        recipient = recipient[recipient.find('<')+1:recipient.find('>')]
                
                if not sender:
                    sender = msg.get('From', None)
                    # Clean sender
                    if sender and '<' in sender:
                        sender = sender[sender.find('<')+1:sender.find('>')]
                
                if not subject:
                    subject = msg.get('Subject', None)
                
                if not body:
                    body = parse_email_body(raw_body)
                
                print(f"  Parsed recipient: {recipient}")
                print(f"  Parsed sender: {sender}")
                print(f"  Parsed subject: {subject}")
                
            except Exception as e:
                print(f"❌ Error parsing raw email: {e}")
        
        # Fallback defaults
        if not recipient:
            # Try to extract from raw body using regex
            import re
            to_match = re.search(r'To: ([^\r\n]+)', raw_body)
            if to_match:
                recipient = to_match.group(1).strip()
                if '<' in recipient:
                    recipient = recipient[recipient.find('<')+1:recipient.find('>')]
            else:
                recipient = 'unknown@unknown.com'
        
        if not sender:
            from_match = re.search(r'From: ([^\r\n]+)', raw_body)
            if from_match:
                sender = from_match.group(1).strip()
                if '<' in sender:
                    sender = sender[sender.find('<')+1:sender.find('>')]
            else:
                sender = 'unknown'
        
        if not subject:
            subject = 'No subject'
        
        if not body:
            body = 'No content'
        
        # Clean up
        body = body.strip()
        recipient = recipient.strip()
        sender = sender.strip()
        
        # Get timestamp
        timestamp = datetime.utcnow().isoformat()
        
        # Store in database
        conn = sqlite3.connect('emails.db')
        c = conn.cursor()
        c.execute('''
            INSERT INTO emails (recipient, sender, subject, body, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (recipient, sender, subject, body, timestamp))
        conn.commit()
        conn.close()
        
        print(f"✅ Email stored: {sender} → {recipient}")
        print("=" * 50)
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

