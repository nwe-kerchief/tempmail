from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
import sqlite3
import os
import random
import string
from datetime import datetime
import email
from email import policy
from functools import wraps
import re

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'change-this-in-production')
CORS(app)

APP_PASSWORD = os.getenv('APP_PASSWORD', 'admin123')
DOMAIN = os.getenv('DOMAIN', 'aungmyomyatzaw.online')

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

def parse_email_body(raw_body):
    """Parse MIME email and extract clean HTML/text"""
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

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/domains', methods=['GET'])
def get_domains():
    return jsonify({'domains': [DOMAIN]})

@app.route('/api/create', methods=['POST'])
def create_email():
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
    try:
        json_data = request.get_json(force=True, silent=True)
        
        if not json_data:
            return jsonify({'error': 'No JSON data'}), 400
        
        print("=" * 50)
        print("📧 INCOMING EMAIL")
        
        recipient = json_data.get('to', 'unknown@unknown.com')
        sender = json_data.get('from', 'unknown')
        subject = json_data.get('subject', 'No subject')
        
        # Clean sender
        if '<' in sender and '>' in sender:
            sender = sender[sender.find('<')+1:sender.find('>')]
        
        if 'bounce' in sender.lower():
            if '@' in sender:
                domain_part = sender.split('@')[1]
                if 'openai.com' in domain_part or 'mandrillapp.com' in domain_part:
                    sender = 'ChatGPT'
                elif 'afraid.org' in domain_part:
                    sender = 'FreeDNS'
                else:
                    sender = 'Notification'
        
        # Get body - HTML first, then plain
        body = json_data.get('html_body', None)
        if not body or body.strip() == '':
            body = json_data.get('plain_body', 'No content')
        
        recipient = recipient.strip()
        sender = sender.strip()
        subject = subject.strip()
        body = body.strip()
        
        # Parse MIME if needed
        if 'Content-Type:' in body and 'multipart' in body:
            body = parse_email_body(body)
        
        # AGGRESSIVE HEADER REMOVAL
        header_patterns = [
            'Received:', 'Received-SPF:', 'ARC-Seal:', 'ARC-Message-Signature:', 
            'ARC-Authentication-Results:', 'DKIM-Signature:', 'Authentication-Results:',
            'Return-Path:', 'Delivered-To:', 'X-', 'Message-ID:', 'Date:', 
            'MIME-Version:', 'Content-Type:', 'Content-Transfer-Encoding:',
            'Content-ID:', 'Reply-To:', 'List-', 'Precedence:'
        ]
        
        if any(body.startswith(pattern) or ('\n' + pattern in body[:1000]) for pattern in header_patterns):
            lines = body.split('\n')
            clean_lines = []
            skip_mode = True
            empty_line_count = 0
            
            for line in lines:
                stripped = line.strip()
                
                # Count empty lines
                if stripped == '':
                    empty_line_count += 1
                    if empty_line_count >= 2:  # After 2 empty lines, assume body starts
                        skip_mode = False
                    continue
                else:
                    empty_line_count = 0
                
                # Check if it's a header line
                is_header = False
                for pattern in header_patterns:
                    if stripped.startswith(pattern) or (skip_mode and ':' in stripped[:50]):
                        is_header = True
                        break
                
                # Check for continuation lines (indented)
                if skip_mode and (line.startswith(' ') or line.startswith('\t')):
                    is_header = True
                
                if not is_header:
                    skip_mode = False
                
                if not skip_mode and not is_header:
                    clean_lines.append(line)
            
            body = '\n'.join(clean_lines).strip()
        
        # If body is still base64 encoded junk, try plain_body
        if len(body) > 1000 and (body.count('=') > 50 or body.count('+') > 50):
            plain = json_data.get('plain_body', '')
            if plain and len(plain) < len(body) * 0.8:
                body = plain
        
        print(f"  ✉️  From: {sender}")
        print(f"  📬 To: {recipient}")
        print(f"  📝 Subject: {subject}")
        print(f"  📄 Body: {len(body)} chars")
        print("=" * 50)
        
        # Store ARRIVAL time, not email send time
        timestamp = datetime.now().isoformat()

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

# Admin routes
@app.route('/admin')
def admin_panel():
    return render_template('admin.html')

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json() or {}
    password = data.get('password', '')
    
    if password == APP_PASSWORD:
        session['admin_authenticated'] = True
        return jsonify({'success': True})
    return jsonify({'success': False}), 401

@app.route('/api/admin/logout', methods=['POST'])
@admin_required
def admin_logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    try:
        conn = sqlite3.connect('emails.db')
        c = conn.cursor()
        
        c.execute('SELECT COUNT(*) FROM emails')
        total_emails = c.fetchone()[0]
        
        c.execute('SELECT COUNT(DISTINCT recipient) FROM emails')
        total_addresses = c.fetchone()[0]
        
        c.execute('''
            SELECT COUNT(*) FROM emails 
            WHERE datetime(timestamp) > datetime('now', '-1 day')
        ''')
        recent_emails = c.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'total_emails': total_emails,
            'total_addresses': total_addresses,
            'recent_emails': recent_emails
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/addresses', methods=['GET'])
@admin_required
def admin_addresses():
    try:
        conn = sqlite3.connect('emails.db')
        c = conn.cursor()
        
        c.execute('''
            SELECT recipient, COUNT(*) as count, MAX(timestamp) as last_email
            FROM emails
            GROUP BY recipient
            ORDER BY last_email DESC
        ''')
        
        addresses = []
        for row in c.fetchall():
            addresses.append({
                'address': row[0],
                'count': row[1],
                'last_email': row[2]
            })
        
        conn.close()
        return jsonify({'addresses': addresses})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/emails/<email_address>', methods=['GET'])
@admin_required
def admin_get_emails(email_address):
    try:
        conn = sqlite3.connect('emails.db')
        c = conn.cursor()
        
        c.execute('''
            SELECT id, sender, subject, body, timestamp 
            FROM emails 
            WHERE recipient = ? 
            ORDER BY timestamp DESC
        ''', (email_address,))
        
        emails = []
        for row in c.fetchall():
            emails.append({
                'id': row[0],
                'sender': row[1],
                'subject': row[2],
                'body': row[3],
                'timestamp': row[4]
            })
        
        conn.close()
        return jsonify({'emails': emails})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/delete/<int:email_id>', methods=['DELETE'])
@admin_required
def admin_delete_email(email_id):
    try:
        conn = sqlite3.connect('emails.db')
        c = conn.cursor()
        c.execute('DELETE FROM emails WHERE id = ?', (email_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/delete-address/<email_address>', methods=['DELETE'])
@admin_required
def admin_delete_address(email_address):
    try:
        conn = sqlite3.connect('emails.db')
        c = conn.cursor()
        c.execute('DELETE FROM emails WHERE recipient = ?', (email_address,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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

