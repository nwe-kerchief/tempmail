from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
import os
import random
import string
from datetime import datetime, timedelta
import email
from email import policy
from functools import wraps
import secrets
from threading import Thread
import time

# PostgreSQL support
import psycopg2
from psycopg2.extras import RealDictCursor

MALE_NAMES = ['james', 'john', 'robert', 'michael', 'william', 'david', 'richard', 'joseph', 'thomas', 'charles', 
              'daniel', 'matthew', 'anthony', 'mark', 'paul', 'steven', 'andrew', 'joshua', 'kevin', 'brian',
              'george', 'kenneth', 'edward', 'ryan', 'jacob', 'nicholas', 'tyler', 'samuel', 'benjamin', 'alexander']

FEMALE_NAMES = ['mary', 'patricia', 'jennifer', 'linda', 'elizabeth', 'barbara', 'susan', 'jessica', 'sarah', 'karen',
                'nancy', 'lisa', 'betty', 'margaret', 'sandra', 'ashley', 'kimberly', 'emily', 'donna', 'michelle',
                'dorothy', 'carol', 'amanda', 'melissa', 'deborah', 'stephanie', 'rebecca', 'sharon', 'laura', 'grace']

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_urlsafe(32))
CORS(app)

APP_PASSWORD = os.getenv('APP_PASSWORD', 'admin123')
DOMAIN = os.getenv('DOMAIN', 'aungmyomyatzaw.online')
DATABASE_URL = os.getenv('DATABASE_URL')

# Database connection helper
def get_db():
    return psycopg2.connect(DATABASE_URL, sslmode='require')

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Sessions table
    c.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_token TEXT PRIMARY KEY,
            email_address TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            last_activity TIMESTAMP NOT NULL
        )
    ''')
    
    # Emails table
    c.execute('''
        CREATE TABLE IF NOT EXISTS emails (
            id SERIAL PRIMARY KEY,
            recipient TEXT NOT NULL,
            sender TEXT NOT NULL,
            subject TEXT,
            body TEXT,
            timestamp TEXT,
            received_at TIMESTAMP NOT NULL,
            session_token TEXT NOT NULL,
            FOREIGN KEY (session_token) REFERENCES sessions(session_token) ON DELETE CASCADE
        )
    ''')
    
    # Indexes for performance
    c.execute('CREATE INDEX IF NOT EXISTS idx_recipient ON emails(recipient)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_session ON emails(session_token)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_received_at ON emails(received_at)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_email_address ON sessions(email_address)')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized")

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
        # Generate random name: malename + femalename + 3 digits
        male_name = random.choice(MALE_NAMES)
        female_name = random.choice(FEMALE_NAMES)
        three_digits = ''.join(random.choices(string.digits, k=3))
        username = f"{male_name}{female_name}{three_digits}"
    
    email_address = f"{username}@{DOMAIN}"
    
    # Create session token
    session_token = secrets.token_urlsafe(32)
    created_at = datetime.now()
    expires_at = created_at + timedelta(hours=1)
    
    # Store session in PostgreSQL
    conn = get_db()
    c = conn.cursor()
    
    try:
        c.execute('''
            INSERT INTO sessions (session_token, email_address, created_at, expires_at, last_activity)
            VALUES (%s, %s, %s, %s, %s)
        ''', (session_token, email_address, created_at, expires_at, created_at))
        conn.commit()
        conn.close()
        
        return jsonify({
            'email': email_address,
            'session_token': session_token,
            'expires_at': expires_at.isoformat()
        })
    except Exception as e:
        conn.rollback()
        conn.close()
        print(f"❌ Error creating session: {e}")
        return jsonify({'error': 'Failed to create session'}), 500

@app.route('/api/emails/<email_address>', methods=['GET'])
def get_emails(email_address):
    session_token = request.headers.get('X-Session-Token')
    
    if not session_token:
        return jsonify({'error': 'No session token'}), 401
    
    conn = get_db()
    c = conn.cursor(cursor_factory=RealDictCursor)
    
    # Verify session
    c.execute('''
        SELECT email_address, expires_at 
        FROM sessions 
        WHERE session_token = %s AND email_address = %s
    ''', (session_token, email_address))
    
    session_data = c.fetchone()
    
    if not session_data:
        conn.close()
        return jsonify({'error': 'Invalid session'}), 401
    
    # Check if expired
    if datetime.now() > session_data['expires_at']:
        conn.close()
        return jsonify({'error': 'Session expired'}), 401
    
    # Update last activity
    c.execute('''
        UPDATE sessions 
        SET last_activity = %s 
        WHERE session_token = %s
    ''', (datetime.now(), session_token))
    conn.commit()
    
    # Get emails for this session only
    c.execute('''
        SELECT sender, subject, body, received_at, timestamp 
        FROM emails 
        WHERE recipient = %s AND session_token = %s
        ORDER BY received_at DESC
    ''', (email_address, session_token))
    
    emails = []
    for row in c.fetchall():
        display_timestamp = row['received_at'] if row['received_at'] else row['timestamp']
        
        emails.append({
            'id': len(emails) + 1,
            'sender': row['sender'],
            'subject': row['subject'],
            'body': row['body'],
            'timestamp': display_timestamp.isoformat() if hasattr(display_timestamp, 'isoformat') else display_timestamp
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
        
        # Get body
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
                
                if stripped == '':
                    empty_line_count += 1
                    if empty_line_count >= 2:
                        skip_mode = False
                    continue
                else:
                    empty_line_count = 0
                
                is_header = False
                for pattern in header_patterns:
                    if stripped.startswith(pattern) or (skip_mode and ':' in stripped[:50]):
                        is_header = True
                        break
                
                if skip_mode and (line.startswith(' ') or line.startswith('\t')):
                    is_header = True
                
                if not is_header:
                    skip_mode = False
                
                if not skip_mode and not is_header:
                    clean_lines.append(line)
            
            body = '\n'.join(clean_lines).strip()
        
        if len(body) > 1000 and (body.count('=') > 50 or body.count('+') > 50):
            plain = json_data.get('plain_body', '')
            if plain and len(plain) < len(body) * 0.8:
                body = plain
        
        print(f"  ✉️  From: {sender}")
        print(f"  📬 To: {recipient}")
        print(f"  📝 Subject: {subject}")
        print(f"  📄 Body: {len(body)} chars")
        print("=" * 50)
        
        # Store timestamps
        received_at = datetime.now()
        original_timestamp = json_data.get('timestamp', received_at.isoformat())
        
        # Find active session for this recipient
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            SELECT session_token 
            FROM sessions 
            WHERE email_address = %s AND expires_at > NOW()
            ORDER BY created_at DESC 
            LIMIT 1
        ''', (recipient,))
        
        session_data = c.fetchone()
        
        if session_data:
            session_token = session_data[0]
            
            # Store email
            c.execute('''
                INSERT INTO emails (recipient, sender, subject, body, timestamp, received_at, session_token)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (recipient, sender, subject, body, original_timestamp, received_at, session_token))
            
            # Update session last_activity
            c.execute('''
                UPDATE sessions 
                SET last_activity = %s 
                WHERE session_token = %s
            ''', (received_at, session_token))
            
            conn.commit()
            conn.close()
            
            print(f"✅ Email stored: {sender} → {recipient}")
            return '', 204
        else:
            conn.close()
            print(f"⚠️ No active session for {recipient}")
            return '', 204
        
    except Exception as e:
        print(f"❌ Webhook error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 400

# Cleanup expired sessions
def cleanup_expired_sessions():
    while True:
        time.sleep(300)  # Every 5 minutes
        
        try:
            conn = get_db()
            c = conn.cursor()
            
            # Delete expired sessions (CASCADE will delete emails too)
            c.execute('''
                DELETE FROM sessions 
                WHERE expires_at < NOW()
            ''')
            
            deleted = c.rowcount
            conn.commit()
            conn.close()
            
            if deleted > 0:
                print(f"🧹 Cleaned up {deleted} expired sessions")
        except Exception as e:
            print(f"❌ Cleanup error: {e}")

# Start cleanup thread
cleanup_thread = Thread(target=cleanup_expired_sessions, daemon=True)
cleanup_thread.start()

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
        conn = get_db()
        c = conn.cursor()
        
        c.execute('SELECT COUNT(*) FROM emails')
        total_emails = c.fetchone()[0]
        
        c.execute('SELECT COUNT(DISTINCT recipient) FROM emails')
        total_addresses = c.fetchone()[0]
        
        c.execute('''
            SELECT COUNT(*) FROM emails 
            WHERE received_at > NOW() - INTERVAL '1 day'
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
        conn = get_db()
        c = conn.cursor(cursor_factory=RealDictCursor)
        
        c.execute('''
            SELECT recipient, COUNT(*) as count, MAX(received_at) as last_email
            FROM emails
            GROUP BY recipient
            ORDER BY last_email DESC
        ''')
        
        addresses = []
        for row in c.fetchall():
            addresses.append({
                'address': row['recipient'],
                'count': row['count'],
                'last_email': row['last_email'].isoformat() if row['last_email'] else None
            })
        
        conn.close()
        return jsonify({'addresses': addresses})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/emails/<email_address>', methods=['GET'])
@admin_required
def admin_get_emails(email_address):
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=RealDictCursor)
        
        c.execute('''
            SELECT id, sender, subject, body, received_at, timestamp 
            FROM emails 
            WHERE recipient = %s 
            ORDER BY received_at DESC
        ''', (email_address,))
        
        emails = []
        for row in c.fetchall():
            emails.append({
                'id': row['id'],
                'sender': row['sender'],
                'subject': row['subject'],
                'body': row['body'],
                'received_at': row['received_at'].isoformat() if row['received_at'] else None,
                'timestamp': row['timestamp']
            })
        
        conn.close()
        return jsonify({'emails': emails})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/delete/<int:email_id>', methods=['DELETE'])
@admin_required
def admin_delete_email(email_id):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('DELETE FROM emails WHERE id = %s', (email_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/delete-address/<email_address>', methods=['DELETE'])
@admin_required
def admin_delete_address(email_address):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('DELETE FROM emails WHERE recipient = %s', (email_address,))
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
