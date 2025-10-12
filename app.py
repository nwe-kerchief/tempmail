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
import psycopg2
from psycopg2.extras import RealDictCursor
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MALE_NAMES = ['james', 'john', 'robert', 'michael', 'william', 'david', 'richard', 'joseph', 'thomas', 'charles', 
              'daniel', 'matthew', 'anthony', 'mark', 'paul', 'steven', 'andrew', 'joshua', 'kevin', 'brian',
              'george', 'kenneth', 'edward', 'ryan', 'jacob', 'nicholas', 'tyler', 'samuel', 'benjamin', 'alexander']

FEMALE_NAMES = ['mary', 'patricia', 'jennifer', 'linda', 'elizabeth', 'barbara', 'susan', 'jessica', 'sarah', 'karen',
                'nancy', 'lisa', 'betty', 'margaret', 'sandra', 'ashley', 'kimberly', 'emily', 'donna', 'michelle',
                'dorothy', 'carol', 'amanda', 'melissa', 'deborah', 'stephanie', 'rebecca', 'sharon', 'laura', 'grace']

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_urlsafe(32))
CORS(app, origins=[os.getenv('FRONTEND_URL', '*')], supports_credentials=True)

APP_PASSWORD = os.getenv('APP_PASSWORD', 'admin123')
DOMAIN = os.getenv('DOMAIN', 'aungmyomyatzaw.online')
DATABASE_URL = os.getenv('DATABASE_URL')

# Database connection helper
def get_db():
    try:
        return psycopg2.connect(DATABASE_URL, sslmode='require')
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        raise

def init_db():
    try:
        conn = get_db()
        conn.autocommit = True  # Use autocommit for schema changes
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
        
        # Check if is_active column exists, if not add it
        try:
            c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='sessions' AND column_name='is_active'")
            if not c.fetchone():
                logger.info("Adding is_active column to sessions table...")
                c.execute('ALTER TABLE sessions ADD COLUMN is_active BOOLEAN DEFAULT TRUE')
                logger.info("✅ is_active column added successfully")
        except Exception as e:
            logger.warning(f"Could not check/add is_active column: {e}")
        
        # Indexes for performance
        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_recipient ON emails(recipient)',
            'CREATE INDEX IF NOT EXISTS idx_session ON emails(session_token)',
            'CREATE INDEX IF NOT EXISTS idx_received_at ON emails(received_at)',
            'CREATE INDEX IF NOT EXISTS idx_email_address ON sessions(email_address)',
            'CREATE INDEX IF NOT EXISTS idx_is_active ON sessions(is_active)'
        ]
        
        for index_sql in indexes:
            try:
                c.execute(index_sql)
            except Exception as e:
                logger.warning(f"Could not create index: {e}")
        
        conn.close()
        logger.info("✅ Database initialized successfully")
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        # Try to continue even if initialization fails

init_db()

def extract_content_from_mime(msg):
    """Extract content from MIME message"""
    html_content = None
    text_content = None
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            
            # Skip attachments
            if "attachment" in content_disposition:
                continue
            
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    decoded = payload.decode('utf-8', errors='ignore')
                    
                    if content_type == 'text/html' and not html_content:
                        html_content = decoded
                    elif content_type == 'text/plain' and not text_content:
                        text_content = decoded
            except Exception as e:
                logger.warning(f"Failed to decode part: {e}")
                continue
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            decoded = payload.decode('utf-8', errors='ignore')
            if msg.get_content_type() == 'text/html':
                html_content = decoded
            else:
                text_content = decoded
    
    return html_content or text_content

def clean_raw_email(raw_body):
    """Clean raw email body by removing headers"""
    header_patterns = [
        'Received:', 'Received-SPF:', 'ARC-Seal:', 'ARC-Message-Signature:', 
        'ARC-Authentication-Results:', 'DKIM-Signature:', 'Authentication-Results:',
        'Return-Path:', 'Delivered-To:', 'X-', 'Message-ID:', 'Date:', 
        'MIME-Version:', 'Content-Type:', 'Content-Transfer-Encoding:',
        'Content-ID:', 'Reply-To:', 'List-', 'Precedence:'
    ]
    
    lines = raw_body.split('\n')
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
    
    return '\n'.join(clean_lines).strip()

def parse_email_body(raw_body):
    """Parse MIME email and extract clean HTML/text"""
    try:
        # If it's already clean HTML/text, return as is
        if '<html' in raw_body.lower() or '<body' in raw_body.lower():
            return raw_body
        
        if 'Content-Type:' in raw_body:
            msg = email.message_from_string(raw_body, policy=policy.default)
            content = extract_content_from_mime(msg)
            if content:
                return content
        
        return clean_raw_email(raw_body)
        
    except Exception as e:
        logger.error(f"Email parsing error: {e}")
        return clean_raw_email(raw_body)

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
    try:
        data = request.get_json() or {}
        custom_name = data.get('name', '').strip()
        
        # Validate security headers
        session_id = request.headers.get('X-Session-ID')
        security_key = request.headers.get('X-Security-Key')
        
        if not session_id or not security_key:
            logger.warning("Missing security headers in create request")
        
        if custom_name:
            username = custom_name.lower()
            username = ''.join(c for c in username if c.isalnum() or c in '-_')
            if not username:
                return jsonify({'error': 'Invalid username', 'code': 'INVALID_USERNAME'}), 400
        else:
            # Generate random name: malename + femalename + 3 digits
            male_name = random.choice(MALE_NAMES)
            female_name = random.choice(FEMALE_NAMES)
            three_digits = ''.join(random.choices(string.digits, k=3))
            username = f"{male_name}{female_name}{three_digits}"
        
        email_address = f"{username}@{DOMAIN}"
        
        # Check if email already has an active session
        conn = get_db()
        c = conn.cursor()
        
        # Check if is_active column exists and handle accordingly
        try:
            c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='sessions' AND column_name='is_active'")
            has_is_active = c.fetchone() is not None
            
            if has_is_active:
                c.execute('''
                    SELECT session_token, is_active 
                    FROM sessions 
                    WHERE email_address = %s AND expires_at > NOW()
                    ORDER BY created_at DESC 
                    LIMIT 1
                ''', (email_address,))
            else:
                c.execute('''
                    SELECT session_token
                    FROM sessions 
                    WHERE email_address = %s AND expires_at > NOW()
                    ORDER BY created_at DESC 
                    LIMIT 1
                ''', (email_address,))
        except Exception as e:
            logger.warning(f"Error checking session: {e}")
            # Fallback to simple check
            c.execute('''
                SELECT session_token
                FROM sessions 
                WHERE email_address = %s AND expires_at > NOW()
                ORDER BY created_at DESC 
                LIMIT 1
            ''', (email_address,))
        
        existing_session = c.fetchone()
        
        if existing_session:
            # Check if session is active (if is_active column exists)
            if len(existing_session) > 1 and existing_session[1] is False:
                # Session exists but is inactive, we can proceed
                pass
            elif len(existing_session) > 1 and existing_session[1]:  # is_active is True
                conn.close()
                return jsonify({
                    'error': 'This email address is already in use by another session. Please choose a different username or wait for the current session to expire.',
                    'code': 'EMAIL_IN_USE'
                }), 409
            else:
                # No is_active column, but session exists
                conn.close()
                return jsonify({
                    'error': 'This email address is already in use by another session. Please choose a different username or wait for the current session to expire.',
                    'code': 'EMAIL_IN_USE'
                }), 409
        
        # Create session token
        session_token = secrets.token_urlsafe(32)
        created_at = datetime.now()
        expires_at = created_at + timedelta(hours=1)
        
        # Check if is_active column exists
        try:
            c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='sessions' AND column_name='is_active'")
            has_is_active = c.fetchone() is not None
            
            if has_is_active:
                c.execute('''
                    INSERT INTO sessions (session_token, email_address, created_at, expires_at, last_activity, is_active)
                    VALUES (%s, %s, %s, %s, %s, %s)
                ''', (session_token, email_address, created_at, expires_at, created_at, True))
            else:
                c.execute('''
                    INSERT INTO sessions (session_token, email_address, created_at, expires_at, last_activity)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (session_token, email_address, created_at, expires_at, created_at))
        except Exception as e:
            logger.warning(f"Error with is_active column, falling back: {e}")
            c.execute('''
                INSERT INTO sessions (session_token, email_address, created_at, expires_at, last_activity)
                VALUES (%s, %s, %s, %s, %s)
            ''', (session_token, email_address, created_at, expires_at, created_at))
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Created email: {email_address}")
        
        return jsonify({
            'email': email_address,
            'session_token': session_token,
            'expires_at': expires_at.isoformat()
        })
        
    except Exception as e:
        logger.error(f"❌ Error creating email: {e}")
        return jsonify({'error': 'Failed to create session', 'code': 'SERVER_ERROR'}), 500

@app.route('/api/emails/<email_address>', methods=['GET'])
def get_emails(email_address):
    try:
        session_token = request.headers.get('X-Session-Token')
        
        if not session_token:
            return jsonify({'error': 'No session token'}), 401
        
        conn = get_db()
        c = conn.cursor(cursor_factory=RealDictCursor)
        
        # Check if is_active column exists
        try:
            c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='sessions' AND column_name='is_active'")
            has_is_active = c.fetchone() is not None
            
            if has_is_active:
                c.execute('''
                    SELECT email_address, expires_at, is_active
                    FROM sessions 
                    WHERE session_token = %s AND email_address = %s
                ''', (session_token, email_address))
            else:
                c.execute('''
                    SELECT email_address, expires_at
                    FROM sessions 
                    WHERE session_token = %s AND email_address = %s
                ''', (session_token, email_address))
        except Exception as e:
            logger.warning(f"Error checking session with is_active: {e}")
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
            # Try to mark session as inactive if column exists
            try:
                c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='sessions' AND column_name='is_active'")
                if c.fetchone():
                    c.execute('UPDATE sessions SET is_active = FALSE WHERE session_token = %s', (session_token,))
            except Exception:
                pass  # Ignore if is_active column doesn't exist or update fails
            conn.commit()
            conn.close()
            return jsonify({'error': 'Session expired'}), 401
        
        # Check if session is active (if is_active column exists)
        if 'is_active' in session_data and not session_data['is_active']:
            conn.close()
            return jsonify({'error': 'Session has been ended'}), 401
        
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
        
    except Exception as e:
        logger.error(f"❌ Error fetching emails: {e}")
        return jsonify({'error': 'Failed to fetch emails'}), 500

@app.route('/api/session/end', methods=['POST'])
def end_session():
    try:
        data = request.get_json() or {}
        session_token = data.get('session_token')
        email_address = data.get('email_address')
        
        if not session_token or not email_address:
            return jsonify({'error': 'Missing session data'}), 400
        
        conn = get_db()
        c = conn.cursor()
        
        # Check if is_active column exists
        try:
            c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='sessions' AND column_name='is_active'")
            has_is_active = c.fetchone() is not None
            
            if has_is_active:
                c.execute('''
                    UPDATE sessions 
                    SET is_active = FALSE 
                    WHERE session_token = %s AND email_address = %s
                ''', (session_token, email_address))
            else:
                # If is_active column doesn't exist, delete the session
                c.execute('''
                    DELETE FROM sessions 
                    WHERE session_token = %s AND email_address = %s
                ''', (session_token, email_address))
        except Exception as e:
            logger.warning(f"Error ending session: {e}")
            # Fallback to deletion
            c.execute('''
                DELETE FROM sessions 
                WHERE session_token = %s AND email_address = %s
            ''', (session_token, email_address))
        
        if c.rowcount == 0:
            conn.close()
            return jsonify({'error': 'Session not found'}), 404
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Session ended for: {email_address}")
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"❌ Error ending session: {e}")
        return jsonify({'error': 'Failed to end session'}), 500

@app.route('/api/webhook/inbound', methods=['POST'])
def webhook_inbound():
    try:
        json_data = request.get_json(force=True, silent=True)
        
        if not json_data:
            return jsonify({'error': 'No JSON data'}), 400
        
        logger.info("📧 INCOMING EMAIL")
        
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
        
        # Clean headers
        body = clean_raw_email(body)
        
        logger.info(f"  ✉️  From: {sender} → {recipient}")
        logger.info(f"  📝 Subject: {subject}")
        logger.info(f"  📄 Body: {len(body)} chars")
        
        # Store timestamps
        received_at = datetime.now()
        original_timestamp = json_data.get('timestamp', received_at.isoformat())
        
        # Find active session for this recipient
        conn = get_db()
        c = conn.cursor()
        
        # Check if is_active column exists
        try:
            c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='sessions' AND column_name='is_active'")
            has_is_active = c.fetchone() is not None
            
            if has_is_active:
                c.execute('''
                    SELECT session_token 
                    FROM sessions 
                    WHERE email_address = %s AND expires_at > NOW() AND is_active = TRUE
                    ORDER BY created_at DESC 
                    LIMIT 1
                ''', (recipient,))
            else:
                c.execute('''
                    SELECT session_token 
                    FROM sessions 
                    WHERE email_address = %s AND expires_at > NOW()
                    ORDER BY created_at DESC 
                    LIMIT 1
                ''', (recipient,))
        except Exception as e:
            logger.warning(f"Error finding session: {e}")
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
            
            logger.info(f"✅ Email stored: {sender} → {recipient}")
            return '', 204
        else:
            conn.close()
            logger.warning(f"⚠️ No active session for {recipient}")
            return '', 204
        
    except Exception as e:
        logger.error(f"❌ Webhook error: {e}")
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
                logger.info(f"🧹 Cleaned up {deleted} expired sessions")
        except Exception as e:
            logger.error(f"❌ Cleanup error: {e}")

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
        logger.error(f"❌ Admin stats error: {e}")
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
        logger.error(f"❌ Admin addresses error: {e}")
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
        logger.error(f"❌ Admin get emails error: {e}")
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
        logger.error(f"❌ Admin delete email error: {e}")
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
        logger.error(f"❌ Admin delete address error: {e}")
        return jsonify({'error': str(e)}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'domain': DOMAIN,
        'timestamp': datetime.utcnow().isoformat()
    })

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)

