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
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
MALE_NAMES = ['james', 'john', 'robert', 'michael', 'william', 'david', 'richard', 'joseph', 'thomas', 'charles']
FEMALE_NAMES = ['mary', 'patricia', 'jennifer', 'linda', 'elizabeth', 'barbara', 'susan', 'jessica', 'sarah', 'karen']
INITIAL_BLACKLIST = ['ammz', 'admin', 'owner', 'root', 'system', 'az', 'c']

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_urlsafe(32))
CORS(app, origins=[os.getenv('FRONTEND_URL', '*')], supports_credentials=True)

APP_PASSWORD = os.getenv('APP_PASSWORD', 'admin123')
DOMAIN = os.getenv('DOMAIN', 'aungmyomyatzaw.online')
DATABASE_URL = os.getenv('DATABASE_URL')

# Database connection
def get_db():
    return psycopg2.connect(DATABASE_URL, sslmode='require')

def init_db():
    try:
        conn = get_db()
        conn.autocommit = True
        c = conn.cursor()
        
        # Sessions table
        c.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_token TEXT PRIMARY KEY,
                email_address TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                last_activity TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT TRUE
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
                session_token TEXT
            )
        ''')
        
        # Blacklist table
        c.execute('''
            CREATE TABLE IF NOT EXISTS blacklist (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                added_at TIMESTAMP NOT NULL,
                added_by TEXT DEFAULT 'system'
            )
        ''')
        
        # Insert initial blacklist
        for username in INITIAL_BLACKLIST:
            try:
                c.execute('''
                    INSERT INTO blacklist (username, added_at) 
                    VALUES (%s, %s)
                    ON CONFLICT (username) DO NOTHING
                ''', (username, datetime.now()))
            except Exception as e:
                logger.warning(f"Could not insert blacklist user {username}: {e}")
        
        # Create indexes
        c.execute('CREATE INDEX IF NOT EXISTS idx_recipient ON emails(recipient)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_session ON emails(session_token)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_received_at ON emails(received_at)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_email_address ON sessions(email_address)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_is_active ON sessions(is_active)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_blacklist_username ON blacklist(username)')
        
        conn.close()
        logger.info("✅ Database initialized successfully")
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")

# Admin decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Initialize database
init_db()

def is_username_blacklisted(username):
    """Check if username is blacklisted"""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT username FROM blacklist WHERE username = %s', (username.lower(),))
        result = c.fetchone()
        conn.close()
        return result is not None
    except Exception as e:
        logger.error(f"Error checking blacklist: {e}")
        return username.lower() in INITIAL_BLACKLIST

def validate_session(email_address, session_token):
    """Validate session token"""
    try:
        conn = get_db()
        c = conn.cursor()
        
        c.execute('''
            SELECT session_token FROM sessions 
            WHERE email_address = %s AND session_token = %s 
            AND expires_at > NOW() AND is_active = TRUE
        ''', (email_address, session_token))
        
        session_data = c.fetchone()
        conn.close()
        
        if not session_data:
            return False, "Invalid or expired session"
        
        return True, "Valid session"
    except Exception as e:
        logger.error(f"Session validation error: {e}")
        return False, str(e)

def clean_email_body(raw_body):
    """Clean and extract email content"""
    try:
        # Remove headers and footers
        lines = raw_body.split('\n')
        clean_lines = []
        in_body = False
        
        for line in lines:
            stripped = line.strip()
            
            # Skip empty lines at start
            if not in_body and not stripped:
                continue
                
            # Start capturing after headers
            if not in_body and (stripped.startswith('Content-') or '<html' in stripped.lower() or stripped and ':' not in stripped):
                in_body = True
                
            if in_body:
                clean_lines.append(line)
        
        clean_body = '\n'.join(clean_lines)
        
        # Remove HTML tags if present but keep content
        if '<' in clean_body and '>' in clean_body:
            clean_body = re.sub(r'<[^>]+>', ' ', clean_body)
        
        # Clean up whitespace
        clean_body = re.sub(r'\s+', ' ', clean_body).strip()
        
        return clean_body if clean_body else "No readable content found"
        
    except Exception as e:
        logger.error(f"Error cleaning email body: {e}")
        return raw_body

# Routes
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
        custom_name = data.get('name', '').strip().lower()
        admin_mode = data.get('admin_mode', False)
        
        # Generate username
        if custom_name:
            username = ''.join(c for c in custom_name if c.isalnum() or c in '-_')
            if not username:
                return jsonify({'error': 'Invalid username', 'code': 'INVALID_USERNAME'}), 400
            
            # Check blacklist unless admin mode
            if not admin_mode and is_username_blacklisted(username):
                return jsonify({
                    'error': 'This username is reserved. Please choose a different username.',
                    'code': 'USERNAME_BLACKLISTED'
                }), 403
        else:
            # Generate random username
            male_name = random.choice(MALE_NAMES)
            female_name = random.choice(FEMALE_NAMES)
            three_digits = ''.join(random.choices(string.digits, k=3))
            username = f"{male_name}{female_name}{three_digits}"
        
        email_address = f"{username}@{DOMAIN}"
        
        conn = get_db()
        c = conn.cursor()
        
        # End any existing sessions for this email
        c.execute('DELETE FROM sessions WHERE email_address = %s', (email_address,))
        
        # Create new session
        session_token = secrets.token_urlsafe(32)
        created_at = datetime.now()
        expires_at = created_at + timedelta(hours=1)
        
        c.execute('''
            INSERT INTO sessions (session_token, email_address, created_at, expires_at, last_activity, is_active)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (session_token, email_address, created_at, expires_at, created_at, True))
        
        # Auto-blacklist if admin mode with custom name
        if admin_mode and custom_name:
            try:
                c.execute('''
                    INSERT INTO blacklist (username, added_at, added_by) 
                    VALUES (%s, %s, %s)
                    ON CONFLICT (username) DO NOTHING
                ''', (username, datetime.now(), 'admin_auto'))
                logger.info(f"✅ Auto-blacklisted: {username}")
            except Exception as e:
                logger.error(f"Error auto-blacklisting: {e}")
        
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
        
        # Mark session as inactive
        c.execute('''
            UPDATE sessions 
            SET is_active = FALSE 
            WHERE session_token = %s AND email_address = %s
        ''', (session_token, email_address))
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Session ended: {email_address}")
        return jsonify({'success': True, 'message': 'Session ended'})
        
    except Exception as e:
        logger.error(f"❌ Error ending session: {e}")
        return jsonify({'error': 'Failed to end session'}), 500

@app.route('/api/emails/<email_address>', methods=['GET'])
def get_emails(email_address):
    try:
        session_token = request.headers.get('X-Session-Token', '')
        
        # Validate session
        is_valid, message = validate_session(email_address, session_token)
        if not is_valid:
            return jsonify({'error': message}), 403
        
        conn = get_db()
        c = conn.cursor(cursor_factory=RealDictCursor)
        
        c.execute('''
            SELECT id, sender, subject, body, timestamp, received_at
            FROM emails 
            WHERE recipient = %s AND session_token = %s
            ORDER BY received_at DESC
        ''', (email_address, session_token))
        
        emails = []
        for row in c.fetchall():
            emails.append({
                'id': row['id'],
                'sender': row['sender'],
                'subject': row['subject'],
                'body': clean_email_body(row['body']),
                'timestamp': row['timestamp'],
                'received_at': row['received_at'].isoformat() if row['received_at'] else None
            })
        
        conn.close()
        return jsonify({'emails': emails})
        
    except Exception as e:
        logger.error(f"❌ Error getting emails: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/webhook/inbound', methods=['POST'])
def webhook_inbound():
    try:
        json_data = request.get_json(force=True, silent=True) or {}
        
        recipient = json_data.get('to', '')
        sender = json_data.get('from', 'Unknown')
        subject = json_data.get('subject', 'No subject')
        body = json_data.get('html_body') or json_data.get('plain_body', 'No content')
        
        # Clean sender
        if '<' in sender and '>' in sender:
            sender = sender[sender.find('<')+1:sender.find('>')]
        
        logger.info(f"📧 Received email: {sender} → {recipient}")
        
        # Find active session
        conn = get_db()
        c = conn.cursor()
        
        c.execute('''
            SELECT session_token 
            FROM sessions 
            WHERE email_address = %s AND expires_at > NOW() AND is_active = TRUE
            LIMIT 1
        ''', (recipient,))
        
        session_data = c.fetchone()
        
        if session_data:
            session_token = session_data[0]
            received_at = datetime.now()
            
            # Store email
            c.execute('''
                INSERT INTO emails (recipient, sender, subject, body, timestamp, received_at, session_token)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (recipient, sender, subject, body, received_at.isoformat(), received_at, session_token))
            
            # Update session activity
            c.execute('UPDATE sessions SET last_activity = %s WHERE session_token = %s', (received_at, session_token))
            
            conn.commit()
            logger.info(f"✅ Email stored: {recipient}")
        else:
            logger.warning(f"⚠️ No active session for {recipient}")
        
        conn.close()
        return '', 204
        
    except Exception as e:
        logger.error(f"❌ Webhook error: {e}")
        return jsonify({'error': str(e)}), 400

# Admin Routes
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
        
        c.execute("SELECT COUNT(*) FROM emails WHERE received_at > NOW() - INTERVAL '1 day'")
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
            SELECT recipient as address, COUNT(*) as count, MAX(received_at) as last_email
            FROM emails
            GROUP BY recipient
            ORDER BY last_email DESC
        ''')
        
        addresses = []
        for row in c.fetchall():
            addresses.append({
                'address': row['address'],
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
                'body': clean_email_body(row['body']),
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

@app.route('/api/admin/sessions', methods=['GET'])
@admin_required
def admin_get_sessions():
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=RealDictCursor)
        
        c.execute('''
            SELECT session_token, email_address, created_at, expires_at, last_activity
            FROM sessions 
            WHERE expires_at > NOW() AND is_active = TRUE
            ORDER BY last_activity DESC
        ''')
        
        sessions = []
        for row in c.fetchall():
            sessions.append({
                'session_token': row['session_token'],
                'email': row['email_address'],
                'created_at': row['created_at'].isoformat(),
                'expires_at': row['expires_at'].isoformat(),
                'last_activity': row['last_activity'].isoformat()
            })
        
        conn.close()
        return jsonify({'sessions': sessions})
        
    except Exception as e:
        logger.error(f"❌ Error fetching sessions: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/session/<session_token>/end', methods=['POST'])
@admin_required
def admin_end_session(session_token):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('UPDATE sessions SET is_active = FALSE WHERE session_token = %s', (session_token,))
        conn.commit()
        conn.close()
        logger.info(f"✅ Admin ended session: {session_token}")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"❌ Error ending session: {e}")
        return jsonify({'error': str(e)}), 500

# Blacklist management
@app.route('/api/admin/blacklist', methods=['GET'])
@admin_required
def get_blacklist():
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT username, added_at, added_by FROM blacklist ORDER BY username')
        
        blacklist = []
        for row in c.fetchall():
            blacklist.append({
                'username': row['username'],
                'added_at': row['added_at'].isoformat(),
                'added_by': row['added_by']
            })
        
        conn.close()
        return jsonify({'blacklist': blacklist})
    except Exception as e:
        logger.error(f"❌ Error getting blacklist: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/blacklist', methods=['POST'])
@admin_required
def add_to_blacklist():
    try:
        data = request.get_json() or {}
        username = data.get('username', '').strip().lower()
        
        if not username:
            return jsonify({'error': 'Username is required'}), 400
        
        if not re.match(r'^[a-zA-Z0-9-_]+$', username):
            return jsonify({'error': 'Username can only contain letters, numbers, hyphens, and underscores'}), 400
        
        conn = get_db()
        c = conn.cursor()
        
        try:
            c.execute('INSERT INTO blacklist (username, added_at, added_by) VALUES (%s, %s, %s)', 
                     (username, datetime.now(), 'admin_manual'))
            conn.commit()
            conn.close()
            logger.info(f"✅ Added to blacklist: {username}")
            return jsonify({'success': True, 'message': f'Username {username} added to blacklist'})
        except psycopg2.IntegrityError:
            conn.close()
            return jsonify({'error': 'Username already in blacklist'}), 409
        
    except Exception as e:
        logger.error(f"❌ Error adding to blacklist: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/blacklist/<username>', methods=['DELETE'])
@admin_required
def remove_from_blacklist(username):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('DELETE FROM blacklist WHERE username = %s', (username,))
        conn.commit()
        conn.close()
        logger.info(f"✅ Removed from blacklist: {username}")
        return jsonify({'success': True, 'message': f'Username {username} removed from blacklist'})
    except Exception as e:
        logger.error(f"❌ Error removing from blacklist: {e}")
        return jsonify({'error': str(e)}), 500

# Cleanup expired sessions
def cleanup_expired_sessions():
    while True:
        time.sleep(300)  # Every 5 minutes
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("UPDATE sessions SET is_active = FALSE WHERE expires_at < NOW() AND is_active = TRUE")
            deleted = c.rowcount
            conn.commit()
            conn.close()
            if deleted > 0:
                logger.info(f"🔄 Deactivated {deleted} expired sessions")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")

# Start cleanup thread
cleanup_thread = Thread(target=cleanup_expired_sessions, daemon=True)
cleanup_thread.start()

# Health check
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
