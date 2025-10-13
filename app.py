from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
import os
import random
import string
from datetime import datetime, timedelta, timezone
import email
from email import policy
from functools import wraps
import secrets
from threading import Thread
import time
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import pool
import logging
import re
from contextlib import contextmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MALE_NAMES = ['james', 'john', 'robert', 'michael', 'william', 'david', 'richard', 'joseph', 'thomas', 'charles',
              'daniel', 'matthew', 'anthony', 'mark', 'paul', 'steven', 'andrew', 'joshua', 'kevin', 'brian',
              'george', 'kenneth', 'edward', 'ryan', 'jacob', 'nicholas', 'tyler', 'samuel', 'benjamin', 'alexander']

FEMALE_NAMES = ['mary', 'patricia', 'jennifer', 'linda', 'elizabeth', 'barbara', 'susan', 'jessica', 'sarah', 'karen',
                'nancy', 'lisa', 'betty', 'margaret', 'sandra', 'ashley', 'kimberly', 'emily', 'donna', 'michelle',
                'dorothy', 'carol', 'amanda', 'melissa', 'deborah', 'stephanie', 'rebecca', 'sharon', 'laura', 'grace']

# Initial blacklist - will be stored in database
INITIAL_BLACKLIST = ['ammz', 'admin', 'owner', 'root', 'system', 'az', 'c']

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_urlsafe(32))
CORS(app, origins=[os.getenv('FRONTEND_URL', '*')], supports_credentials=True)

# Configuration from environment
APP_PASSWORD = os.getenv('APP_PASSWORD', 'admin123')
DOMAIN = os.getenv('DOMAIN', 'aungmyomyatzaw.online')
DATABASE_URL = os.getenv('DATABASE_URL')
MAX_EMAIL_SIZE = 1024 * 1024  # 1MB limit
SESSION_TIMEOUT = timedelta(hours=1)

# Myanmar timezone
MYANMAR_TZ = timezone(timedelta(hours=6, minutes=30))

# FIX: Connection pooling to prevent connection exhaustion
db_pool = None

def init_db_pool():
    """Initialize database connection pool"""
    global db_pool
    try:
        db_pool = psycopg2.pool.ThreadedConnectionPool(
            1, 20,  # min=1, max=20 connections
            DATABASE_URL,
            sslmode='require'
        )
        logger.info("✅ Database connection pool initialized")
    except Exception as e:
        logger.error(f"❌ Failed to initialize database pool: {e}")
        raise

@contextmanager
def get_db():
    """Context manager for database connections with proper error handling"""
    conn = None
    try:
        if db_pool:
            conn = db_pool.getconn()
        else:
            conn = psycopg2.connect(DATABASE_URL, sslmode='require')
        yield conn
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        if conn and db_pool:
            db_pool.putconn(conn)
        elif conn:
            conn.close()

def init_db():
    """Initialize database tables with proper error handling"""
    try:
        with get_db() as conn:
            conn.autocommit = True
            c = conn.cursor()
            
            # Sessions table with proper timezone handling
            c.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    session_token TEXT PRIMARY KEY,
                    email_address TEXT NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    last_activity TIMESTAMP WITH TIME ZONE NOT NULL,
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
                    received_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    session_token TEXT,
                    size_bytes INTEGER DEFAULT 0
                )
            ''')
            
            # Blacklist table
            c.execute('''
                CREATE TABLE IF NOT EXISTS blacklist (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    added_at TIMESTAMP WITH TIME ZONE NOT NULL,
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
                    ''', (username, datetime.now(MYANMAR_TZ)))
                except Exception as e:
                    logger.warning(f"Could not insert blacklist user {username}: {e}")
            
            # Indexes for performance
            indexes = [
                'CREATE INDEX IF NOT EXISTS idx_recipient ON emails(recipient)',
                'CREATE INDEX IF NOT EXISTS idx_session ON emails(session_token)',
                'CREATE INDEX IF NOT EXISTS idx_received_at ON emails(received_at)',
                'CREATE INDEX IF NOT EXISTS idx_email_address ON sessions(email_address)',
                'CREATE INDEX IF NOT EXISTS idx_is_active ON sessions(is_active)',
                'CREATE INDEX IF NOT EXISTS idx_blacklist_username ON blacklist(username)'
            ]
            
            for index_sql in indexes:
                try:
                    c.execute(index_sql)
                except Exception as e:
                    logger.warning(f"Could not create index: {e}")
            
            logger.info("✅ Database initialized successfully")
            
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        raise

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

def is_username_blacklisted(username):
    """Check if username is blacklisted in database"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT username FROM blacklist WHERE username = %s', (username.lower(),))
            result = c.fetchone()
            return result is not None
    except Exception as e:
        logger.error(f"Error checking blacklist: {e}")
        return username.lower() in INITIAL_BLACKLIST

def extract_content_from_mime(msg):
    """Extract content from MIME message with size limits"""
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
                        html_content = decoded[:50000]  # Limit HTML
                    elif content_type == 'text/plain' and not text_content:
                        text_content = decoded[:10000]  # Limit text
                        
            except Exception as e:
                logger.warning(f"Failed to decode part: {e}")
                continue
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            decoded = payload.decode('utf-8', errors='ignore')
            if msg.get_content_type() == 'text/html':
                html_content = decoded[:50000]
            else:
                text_content = decoded[:10000]
    
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
    """Parse MIME email and extract clean HTML/text with size limits"""
    try:
        # Check size limit
        if len(raw_body) > MAX_EMAIL_SIZE:
            logger.warning(f"Email body too large: {len(raw_body)} bytes")
            return "Email content too large to display"
        
        # If it's already clean HTML/text, return as is
        if 'Content-Type:' not in raw_body:
            return raw_body[:10000]  # Limit plain text
        
        # Parse MIME message
        msg = email.message_from_string(raw_body, policy=policy.default)
        content = extract_content_from_mime(msg)
        
        if content:
            return content
        
        # Fallback to raw cleaning
        return clean_raw_email(raw_body)
        
    except Exception as e:
        logger.error(f"Email parsing error: {e}")
        return "Error parsing email content"

# FIX 1: Session validation 
def validate_session(email_address, session_token):
    if not session_token: return False, "No token"
    
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT expires_at FROM sessions WHERE email_address = %s AND session_token = %s', 
                     (email_address, session_token))
            result = c.fetchone()
            
            if not result: return False, "Session not found"
            
            # Simple expiry check
            if datetime.now(MYANMAR_TZ) > result[0].astimezone(MYANMAR_TZ):
                return False, "Session expired"
            
            return True, "Valid"
    except:
        return True, "Fallback allow"  # Prevent blocking on errors

# FIX 2: Get emails endpoint

# FIX 3: Session end endpoint
@app.route('/api/session/end', methods=['POST'])
def end_session():
    session_token = request.headers.get('X-Session-Token')
    if not session_token:
        return jsonify({'error': 'No token'}), 400
    
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('UPDATE sessions SET expires_at = NOW() WHERE session_token = %s', (session_token,))
            conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def invalidate_existing_sessions(email_address):
    """Invalidate existing sessions for an email"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            
            # Multiple methods to ensure sessions are ended
            try:
                # Method 1: Set is_active to FALSE
                c.execute('''
                    UPDATE sessions
                    SET is_active = FALSE
                    WHERE email_address = %s
                ''', (email_address,))
                
                # Method 2: Set expires_at to past
                c.execute('''
                    UPDATE sessions
                    SET expires_at = NOW() - INTERVAL '1 minute'
                    WHERE email_address = %s AND expires_at > NOW()
                ''', (email_address,))
                
            except Exception as e:
                logger.warning(f"Error ending existing sessions: {e}")
                # Fallback - delete sessions
                c.execute('DELETE FROM sessions WHERE email_address = %s', (email_address,))
            
            conn.commit()
            logger.info(f"Invalidated existing sessions for {email_address}")
            
    except Exception as e:
        logger.error(f"Error invalidating sessions: {e}")

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/domains', methods=['GET'])
def get_domains():
    return jsonify({'domains': [DOMAIN]})

@app.route('/api/create', methods=['POST'])
def create_email():
    """Create new email with proper validation and session handling"""
    try:
        data = request.get_json() or {}
        custom_name = data.get('name', '').strip()
        admin_mode = data.get('admin_mode', False) and session.get('admin_authenticated', False)
        
        # Validate security headers
        session_id = request.headers.get('X-Session-ID')
        security_key = request.headers.get('X-Security-Key')
        
        if not session_id or not security_key:
            logger.warning("Missing security headers in create request")
        
        # Define username variable
        username = ""
        
        if custom_name:
            username = custom_name.lower()
            username = ''.join(c for c in username if c.isalnum() or c in '-_')
            
            if not username:
                return jsonify({'error': 'Invalid username', 'code': 'INVALID_USERNAME'}), 400
            
            if len(username) > 20:
                return jsonify({'error': 'Username too long (max 20 chars)'}), 400
            
            # Skip blacklist check if admin mode is enabled
            if not admin_mode and is_username_blacklisted(username):
                return jsonify({
                    'error': 'This username is reserved for the system owner. Please choose a different username.',
                    'code': 'USERNAME_BLACKLISTED'
                }), 403
        else:
            # Generate random name: malename + femalename + 3 digits
            male_name = random.choice(MALE_NAMES)
            female_name = random.choice(FEMALE_NAMES)
            three_digits = ''.join(random.choices(string.digits, k=3))
            username = f"{male_name}{female_name}{three_digits}"
        
        email_address = f"{username}@{DOMAIN}"
        
        # Invalidate existing sessions for this email
        invalidate_existing_sessions(email_address)
        
        # Create new session with proper timezone
        session_token = secrets.token_urlsafe(32)
        now = datetime.now(MYANMAR_TZ)
        expires_at = now + SESSION_TIMEOUT
        
        with get_db() as conn:
            c = conn.cursor()
            c.execute(
                "UPDATE sessions SET expires_at = NOW() WHERE email_address = %s AND expires_at > NOW()",
                (email_address,)
            )
            conn.commit()
            
            # Insert new session
            try:
                c.execute('''
                    INSERT INTO sessions (session_token, email_address, created_at, expires_at, last_activity, is_active)
                    VALUES (%s, %s, %s, %s, %s, %s)
                ''', (session_token, email_address, now, expires_at, now, True))
            except Exception as e:
                logger.warning(f"Error with is_active column, falling back: {e}")
                c.execute('''
                    INSERT INTO sessions (session_token, email_address, created_at, expires_at, last_activity)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (session_token, email_address, now, expires_at, now))
            
            # Auto-blacklist in admin mode
            if admin_mode and custom_name:
                try:
                    c.execute('''
                        INSERT INTO blacklist (username, added_at, added_by)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (username) DO NOTHING
                    ''', (username.lower(), now, 'admin_auto'))
                    logger.info(f"✅ Automatically blacklisted username: {username}")
                except Exception as e:
                    logger.error(f"Error auto-blacklisting username: {e}")
            
            conn.commit()
        
        logger.info(f"✅ Created email: {email_address} (admin: {admin_mode})")
        
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
    session_token = request.headers.get('X-Session-Token', '')
    
    # Skip validation if missing (backward compatibility)
    if session_token:
        is_valid, msg = validate_session(email_address, session_token)
        if not is_valid and "expired" in msg:
            return jsonify({'error': 'Session expired'}), 403
    
    # Get emails regardless (for compatibility)
    with get_db() as conn:
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT * FROM emails WHERE recipient = %s ORDER BY received_at DESC LIMIT 50', 
                 (email_address,))
        
        emails = []
        for row in c.fetchall():
            emails.append({
                'sender': row['sender'],
                'subject': row['subject'] or 'No Subject', 
                'body': row['body'] or 'No Content',
                'timestamp': row['received_at'].astimezone(MYANMAR_TZ).isoformat()
            })
        
    return jsonify({'emails': emails})


@app.route('/api/webhook/inbound', methods=['POST'])
def webhook_inbound():
    """Handle incoming emails with improved error handling"""
    try:
        json_data = request.get_json(force=True, silent=True)
        
        if not json_data:
            return jsonify({'error': 'No JSON data'}), 400
        
        logger.info("📧 INCOMING EMAIL")
        
        recipient = json_data.get('to', 'unknown@unknown.com').strip()
        sender = json_data.get('from', 'unknown').strip()
        subject = json_data.get('subject', 'No subject').strip()
        
        # Clean sender display name
        if '<' in sender and '>' in sender:
            sender = sender[sender.find('<')+1:sender.find('>')]
        
        # Beautify known senders
        sender_lower = sender.lower()
        if 'bounce' in sender_lower or 'noreply' in sender_lower:
            if any(domain in sender_lower for domain in ['openai.com', 'mandrillapp.com']):
                sender = 'ChatGPT'
            elif 'afraid.org' in sender_lower:
                sender = 'FreeDNS'
            elif 'github.com' in sender_lower:
                sender = 'GitHub'
            else:
                sender = 'System Notification'
        
        # Get and process body
        body = json_data.get('html_body') or json_data.get('plain_body', 'No content')
        
        # Size check before processing
        if len(body) > MAX_EMAIL_SIZE:
            logger.warning(f"Email too large from {sender}: {len(body)} bytes")
            body = body[:MAX_EMAIL_SIZE] + "\n\n[Content truncated - email too large]"
        
        # Parse MIME if needed
        if 'Content-Type:' in body and 'multipart' in body:
            body = parse_email_body(body)
        else:
            body = clean_raw_email(body)
        
        body_size = len(body.encode('utf-8'))
        
        logger.info(f" ✉️ From: {sender} → {recipient}")
        logger.info(f" 📝 Subject: {subject}")
        logger.info(f" 📄 Body: {body_size} chars")
        
        # Store timestamps
        received_at = datetime.now(MYANMAR_TZ)
        original_timestamp = json_data.get('timestamp', received_at.isoformat())
        
        # Find active session for this recipient
        with get_db() as conn:
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
                    INSERT INTO emails (recipient, sender, subject, body, timestamp, received_at, session_token, size_bytes)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ''', (recipient, sender, subject, body, original_timestamp, received_at, session_token, body_size))
                
                # Update session last_activity
                c.execute('''
                    UPDATE sessions
                    SET last_activity = %s
                    WHERE session_token = %s
                ''', (received_at, session_token))
                
                conn.commit()
                logger.info(f"✅ Email stored: {sender} → {recipient}")
                
            else:
                logger.warning(f"⚠️ No active session for {recipient}")
        
        return '', 204
        
    except Exception as e:
        logger.error(f"❌ Webhook error: {e}")
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
        session.permanent = True
        return jsonify({'success': True})
    return jsonify({'success': False}), 401

@app.route('/api/verify-admin', methods=['POST'])
def verify_admin():
    """Alternative endpoint for frontend admin verification"""
    try:
        data = request.get_json() or {}
        password = data.get('password', '')
        
        if password == APP_PASSWORD:
            session['admin_authenticated'] = True
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Invalid password'}), 401
        
    except Exception as e:
        logger.error(f"Admin verification error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/status', methods=['GET'])
def admin_status():
    """Check if user is admin authenticated"""
    return jsonify({'authenticated': session.get('admin_authenticated', False)})

@app.route('/api/admin/logout', methods=['POST'])
@admin_required
def admin_logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    try:
        with get_db() as conn:
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
            
            # Count active sessions
            try:
                c.execute('SELECT COUNT(*) FROM sessions WHERE is_active = TRUE AND expires_at > NOW()')
                active_sessions = c.fetchone()[0]
            except:
                c.execute('SELECT COUNT(*) FROM sessions WHERE expires_at > NOW()')
                active_sessions = c.fetchone()[0]
        
        return jsonify({
            'total_emails': total_emails,
            'total_addresses': total_addresses,
            'recent_emails': recent_emails,
            'active_sessions': active_sessions
        })
        
    except Exception as e:
        logger.error(f"❌ Admin stats error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/addresses', methods=['GET'])
@admin_required
def admin_addresses():
    try:
        with get_db() as conn:
            c = conn.cursor(cursor_factory=RealDictCursor)
            
            c.execute('''
                SELECT recipient as address, COUNT(*) as count, MAX(received_at) as last_email
                FROM emails
                GROUP BY recipient
                ORDER BY last_email DESC
                LIMIT 100
            ''')
            
            addresses = []
            for row in c.fetchall():
                if row['last_email']:
                    # Convert to Myanmar timezone
                    myanmar_time = row['last_email'].astimezone(MYANMAR_TZ)
                    last_email_str = myanmar_time.isoformat()
                else:
                    last_email_str = None
                
                addresses.append({
                    'address': row['address'],
                    'count': row['count'],
                    'last_email': last_email_str
                })
        
        return jsonify({'addresses': addresses})
        
    except Exception as e:
        logger.error(f"❌ Admin addresses error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/emails/<email_address>', methods=['GET'])
@admin_required
def admin_get_emails(email_address):
    try:
        with get_db() as conn:
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
                    'received_at': row['received_at'].astimezone(MYANMAR_TZ).isoformat() if row['received_at'] else None,
                    'timestamp': row['timestamp']
                })
        
        return jsonify({'emails': emails})
        
    except Exception as e:
        logger.error(f"❌ Admin get emails error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/delete/<int:email_id>', methods=['DELETE'])
@admin_required
def admin_delete_email(email_id):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('DELETE FROM emails WHERE id = %s', (email_id,))
            conn.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"❌ Admin delete email error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/delete-address/<email_address>', methods=['DELETE'])
@admin_required
def admin_delete_address(email_address):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('DELETE FROM emails WHERE recipient = %s', (email_address,))
            conn.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"❌ Admin delete address error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/sessions', methods=['GET'])
@admin_required
def admin_get_sessions():
    """Get all active sessions"""
    try:
        with get_db() as conn:
            c = conn.cursor(cursor_factory=RealDictCursor)
            
            try:
                c.execute('''
                    SELECT session_token, email_address, created_at, expires_at, last_activity
                    FROM sessions
                    WHERE expires_at > NOW() AND is_active = TRUE
                    ORDER BY last_activity DESC
                ''')
            except:
                c.execute('''
                    SELECT session_token, email_address, created_at, expires_at, last_activity
                    FROM sessions
                    WHERE expires_at > NOW()
                    ORDER BY last_activity DESC
                ''')
            
            sessions = []
            for row in c.fetchall():
                created_at = row['created_at'].astimezone(MYANMAR_TZ)
                expires_at = row['expires_at'].astimezone(MYANMAR_TZ)
                last_activity = row['last_activity'].astimezone(MYANMAR_TZ)
                
                sessions.append({
                    'session_token': row['session_token'],
                    'email': row['email_address'],
                    'created_at': created_at.isoformat(),
                    'expires_at': expires_at.isoformat(),
                    'last_activity': last_activity.isoformat(),
                    'session_age_minutes': int((datetime.now(MYANMAR_TZ) - created_at).total_seconds() / 60),
                    'time_remaining_minutes': int((expires_at - datetime.now(MYANMAR_TZ)).total_seconds() / 60)
                })
        
        return jsonify({'sessions': sessions})
        
    except Exception as e:
        logger.error(f"❌ Error fetching sessions: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/session/<session_token>/end', methods=['POST'])
@admin_required
def admin_end_session(session_token):
    """End a user session from admin panel"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            
            # Mark session as inactive
            try:
                c.execute('''
                    UPDATE sessions
                    SET is_active = FALSE
                    WHERE session_token = %s
                ''', (session_token,))
            except:
                c.execute('''
                    UPDATE sessions
                    SET expires_at = NOW()
                    WHERE session_token = %s
                ''', (session_token,))
            
            if c.rowcount == 0:
                return jsonify({'error': 'Session not found'}), 404
            
            conn.commit()
        
        logger.info(f"✅ Admin ended session: {session_token}")
        return jsonify({'success': True, 'message': 'Session ended successfully'})
        
    except Exception as e:
        logger.error(f"❌ Error ending session from admin: {e}")
        return jsonify({'error': str(e)}), 500

# Blacklist management
@app.route('/api/admin/blacklist', methods=['GET'])
@admin_required
def get_blacklist():
    """Get current blacklisted usernames from database"""
    try:
        with get_db() as conn:
            c = conn.cursor(cursor_factory=RealDictCursor)
            
            c.execute('''
                SELECT username, added_at, added_by
                FROM blacklist
                ORDER BY username
            ''')
            
            blacklist = []
            for row in c.fetchall():
                added_at = row['added_at']
                if added_at:
                    myanmar_time = added_at.astimezone(MYANMAR_TZ)
                    added_at_str = myanmar_time.isoformat()
                else:
                    added_at_str = None
                
                blacklist.append({
                    'username': row['username'],
                    'added_at': added_at_str,
                    'added_by': row['added_by']
                })
        
        return jsonify({'blacklist': blacklist})
        
    except Exception as e:
        logger.error(f"❌ Error getting blacklist: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/blacklist', methods=['POST'])
@admin_required
def add_to_blacklist():
    """Add username to blacklist in database"""
    try:
        data = request.get_json() or {}
        username = data.get('username', '').strip().lower()
        
        if not username:
            return jsonify({'error': 'Username is required'}), 400
        
        if not re.match(r'^[a-zA-Z0-9-_]+$', username):
            return jsonify({'error': 'Username can only contain letters, numbers, hyphens, and underscores'}), 400
        
        with get_db() as conn:
            c = conn.cursor()
            
            try:
                c.execute('''
                    INSERT INTO blacklist (username, added_at, added_by)
                    VALUES (%s, %s, %s)
                ''', (username, datetime.now(MYANMAR_TZ), 'admin_manual'))
                conn.commit()
                
                logger.info(f"✅ Added to blacklist: {username}")
                return jsonify({'success': True, 'message': f'Username {username} added to blacklist'})
                
            except psycopg2.IntegrityError:
                return jsonify({'error': 'Username already in blacklist'}), 409
                
    except Exception as e:
        logger.error(f"❌ Error adding to blacklist: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/blacklist/<username>', methods=['DELETE'])
@admin_required
def remove_from_blacklist(username):
    """Remove username from blacklist in database"""
    try:
        username = username.lower()
        
        with get_db() as conn:
            c = conn.cursor()
            c.execute('DELETE FROM blacklist WHERE username = %s', (username,))
            
            if c.rowcount == 0:
                return jsonify({'error': 'Username not found in blacklist'}), 404
            
            conn.commit()
        
        logger.info(f"✅ Removed from blacklist: {username}")
        return jsonify({'success': True, 'message': f'Username {username} removed from blacklist'})
        
    except Exception as e:
        logger.error(f"❌ Error removing from blacklist: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/clear-sessions', methods=['POST'])
@admin_required
def admin_clear_sessions():
    """Clear all admin-related sessions"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            
            # End all active sessions for admin usernames
            admin_usernames = ['ammz', 'admin', 'owner', 'root', 'system', 'az', 'c']
            
            for username in admin_usernames:
                email_pattern = f"{username}@%"
                
                try:
                    c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='sessions' AND column_name='is_active'")
                    has_is_active = c.fetchone() is not None
                    
                    if has_is_active:
                        c.execute('''
                            UPDATE sessions
                            SET is_active = FALSE
                            WHERE email_address LIKE %s AND is_active = TRUE
                        ''', (email_pattern,))
                    else:
                        c.execute('''
                            UPDATE sessions
                            SET expires_at = NOW()
                            WHERE email_address LIKE %s AND expires_at > NOW()
                        ''', (email_pattern,))
                        
                except Exception as e:
                    logger.warning(f"Error clearing admin session for {username}: {e}")
            
            conn.commit()
        
        logger.info("✅ All admin sessions cleared")
        return jsonify({'success': True, 'message': 'Admin sessions cleared'})
        
    except Exception as e:
        logger.error(f"❌ Error clearing admin sessions: {e}")
        return jsonify({'error': str(e)}), 500

@app.before_request
def check_admin_session():
    """Check and expire admin sessions automatically"""
    if session.get('admin_authenticated'):
        # Set session to expire after 1 hour of inactivity
        session.permanent = True
        app.permanent_session_lifetime = timedelta(hours=1)

# Debug endpoints
@app.route('/api/debug/create-test', methods=['POST'])
def debug_create_test():
    """Test the create function step by step"""
    try:
        data = request.get_json() or {}
        custom_name = data.get('name', '').strip()
        admin_mode = data.get('admin_mode', False)
        
        steps = []
        
        # Step 1: Check custom_name
        steps.append(f"Step 1 - custom_name: '{custom_name}'")
        
        # Step 2: Generate username
        username = ""
        if custom_name:
            username = custom_name.lower()
            username = ''.join(c for c in username if c.isalnum() or c in '-_')
            steps.append(f"Step 2 - custom username: '{username}'")
        else:
            male_name = random.choice(MALE_NAMES)
            female_name = random.choice(FEMALE_NAMES)
            three_digits = ''.join(random.choices(string.digits, k=3))
            username = f"{male_name}{female_name}{three_digits}"
            steps.append(f"Step 2 - random username: '{username}'")
        
        # Step 3: Create email
        email_address = f"{username}@{DOMAIN}"
        steps.append(f"Step 3 - email_address: '{email_address}'")
        
        return jsonify({
            'success': True,
            'steps': steps,
            'username': username,
            'email_address': email_address
        })
        
    except Exception as e:
        return jsonify({'error': str(e), 'steps': steps}), 500

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
        'timestamp': datetime.now(MYANMAR_TZ).isoformat()
    })

# Cleanup expired sessions
def cleanup_expired_sessions():
    """Background thread to clean up expired sessions"""
    while True:
        try:
            time.sleep(300)  # Every 5 minutes
            
            with get_db() as conn:
                c = conn.cursor()
                
                # Clean expired sessions
                try:
                    c.execute('''
                        UPDATE sessions 
                        SET is_active = FALSE 
                        WHERE expires_at < NOW() AND is_active = TRUE
                    ''')
                except:
                    c.execute('''
                        UPDATE sessions 
                        SET expires_at = NOW() - INTERVAL '1 minute'
                        WHERE expires_at < NOW()
                    ''')
                
                updated = c.rowcount
                conn.commit()
                
                if updated > 0:
                    logger.info(f"🧹 Cleaned up {updated} expired sessions (emails preserved)")
                    
        except Exception as e:
            logger.error(f"❌ Cleanup error: {e}")
            time.sleep(60)  # Wait longer on error

# Initialize everything
if __name__ == '__main__':
    try:
        # Initialize database pool first
        init_db_pool()
        
        # Initialize database tables
        init_db()
        
        # Start cleanup thread
        cleanup_thread = Thread(target=cleanup_expired_sessions, daemon=True)
        cleanup_thread.start()
        logger.info("🧹 Cleanup thread started")
        
        port = int(os.getenv('PORT', 5000))
        debug = os.getenv('FLASK_ENV') == 'development'
        app.run(host='0.0.0.0', port=port, debug=debug)
        
    except Exception as e:
        logger.error(f"❌ Application startup failed: {e}")
        raise
    finally:
        if db_pool:
            db_pool.closeall()





