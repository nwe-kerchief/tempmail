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
import mailparser
import html2text
from bs4 import BeautifulSoup

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

        c.execute("""
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
        """)
        
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
        
        conn.close()
        logger.info("âœ… Database initialized successfully")
    except Exception as e:
        logger.error(f"âŒ Database initialization failed: {e}")

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_authenticated'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

init_db()

def is_username_blacklisted(username):
    """Check if username is blacklisted in database"""
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

# =============================================================================
# BEAUTIFUL EMAIL RENDERING SYSTEM
# =============================================================================

def parse_email_beautifully(raw_email):
    """Main function: Parse any email and make it beautiful"""
    try:
        # Use mail-parser to get clean content
        mail = mailparser.parse_from_string(raw_email)
        
        parsed_data = {
            'subject': mail.subject or 'No subject',
            'from_email': extract_simple_sender(mail),
            'body_plain': '',
            'body_html': '',
            'attachments': len(mail.attachments)
        }
        
        # Get plain text
        if mail.text_plain:
            parsed_data['body_plain'] = '\n'.join(mail.text_plain)
        elif mail.body:
            parsed_data['body_plain'] = mail.body
            
        # Get HTML
        if mail.text_html:
            parsed_data['body_html'] = '\n'.join(mail.text_html)
            
        logger.info(f"✅ Email parsed: {parsed_data['from_email']}")
        return parsed_data
        
    except Exception as e:
        logger.error(f"❌ Parse error: {e}")
        return parse_email_simple_fallback(raw_email)

def extract_simple_sender(mail):
    """Extract sender simply"""
    if mail.from_:
        try:
            if isinstance(mail.from_[0], (list, tuple)) and len(mail.from_[0]) > 1:
                return mail.from_[0][1]
            return str(mail.from_[0])
        except:
            pass
    return 'Unknown'

def parse_email_simple_fallback(raw_email):
    """Simple fallback parsing"""
    try:
        msg = email.message_from_string(raw_email, policy=policy.default)
        return {
            'subject': msg.get('subject', 'No subject'),
            'from_email': msg.get('from', 'Unknown'),
            'body_plain': extract_simple_content(msg),
            'body_html': '',
            'attachments': 0
        }
    except:
        return {
            'subject': 'Failed to parse',
            'from_email': 'Unknown',
            'body_plain': 'This email could not be parsed.',
            'body_html': '',
            'attachments': 0
        }

def extract_simple_content(msg):
    """Extract content from email"""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        return payload.decode('utf-8', errors='ignore')
                except:
                    continue
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode('utf-8', errors='ignore')
    return body

def render_beautiful_email(parsed_email):
    """Make email beautiful based on its content"""
    text = parsed_email.get('body_plain', '')
    html = parsed_email.get('body_html', '')
    
    # Extract verification code
    verification_code = extract_single_verification_code(text)
    
    # Choose rendering method
    if verification_code:
        return render_verification_email(text, verification_code)
    elif html and len(html) > 200:
        return render_html_email(html)
    else:
        return render_text_email(text)

def extract_single_verification_code(text):
    """Find the real verification code (not false positives)"""
    # Look for 6-digit codes near verification words
    lines = text.split('\n')
    
    for i, line in enumerate(lines):
        line_lower = line.lower()
        if any(word in line_lower for word in ['code', 'verification', 'verify', 'confirm', 'otp']):
            # Check this line and next 2 lines for 6-digit code
            for j in range(i, min(i+3, len(lines))):
                code_match = re.search(r'\b(\d{6})\b', lines[j])
                if code_match:
                    return code_match.group(1)
    
    return None

def render_verification_email(text, verification_code):
    """Beautiful verification email with big code box"""
    clean_text = clean_email_text(text)
    
    return f'''
    <div class="beautiful-email">
        <div class="verification-hero">
            <div class="verification-badge">Verification Code</div>
            <div class="verification-code-large">{verification_code}</div>
            <div class="verification-hint">Copy this code to verify your account</div>
        </div>
        <div class="email-content-text">
            {format_text_as_html(clean_text)}
        </div>
    </div>
    '''

def render_html_email(html_content):
    """Safe HTML email display"""
    safe_html = sanitize_html(html_content)
    return f'''
    <div class="beautiful-email">
        <div class="html-email-container">
            {safe_html}
        </div>
    </div>
    '''

def render_text_email(text):
    """Clean text email display"""
    clean_text = clean_email_text(text)
    return f'''
    <div class="beautiful-email">
        <div class="text-email-container">
            {format_text_as_html(clean_text)}
        </div>
    </div>
    '''

def clean_email_text(text):
    """Remove email headers and junk"""
    if not text:
        return "No content"
    
    lines = text.split('\n')
    clean_lines = []
    in_body = False
    
    header_patterns = [
        'Received:', 'From:', 'To:', 'Subject:', 'Date:', 'Return-Path:',
        'Delivered-To:', 'DKIM-Signature:', 'Content-Type:', 'MIME-Version:'
    ]
    
    for line in lines:
        line = line.strip()
        if not line:
            if clean_lines:
                clean_lines.append('')
            continue
            
        is_header = any(line.startswith(pattern) for pattern in header_patterns)
        
        if is_header and not in_body:
            continue
            
        if not is_header:
            in_body = True
            
        if in_body:
            clean_lines.append(line)
    
    return '\n'.join(clean_lines).strip()

def format_text_as_html(text):
    """Convert plain text to formatted HTML"""
    if not text:
        return '<p class="no-content">No readable content</p>'
    
    paragraphs = re.split(r'\n\s*\n', text)
    html_paragraphs = []
    
    for paragraph in paragraphs:
        paragraph = paragraph.strip()
        if len(paragraph) > 10:
            # Convert URLs to links
            paragraph = re.sub(
                r'(https?://[^\s]+)',
                r'<a href="\1" target="_blank" class="text-link">\1</a>',
                paragraph
            )
            html_paragraphs.append(f'<p>{escapeHtml(paragraph)}</p>')
    
    return '\n'.join(html_paragraphs) if html_paragraphs else '<p class="no-content">No readable content</p>'

def sanitize_html(html):
    """Make HTML safe to display"""
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, 'html.parser')
        
        # Remove dangerous tags
        for tag in soup(['script', 'style', 'meta', 'link', 'head', 'form']):
            tag.decompose()
        
        # Keep only safe tags
        safe_tags = ['div', 'p', 'span', 'br', 'strong', 'em', 'b', 'i', 'u', 'a', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'img']
        for tag in soup.find_all(True):
            if tag.name not in safe_tags:
                tag.unwrap()
        
        # Clean attributes
        for tag in soup.find_all():
            if tag.name == 'a':
                tag.attrs = {'href': tag.get('href', '#'), 'class': 'text-link', 'target': '_blank'}
            elif tag.name == 'img':
                tag.attrs = {'src': tag.get('src', ''), 'class': 'safe-image'}
            else:
                tag.attrs = {}
        
        return str(soup)
    except:
        return '<p>Could not display HTML content</p>'

def escapeHtml(text):
    """Basic HTML escaping"""
    if not text:
        return ""
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


def validate_session(email_address, session_token):
    """Validate if session is valid"""
    try:
        conn = get_db()
        c = conn.cursor()
        
        # Check if session exists and is active
        try:
            c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='sessions' AND column_name='is_active'")
            has_is_active = c.fetchone() is not None
            
            if has_is_active:
                c.execute('''
                    SELECT session_token FROM sessions 
                    WHERE email_address = %s AND session_token = %s 
                    AND expires_at > NOW() AND is_active = TRUE
                ''', (email_address, session_token))
            else:
                c.execute('''
                    SELECT session_token FROM sessions 
                    WHERE email_address = %s AND session_token = %s 
                    AND expires_at > NOW()
                ''', (email_address, session_token))
        except Exception as e:
            logger.warning(f"Error checking session: {e}")
            c.execute('''
                SELECT session_token FROM sessions 
                WHERE email_address = %s AND session_token = %s 
                AND expires_at > NOW()
            ''', (email_address, session_token))
        
        session_data = c.fetchone()
        conn.close()
        
        if not session_data:
            logger.warning(f"❌ Session validation failed for {email_address}")
            return False, "Invalid or expired session"
        
        logger.info(f"✅ Session validated for {email_address}")
        return True, "Valid session"
        
    except Exception as e:
        logger.error(f"Session validation error: {e}")
        return False, str(e)
    

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
        admin_mode = data.get('admin_mode', False)
        current_session_token = data.get('current_session_token')
        
        # Validate security headers
        session_id = request.headers.get('X-Session-ID')
        security_key = request.headers.get('X-Security-Key')
        
        if not session_id or not security_key:
            logger.warning("Missing security headers in create request")
        
        username = ""
        
        if custom_name:
            username = custom_name.lower()
            username = ''.join(c for c in username if c.isalnum() or c in '-_')
            if not username:
                return jsonify({'error': 'Invalid username', 'code': 'INVALID_USERNAME'}), 400
            
            # Skip blacklist check if admin mode is enabled
            if not admin_mode and is_username_blacklisted(username):
                return jsonify({
                    'error': 'This username is reserved for the system owner. Please choose a different username.',
                    'code': 'USERNAME_BLACKLISTED'
                }), 403
        else:
            # Generate random name
            male_name = random.choice(MALE_NAMES)
            female_name = random.choice(FEMALE_NAMES)
            three_digits = ''.join(random.choices(string.digits, k=3))
            username = f"{male_name}{female_name}{three_digits}"
        
        email_address = f"{username}@{DOMAIN}"
        
        conn = get_db()
        c = conn.cursor()
        
        # 🚨 CRITICAL FIX: Check if email is currently in use by an ACTIVE session
        c.execute('''
            SELECT session_token, created_at 
            FROM sessions 
            WHERE email_address = %s AND expires_at > NOW() AND is_active = TRUE
            ORDER BY created_at DESC 
            LIMIT 1
        ''', (email_address,))
        
        active_session = c.fetchone()
        
        if active_session:
            active_session_token = active_session[0]
            
            # 🆕 CHECK: If this is the SAME USER trying to recreate their own email
            if current_session_token and current_session_token == active_session_token:
                # Same user recreating their own email - allow it and return existing session
                logger.info(f"✅ User recreating their own email: {email_address}")
                
                # Update session expiration
                new_expires_at = datetime.now() + timedelta(hours=1)
                c.execute('''
                    UPDATE sessions 
                    SET expires_at = %s, last_activity = %s
                    WHERE session_token = %s
                ''', (new_expires_at, datetime.now(), active_session_token))
                
                conn.commit()
                conn.close()
                
                return jsonify({
                    'email': email_address,
                    'session_token': active_session_token,
                    'expires_at': new_expires_at.isoformat(),
                    'existing_session': True
                })
            else:
                # Different user trying to use this email - reject
                conn.close()
                return jsonify({
                    'error': 'This email address is currently in use by another session. Please choose a different username or try again later.',
                    'code': 'EMAIL_IN_USE_ACTIVE'
                }), 409
        
        # Create session token
        session_token = secrets.token_urlsafe(32)
        created_at = datetime.now()
        expires_at = created_at + timedelta(hours=1)
        
        # Insert new session
        try:
            c.execute('''
                INSERT INTO sessions (session_token, email_address, created_at, expires_at, last_activity, is_active)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (session_token, email_address, created_at, expires_at, created_at, True))
        except Exception as e:
            logger.warning(f"Error with is_active column, falling back: {e}")
            c.execute('''
                INSERT INTO sessions (session_token, email_address, created_at, expires_at, last_activity)
                VALUES (%s, %s, %s, %s, %s)
            ''', (session_token, email_address, created_at, expires_at, created_at))
        
        # NEW FEATURE: If admin mode is enabled, automatically add to blacklist
        if admin_mode and custom_name:
            try:
                c.execute('''
                    INSERT INTO blacklist (username, added_at, added_by) 
                    VALUES (%s, %s, %s)
                    ON CONFLICT (username) DO NOTHING
                ''', (username.lower(), datetime.now(), 'admin_auto'))
                logger.info(f"✅ Automatically blacklisted username: {username}")
            except Exception as e:
                logger.error(f"Error auto-blacklisting username: {e}")
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Created email: {email_address}")
        
        return jsonify({
            'email': email_address,
            'session_token': session_token,
            'expires_at': expires_at.isoformat(),
            'existing_session': False
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
        
        # First check if session exists
        c.execute('''
            SELECT session_token FROM sessions 
            WHERE session_token = %s AND email_address = %s
        ''', (session_token, email_address))
        
        session_exists = c.fetchone()
        
        if not session_exists:
            conn.close()
            return jsonify({'error': 'Session not found'}), 404
        
        # FIX: Only mark session as inactive, NEVER delete emails
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
                # If is_active column doesn't exist, just update expires_at to now
                c.execute('''
                    UPDATE sessions 
                    SET expires_at = NOW()
                    WHERE session_token = %s AND email_address = %s
                ''', (session_token, email_address))
        except Exception as e:
            logger.warning(f"Error in session end logic: {e}")
            # Fallback to updating expires_at
            c.execute('''
                UPDATE sessions 
                SET expires_at = NOW()
                WHERE session_token = %s AND email_address = %s
            ''', (session_token, email_address))
        
        conn.commit()
        conn.close()
        
        logger.info(f"âœ… Session ended for: {email_address} (emails preserved)")
        return jsonify({'success': True, 'message': 'Session ended successfully'})
        
    except Exception as e:
        logger.error(f"âŒ Error ending session: {e}")
        return jsonify({'error': 'Failed to end session'}), 500
    
@app.route('/api/emails/<email_address>', methods=['GET'])
def get_emails(email_address):
    """Get emails for a specific email address"""
    try:
        session_token = request.headers.get('X-Session-Token', '')
        
        # Validate session for regular users
        is_valid, message = validate_session(email_address, session_token)
        if not is_valid:
            logger.warning(f"Session invalid for {email_address}: {message}")
            return jsonify({'error': message}), 403
        
        conn = get_db()
        c = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get emails for this session (regular users only see their session emails)
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
                'body': row['body'],
                'timestamp': row['timestamp'],
                'received_at': row['received_at'].isoformat() if row['received_at'] else None
            })
        
        conn.close()
        logger.info(f"✅ Retrieved {len(emails)} emails for {email_address}")
        return jsonify({'emails': emails})
        
    except Exception as e:
        logger.error(f"❌ Error getting emails: {e}")
        return jsonify({'error': str(e)}), 500
    
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

@app.route('/api/debug/error-test', methods=['POST'])
def debug_error_test():
    """Test if create endpoint works"""
    try:
        # Test database connection
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT 1')
        conn.close()
        
        # Test session creation
        session_token = secrets.token_urlsafe(32)
        email_address = "test@aungmyomyatzaw.online"
        
        return jsonify({
            'success': True,
            'database': 'working',
            'session_token': session_token,
            'test_email': email_address
        })
        
    except Exception as e:
        logger.error(f"Debug error: {e}")
        return jsonify({'error': str(e)}), 500

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
        
        # Clean sender using new function
        sender = clean_sender_address(sender)
        
        # Get body - try multiple fields
        body = json_data.get('html_body') or json_data.get('plain_body') or 'No content'
        
        # PARSE EMAIL WITH NEW MAIL-PARSER SYSTEM
                # Parse email beautifully
        parsed_email = parse_email_beautifully(body)
        display_content = render_beautiful_email(parsed_email)
        
        # Use parsed subject if available and better
        if parsed_email['subject'] and parsed_email['subject'] != 'No subject':
            subject = parsed_email['subject']
        
        recipient = recipient.strip()
        sender = sender.strip() 
        subject = subject.strip()
        
        logger.info(f"  📨 From: {sender} → {recipient}")
        logger.info(f"  📝 Subject: {subject}")
        logger.info(f"  📄 Body: {len(display_content['content'])} chars")
        if display_content['verification_codes']:
            logger.info(f"  🔑 Verification codes: {display_content['verification_codes']}")
        
        # Store timestamps
        received_at = datetime.now()
        original_timestamp = json_data.get('timestamp', received_at.isoformat())
        
        # Find active session for this recipient
        conn = get_db()
        c = conn.cursor()
        
        session_token = None
        
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
            logger.info(f"  ✅ Found active session for {recipient}")
        else:
            logger.info(f"  ℹ️ No active session found for {recipient}, but storing email anyway")

                # Store email (with session_token if available, otherwise NULL)
        c.execute('''
            INSERT INTO emails (recipient, sender, subject, body, timestamp, received_at, session_token)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        ''', (recipient, sender, subject, display_content['content'], original_timestamp, received_at, session_token))
        
        # Update session last_activity if session exists
        if session_data:
            c.execute('''
                UPDATE sessions 
                SET last_activity = %s 
                WHERE session_token = %s
            ''', (received_at, session_token))
            logger.info(f"  ✅ Updated session activity for {recipient}")
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Email stored permanently: {sender} → {recipient}")
        return '', 204
        
    except Exception as e:
        logger.error(f"❌ Webhook error: {e}")
        return jsonify({'error': str(e)}), 400

def cleanup_expired_sessions():
    while True:
        time.sleep(300)  # Every 5 minutes
        try:
            conn = get_db()
            c = conn.cursor()
            
            # ONLY clean sessions, NEVER touch emails
            c.execute("""
                UPDATE sessions 
                SET is_active = FALSE 
                WHERE expires_at < NOW() AND is_active = TRUE
            """)
            
            deleted = c.rowcount
            conn.commit()
            conn.close()
            
            if deleted > 0:
                logger.info(f"ðŸ”„ Deactivated {deleted} expired sessions (emails preserved)")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")

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
        logger.error(f"âŒ Admin stats error: {e}")
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
            if row['last_email']:
                local_time = row['last_email'] + timedelta(hours=6, minutes=30)
                last_email_str = local_time.isoformat()
            else:
                last_email_str = None
                
            addresses.append({
                'address': row['address'],
                'count': row['count'],
                'last_email': last_email_str
            })
        
        conn.close()
        return jsonify({'addresses': addresses})
        
    except Exception as e:
        logger.error(f"âŒ Admin addresses error: {e}")
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
        logger.error(f"âŒ Admin get emails error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/delete/<int:email_id>', methods=['DELETE'])
@admin_required
def admin_delete_email(email_id):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('DELETE FROM emails WHERE id = %s', (email_id,))  # ðŸš¨ DELETES EMAIL
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"âŒ Admin delete email error: {e}")
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
        logger.error(f"âŒ Admin delete address error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/sessions', methods=['GET'])
@admin_required
def admin_get_sessions():
    """Get all active sessions"""
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
                'last_activity': row['last_activity'].isoformat(),
                'session_age_minutes': int((datetime.now() - row['created_at']).total_seconds() / 60),
                'time_remaining_minutes': int((row['expires_at'] - datetime.now()).total_seconds() / 60)
            })
        
        conn.close()
        return jsonify({'sessions': sessions})
        
    except Exception as e:
        logger.error(f"âŒ Error fetching sessions: {e}")
        return jsonify({'error': str(e)}), 500

# End session from admin panel
@app.route('/api/admin/session/<session_token>/end', methods=['POST'])
@admin_required
def admin_end_session(session_token):
    """End a user session from admin panel"""
    try:
        conn = get_db()
        c = conn.cursor()
        
        # Mark session as inactive
        c.execute('''
            UPDATE sessions 
            SET is_active = FALSE 
            WHERE session_token = %s
        ''', (session_token,))
        
        if c.rowcount == 0:
            conn.close()
            return jsonify({'error': 'Session not found'}), 404
        
        conn.commit()
        conn.close()
        
        logger.info(f"âœ… Admin ended session: {session_token}")
        return jsonify({'success': True, 'message': 'Session ended successfully'})
        
    except Exception as e:
        logger.error(f"âŒ Error ending session from admin: {e}")
        return jsonify({'error': str(e)}), 500

# Blacklist endpoints with database persistence
@app.route('/api/admin/blacklist', methods=['GET'])
@admin_required
def get_blacklist():
    """Get current blacklisted usernames from database"""
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=RealDictCursor)
        
        c.execute('''
            SELECT username, added_at, added_by
            FROM blacklist
            ORDER BY username
        ''')
        
        blacklist = []
        for row in c.fetchall():
            blacklist.append({
                'username': row['username'],
                'added_at': row['added_at'].isoformat() if row['added_at'] else None,
                'added_by': row['added_by']
            })
        
        conn.close()
        return jsonify({'blacklist': blacklist})
    except Exception as e:
        logger.error(f"âŒ Error getting blacklist: {e}")
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
        
        conn = get_db()
        c = conn.cursor()
        
        try:
            c.execute('''
                INSERT INTO blacklist (username, added_at, added_by) 
                VALUES (%s, %s, %s)
            ''', (username, datetime.now(), 'admin_manual'))
            conn.commit()
            conn.close()
            
            logger.info(f"âœ… Added to blacklist: {username}")
            return jsonify({'success': True, 'message': f'Username {username} added to blacklist'})
            
        except psycopg2.IntegrityError:
            conn.close()
            return jsonify({'error': 'Username already in blacklist'}), 409
        
    except Exception as e:
        logger.error(f"âŒ Error adding to blacklist: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/blacklist/<username>', methods=['DELETE'])
@admin_required
def remove_from_blacklist(username):
    """Remove username from blacklist in database"""
    try:
        username = username.lower()
        
        conn = get_db()
        c = conn.cursor()
        c.execute('DELETE FROM blacklist WHERE username = %s', (username,))
        
        if c.rowcount == 0:
            conn.close()
            return jsonify({'error': 'Username not found in blacklist'}), 404
        
        conn.commit()
        conn.close()
        
        logger.info(f"âœ… Removed from blacklist: {username}")
        return jsonify({'success': True, 'message': f'Username {username} removed from blacklist'})
        
    except Exception as e:
        logger.error(f"âŒ Error removing from blacklist: {e}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/admin/clear-sessions', methods=['POST'])
@admin_required
def admin_clear_sessions():
    """Clear all admin-related sessions"""
    try:
        conn = get_db()
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
        conn.close()
        
        logger.info("âœ… All admin sessions cleared")
        return jsonify({'success': True, 'message': 'Admin sessions cleared'})
        
    except Exception as e:
        logger.error(f"âŒ Error clearing admin sessions: {e}")
        return jsonify({'error': str(e)}), 500

@app.before_request
def check_admin_session():
    """Check and expire admin sessions automatically"""
    if session.get('admin_authenticated'):
        # Set session to expire after 1 hour of inactivity
        session.permanent = True
        app.permanent_session_lifetime = timedelta(hours=1)

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
