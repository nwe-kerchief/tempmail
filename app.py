
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
import time as time_module
from psycopg2 import OperationalError


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

# Enhanced database connection with retry logic
def get_db():
    max_retries = 3
    retry_delay = 1
    
    for attempt in range(max_retries):
        try:
            conn = psycopg2.connect(DATABASE_URL, sslmode='require')
            return conn
        except OperationalError as e:
            logger.warning(f"Database connection attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                time_module.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
            else:
                logger.error("All database connection attempts failed")
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
                is_active BOOLEAN DEFAULT TRUE,
                is_access_code BOOLEAN DEFAULT FALSE
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

        # Access codes table
        c.execute('''
            CREATE TABLE IF NOT EXISTS access_codes (
                id SERIAL PRIMARY KEY,
                code TEXT UNIQUE NOT NULL,
                email_address TEXT NOT NULL,
                description TEXT DEFAULT '',
                created_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                used_count INTEGER DEFAULT 0,
                max_uses INTEGER DEFAULT 1
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

# Migration: Add description column to access_codes table if it doesn't exist
try:
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        ALTER TABLE access_codes 
        ADD COLUMN IF NOT EXISTS description TEXT DEFAULT ''
    """)
    conn.commit()
    conn.close()
    logger.info("✅ Migration: description column added to access_codes")
except Exception as e:
    logger.warning(f"Migration note: {e}")

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

# Enhanced email parsing with better error handling
def parse_email_with_mailparser(raw_email):
    try:
        mail = mailparser.parse_from_string(raw_email)
        
        # Basic validation
        if not hasattr(mail, 'from_') or not mail.from_:
            logger.warning("Email has no sender information")
            return parse_email_fallback(raw_email)
        
        parsed_data = {
            'subject': mail.subject or 'No subject',
            'from_email': get_clean_sender(mail),
            'to': get_clean_recipient(mail),
            'date': mail.date.isoformat() if mail.date else None,
            'body_plain': '',
            'body_html': '',
            'verification_codes': [],
            'attachments': len(mail.attachments) if hasattr(mail, 'attachments') else 0
        }
        
        # Get ALL available text content
        all_text_parts = []
        
        # Add subject to search context
        if mail.subject:
            all_text_parts.append(mail.subject)
        
        # Add plain text body
        if hasattr(mail, 'text_plain') and mail.text_plain:
            plain_text = '\n'.join(mail.text_plain) if isinstance(mail.text_plain, list) else str(mail.text_plain)
            parsed_data['body_plain'] = plain_text
            all_text_parts.append(plain_text)
        elif hasattr(mail, 'body') and mail.body:
            parsed_data['body_plain'] = mail.body
            all_text_parts.append(mail.body)
        
        # Add HTML body (converted to text for code extraction)
        if hasattr(mail, 'text_html') and mail.text_html:
            html_content = '\n'.join(mail.text_html) if isinstance(mail.text_html, list) else str(mail.text_html)
            parsed_data['body_html'] = html_content
            
            # Convert HTML to text for better code extraction
            try:
                h = html2text.HTML2Text()
                h.ignore_links = True
                h.ignore_images = True
                h.ignore_tables = True
                html_as_text = h.handle(html_content)
                all_text_parts.append(html_as_text)
            except Exception as e:
                logger.warning(f"HTML to text conversion failed: {e}")
                all_text_parts.append(html_content)
        
        # Combine all text for code extraction
        combined_text = ' '.join(all_text_parts)
        
        # Extract codes from combined text
        parsed_data['verification_codes'] = extract_verification_codes(combined_text)
        
        logger.info(f"✅ Email parsed: {parsed_data['from_email']} -> Subject: '{parsed_data['subject']}', Codes: {parsed_data['verification_codes']}")
        return parsed_data
        
    except Exception as e:
        logger.error(f"❌ mail-parser error: {e}")
        return parse_email_fallback(raw_email)

def get_clean_sender(mail):
    """Extract clean sender address"""
    if mail.from_:
        if isinstance(mail.from_[0], (list, tuple)):
            return mail.from_[0][1] if len(mail.from_[0]) > 1 else str(mail.from_[0][0])
        elif hasattr(mail.from_[0], 'email'):
            return mail.from_[0].email
        else:
            return str(mail.from_[0])
    return 'Unknown'

def get_clean_recipient(mail):
    """Extract clean recipient address"""
    if mail.to:
        if isinstance(mail.to[0], (list, tuple)):
            return mail.to[0][1] if len(mail.to[0]) > 1 else str(mail.to[0][0])
        elif hasattr(mail.to[0], 'email'):
            return mail.to[0].email
        else:
            return str(mail.to[0])
    return 'Unknown'

def extract_verification_codes(text):
    """Extract verification codes with more patterns"""
    if not text:
        return []
    
    codes = []
    
    # Enhanced patterns for common verification code formats
    patterns = [
        # ChatGPT specific patterns - FIXED
        r'Your ChatGPT code is\s*(\d{6})',
        r'temporary verification code:\s*(\d{6})',
        r'verification code:\s*(\d{6})',
        r'enter.*code:\s*(\d{6})',
        r'code is:\s*(\d{6})',
        r'code:\s*(\d{6})',
        
        # General patterns
        r'(?:code|verification|verify|confirmation|security|otp|pin)[\s:\-]*[#]?\s*(\d{4,8})\b',
        r'\b(\d{4,8})\s*(?:is your|is the|is my|your|code|verification|OTP|PIN)\b',
        r'\b(?:enter|use|type|input)[\s\w]*[:]?\s*(\d{4,8})\b',
    ]
    
    for pattern in patterns:
        try:
            matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                if match.groups():
                    code = match.group(1)
                    if code and len(code) >= 4 and code not in codes:
                        codes.append(code)
                        logger.info(f"🔍 Found verification code: {code} with pattern: {pattern}")
        except Exception as e:
            logger.warning(f"Pattern error {pattern}: {e}")
            continue
    
    # Also look for standalone 6-digit codes in context
    if not codes:
        # Find all 6-digit numbers
        six_digit_matches = re.finditer(r'\b(\d{6})\b', text)
        for match in six_digit_matches:
            code = match.group(1)
            # Check if this appears near verification keywords
            start_pos = max(0, match.start() - 50)
            end_pos = min(len(text), match.end() + 50)
            context = text[start_pos:end_pos].lower()
            
            verification_keywords = [
                'verification', 'verify', 'code', 'confirm', 'security', 
                'temporary', 'chatgpt', 'openai', 'enter', 'use', 'input'
            ]
            
            if any(keyword in context for keyword in verification_keywords):
                if code not in codes:
                    codes.append(code)
                    logger.info(f"🔍 Found contextual code: {code} in context: {context}")
    
    # Remove duplicates
    seen = set()
    unique_codes = [code for code in codes if not (code in seen or seen.add(code))]
    
    logger.info(f"✅ Final extracted codes: {unique_codes}")
    return unique_codes

def clean_sender_address(sender):
    """Clean sender address from common formats"""
    if not sender:
        return 'Unknown'
    
    # Extract email from "Name <email@domain.com>" format
    if '<' in sender and '>' in sender:
        email_match = re.search(r'<([^>]+)>', sender)
        if email_match:
            return email_match.group(1)
    
    # Clean bounce addresses
    if 'bounce' in sender.lower():
        if '@' in sender:
            domain_part = sender.split('@')[1]
            if 'openai.com' in domain_part or 'mandrillapp.com' in domain_part:
                return 'ChatGPT'
            elif 'afraid.org' in domain_part:
                return 'FreeDNS'
            else:
                return 'Notification'
    
    return sender.strip()


def parse_email_fallback(raw_email):
    """Fallback parsing when mail-parser fails"""
    try:
        msg = email.message_from_string(raw_email, policy=policy.default)
        
        # Use your old extract_content_from_mime logic but simplified
        body_content = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                if "attachment" in content_disposition:
                    continue
                
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        decoded = payload.decode('utf-8', errors='ignore')
                        if content_type == 'text/plain' and not body_content:
                            body_content = decoded
                        elif content_type == 'text/html' and not body_content:
                            body_content = decoded
                except Exception:
                    continue
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body_content = payload.decode('utf-8', errors='ignore')
        
        return {
            'subject': msg.get('subject', 'No subject'),
            'from_email': clean_sender_address(msg.get('from', 'Unknown')),
            'to': msg.get('to', 'Unknown'),
            'date': msg.get('date', ''),
            'body_plain': body_content or 'No content',
            'body_html': '',
            'verification_codes': extract_verification_codes(body_content or ''),
            'attachments': 0
        }
    except Exception as e:
        logger.error(f"❌ Fallback parsing failed: {e}")
        return {
            'subject': 'Failed to parse email',
            'from_email': 'Unknown',
            'to': 'Unknown', 
            'date': '',
            'body_plain': 'This email could not be parsed properly.',
            'body_html': '',
            'verification_codes': [],
            'attachments': 0
        }

def clean_sender_address(sender):
    """Clean sender address from common formats"""
    if not sender:
        return 'Unknown'
    
    if '<' in sender and '>' in sender:
        email_match = re.search(r'<([^>]+)>', sender)
        if email_match:
            return email_match.group(1)
    
    if 'bounce' in sender.lower():
        if '@' in sender:
            domain_part = sender.split('@')[1]
            if 'openai.com' in domain_part or 'mandrillapp.com' in domain_part:
                return 'ChatGPT'
            elif 'afraid.org' in domain_part:
                return 'FreeDNS'
            else:
                return 'Notification'
    
    return sender.strip()

def get_display_body(parsed_email):
    """Return the original email content without modifications"""
    # Use the raw HTML body if available, otherwise use plain text
    raw_content = parsed_email['body_html'] or parsed_email['body_plain']
    
    if not raw_content:
        return {
            'content': '<p class="text-gray-400">No readable content found</p>',
            'verification_codes': parsed_email['verification_codes']
        }
    
    # If it's HTML, return it as-is with minimal wrapper
    if parsed_email['body_html']:
        return {
            'content': f'<div class="email-original">{raw_content}</div>',
            'verification_codes': parsed_email['verification_codes']
        }
    else:
        # For plain text, just preserve line breaks
        formatted_text = escapeHtml(raw_content).replace('\n', '<br>')
        return {
            'content': f'<div class="email-original whitespace-pre-wrap font-sans">{formatted_text}</div>',
            'verification_codes': parsed_email['verification_codes']
        }

def format_time(timestamp):
    """Format timestamp for display"""
    if not timestamp:
        return 'never'
    
    try:
        if isinstance(timestamp, str):
            # Handle string timestamps
            date = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        else:
            date = timestamp
            
        now = datetime.now()
        diff = now - date
        
        seconds = diff.total_seconds()
        minutes = seconds // 60
        hours = minutes // 60
        days = hours // 24
        
        if seconds < 60:
            return 'just now'
        if minutes < 60:
            return f'{int(minutes)} min ago'
        if hours < 24:
            return f'{int(hours)} hour{"s" if hours > 1 else ""} ago'
        if days < 7:
            return f'{int(days)} day{"s" if days > 1 else ""} ago'
        
        return date.strftime('%b %d, %H:%M')
        
    except Exception as e:
        logger.error(f"Time formatting error: {e}")
        return 'unknown'

def format_email_content(text, verification_codes):
    """Format email content for HTML display - preserve original structure"""
    if not text:
        return '<p class="text-gray-400">No content</p>'
    
    # Remove only technical headers, keep everything else as-is
    header_patterns = [
        'Received:', 'Received-SPF:', 'ARC-Seal:', 'ARC-Message-Signature:',
        'DKIM-Signature:', 'Authentication-Results:', 'Return-Path:',
        'Delivered-To:', 'Content-Type:', 'MIME-Version:', 'Message-ID:'
    ]
    
    lines = text.split('\n')
    clean_lines = []
    
    for line in lines:
        # Skip only technical headers
        if not any(line.startswith(pattern) for pattern in header_patterns):
            clean_lines.append(line.rstrip())
    
    text = '\n'.join(clean_lines)
    
    # Convert to HTML with minimal changes
    html_content = escapeHtml(text)
    
    # Remove the "Click to copy verification code" text that appears multiple times
    html_content = html_content.replace('Click to copy verification code', '')
    
    # Highlight verification codes in their original positions with proper styling
    for code in verification_codes:
        # Create a beautiful centered verification code button
        verification_button = f'''
        <div class="text-center my-8">
            <div class="bg-gradient-to-r from-yellow-400 to-orange-400 text-white px-8 py-6 rounded-xl font-mono font-bold border-2 border-yellow-500 text-3xl inline-block cursor-pointer hover:from-yellow-500 hover:to-orange-500 transition-all transform hover:scale-105 shadow-lg" onclick="copyToClipboard('{code}')">
                {code}
            </div>
            <p class="text-sm text-gray-300 mt-3">Click the code above to copy</p>
        </div>
        '''
        
        # Replace the verification code with our styled version
        html_content = html_content.replace(
            f'{code}\nClick to copy verification code', 
            verification_button
        )
        # Also replace standalone codes
        html_content = html_content.replace(
            code, 
            f'<span class="verification-code-highlight">{code}</span>'
        )
    
    # Make URLs clickable
    html_content = re.sub(
        r'(https?://[^\s<]+)', 
        r'<a href="\1" target="_blank" class="text-blue-400 hover:underline break-all">\1</a>', 
        html_content
    )
    
    # Preserve line breaks and whitespace
    html_content = html_content.replace('\n', '<br>')
    
    # Dark background wrapper
    return f'<div class="email-content whitespace-pre-wrap text-gray-200 leading-relaxed font-sans bg-gray-900/50 p-6 rounded-lg border border-gray-700">{html_content}</div>'

def escapeHtml(text):
    if not text:
        return ''
    import html
    return html.escape(text)

def validate_session(email_address, session_token):
    """Validate if session is valid - checks access code status"""
    try:
        conn = get_db()
        c = conn.cursor()
        
        # Check if session exists and is active
        c.execute('''
            SELECT session_token, expires_at, is_access_code
            FROM sessions 
            WHERE email_address = %s AND session_token = %s 
            AND expires_at > NOW() AND is_active = TRUE
        ''', (email_address, session_token))
        
        session_data = c.fetchone()
        
        if not session_data:
            logger.warning(f"❌ Session validation failed for {email_address}")
            return False, "Invalid or expired session"
        
        session_token, expires_at, is_access_code = session_data
        
       # ✅ MODIFIED: For access code sessions, be more flexible about validation
        if is_access_code:
            c.execute('''
                SELECT ac.expires_at, s.created_at
                FROM access_codes ac
                JOIN sessions s ON ac.email_address = s.email_address 
                WHERE s.session_token = %s
            ''', (session_token,))
            
            access_code_data = c.fetchone()
            if access_code_data:
                code_expires_at, session_created = access_code_data
                
                # Only invalidate if the original code expiration has passed
                # This allows sessions to continue even if the code itself expired
                # as long as the session was created before code expiration
                if session_created > code_expires_at:
                    logger.info(f"🔐 Access code session invalid: {email_address}")
                    c.execute('''
                        UPDATE sessions 
                        SET is_active = FALSE 
                        WHERE session_token = %s
                    ''', (session_token,))
                    conn.commit()
                    conn.close()
                    return False, "Access code session invalid"
        
        # Update last activity for regular sessions only
        if not is_access_code:
            try:
                c.execute('''
                    UPDATE sessions 
                    SET last_activity = %s 
                    WHERE session_token = %s
                ''', (datetime.now(), session_token))
                conn.commit()
            except Exception as e:
                logger.warning(f"Could not update session activity: {e}")
        
        conn.close()
        logger.info(f"✅ Session validated for {email_address} (access_code: {is_access_code})")
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

# Enhanced email creation with better conflict handling
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
            
            # Check if this is an access code session
            is_access_code_session = False

            if current_session_token:
                try:
                    conn = get_db()
                    c = conn.cursor()
                    c.execute('SELECT is_access_code FROM sessions WHERE session_token = %s', (current_session_token,))
                    session_data = c.fetchone()
                    conn.close()
                    if session_data and session_data[0]:
                        is_access_code_session = True
                        logger.info(f"⚠️ Access code session detected - bypassing blacklist for: {username}")
                except Exception as e:
                    logger.warning(f"Error checking session type: {e}")

            # Skip blacklist check if admin mode OR access code session
            if not admin_mode and not is_access_code_session and is_username_blacklisted(username):
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
        
        # Check if email is currently in use by an ACTIVE session
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
            
            # If this is the SAME USER trying to recreate their own email
            if current_session_token and current_session_token == active_session_token:
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
        c.execute('''
            INSERT INTO sessions (session_token, email_address, created_at, expires_at, last_activity, is_active)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (session_token, email_address, created_at, expires_at, created_at, True))
        
        # If admin mode is enabled, automatically add to blacklist
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
        
        # Validate session
        is_valid, message = validate_session(email_address, session_token)
        if not is_valid:
            return jsonify({'error': message}), 403
        
        conn = get_db()
        c = conn.cursor(cursor_factory=RealDictCursor)
        
        # Check if this is an access code session
        c.execute('''
            SELECT is_access_code, created_at 
            FROM sessions 
            WHERE session_token = %s AND email_address = %s
        ''', (session_token, email_address))
        
        session_data = c.fetchone()
        is_access_code_session = session_data and session_data['is_access_code']
        session_start_time = session_data['created_at'] if session_data else None
        
        if is_access_code_session and session_start_time:
            # ✅ ACCESS CODE MODE: Only show emails received AFTER session start
            c.execute('''
                SELECT id, sender, subject, body, timestamp, received_at
                FROM emails 
                WHERE recipient = %s AND session_token = %s
                AND received_at >= %s
                ORDER BY received_at DESC
            ''', (email_address, session_token, session_start_time))
            logger.info(f"🔐 Access code mode: Showing emails after {session_start_time}")
        else:
            # ✅ REGULAR MODE: Show all emails for this session
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
        
        email_count = len(emails)
        if is_access_code_session:
            logger.info(f"🔐 Access code session: Showing {email_count} emails (after {session_start_time})")
        else:
            logger.info(f"✅ Regular session: Showing {email_count} emails for {email_address}")
            
        return jsonify({'emails': emails})
        
    except Exception as e:
        logger.error(f"❌ Error getting emails: {e}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/debug/test-codes', methods=['POST'])
def debug_test_codes():
    """Test code extraction with sample text"""
    try:
        data = request.get_json() or {}
        test_text = data.get('text', '')
        
        if not test_text:
            # Use the actual ChatGPT email format
            test_text = """
            Your ChatGPT code is 746300
            https://cdn.openai.com/API/logo-assets/openai-logo-email-header-2.png
            Enter this temporary verification code to continue:
            746300
            Please ignore this email if this wasn't you trying to create a ChatGPT account.
            """
        
        codes = extract_verification_codes(test_text)
        
        return jsonify({
            'success': True,
            'input_text': test_text,
            'codes_found': codes,
            'patterns_tested': [
                'Your ChatGPT code is\\s*(\\d{6})',
                'temporary verification code:\\s*(\\d{6})',
                'verification code:\\s*(\\d{6})',
                '\\b(\\d{6})\\b'
            ]
        })
        
    except Exception as e:
        logger.error(f"Debug test error: {e}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/admin/end-sessions/<email_address>', methods=['POST'])
@admin_required
def admin_end_sessions(email_address):
    try:
        conn = get_db()
        c = conn.cursor()
        
        # End all active sessions for this email address
        c.execute('''
            UPDATE sessions 
            SET is_active = FALSE 
            WHERE email_address = %s AND is_active = TRUE
        ''', (email_address,))
        
        sessions_ended = c.rowcount
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Admin ended {sessions_ended} sessions for {email_address}")
        return jsonify({'success': True, 'sessions_ended': sessions_ended})
        
    except Exception as e:
        logger.error(f"❌ Error ending sessions: {e}")
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
        parsed_email = parse_email_with_mailparser(body)
        display_content = get_display_body(parsed_email)
        
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
            logger.info(f"  ℹ️ No active session found for {recipient}, storing email without session")
        
        # ✅ FIXED: Store email with session_token (can be NULL)
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
        
        logger.info(f"✅ Email stored: {sender} → {recipient}")
        return '', 204
        
    except Exception as e:
        logger.error(f"❌ Webhook error: {e}")
        return jsonify({'error': str(e)}), 400
    
@app.route('/api/debug/email-content', methods=['POST'])
def debug_email_content():
    """Debug endpoint to see raw email content"""
    try:
        data = request.get_json() or {}
        raw_email = data.get('raw_email', '')
        
        if not raw_email:
            return jsonify({'error': 'No email content provided'}), 400
        
        # Parse the email
        parsed = parse_email_with_mailparser(raw_email)
        
        return jsonify({
            'success': True,
            'parsed_data': parsed,
            'body_length': len(parsed.get('body_plain', '')),
            'html_length': len(parsed.get('body_html', '')),
            'codes_found': parsed.get('verification_codes', [])
        })
        
    except Exception as e:
        logger.error(f"Debug error: {e}")
        return jsonify({'error': str(e)}), 500

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
        
        # Get addresses sorted by newest email received
        c.execute('''
            SELECT 
                recipient as address, 
                COUNT(*) as count, 
                MAX(received_at) as last_email_time
            FROM emails
            GROUP BY recipient
            ORDER BY MAX(received_at) DESC
        ''')
        
        addresses = []
        for row in c.fetchall():
            if row['last_email_time']:
                last_email_str = format_time(row['last_email_time'])
            else:
                last_email_str = 'never'
                
            addresses.append({
                'address': row['address'],
                'count': row['count'],
                'last_email': last_email_str,
                'last_email_time': row['last_email_time'].isoformat() if row['last_email_time'] else None
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
    
@app.route('/api/admin/access-codes/generate', methods=['POST'])
@admin_required
def generate_access_code():
    try:
        data = request.get_json() or {}
        email_address = data.get('email_address', '').strip()
        custom_code = data.get('custom_code', '').strip().upper()
        duration_minutes = data.get('duration_minutes', 1440)
        max_uses = data.get('max_uses', 1)
        description = data.get('description', '').strip()
        
        if not email_address:
            return jsonify({'error': 'Email address is required'}), 400
        
        # Validate email format
        if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email_address):
            return jsonify({'error': 'Invalid email address format'}), 400
        
        # Validate custom code or generate random
        if custom_code:
            if not re.match(r'^[A-Z0-9]{4,12}$', custom_code):
                return jsonify({'error': 'Custom code must be 4-12 uppercase letters and numbers only'}), 400
            code = custom_code
        else:
            code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        
        conn = get_db()
        c = conn.cursor()
        
        # Check if code already exists
        c.execute('SELECT code FROM access_codes WHERE code = %s', (code,))
        if c.fetchone():
            conn.close()
            return jsonify({'error': f'Code "{code}" already exists. Please choose a different one.'}), 409
        
        created_at = datetime.now()
        expires_at = created_at + timedelta(minutes=duration_minutes)
        
        # ✅ Store description in database
        c.execute('''
            INSERT INTO access_codes (code, email_address, description, created_at, expires_at, max_uses)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (code, email_address, description, created_at, expires_at, max_uses))
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Access code generated: {code} for {email_address} - {description}")
        
        return jsonify({
            'success': True,
            'code': code,
            'email_address': email_address,
            'description': description,
            'expires_at': expires_at.isoformat(),
            'max_uses': max_uses,
            'duration_minutes': duration_minutes
        })
        
    except Exception as e:
        logger.error(f"❌ Error generating access code: {e}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/access-code/redeem', methods=['POST'])
def redeem_access_code():
    """Redeem an access code to get temporary access to specific email"""
    try:
        data = request.get_json() or {}
        code = data.get('code', '').strip().upper()
        device_id = data.get('device_id', '')
        
        if not code:
            return jsonify({'error': 'Access code is required'}), 400
        
        conn = get_db()
        c = conn.cursor(cursor_factory=RealDictCursor)
        
        # Check if code exists and is valid
        c.execute('''
            SELECT code, email_address, description, created_at, expires_at, is_active, used_count, max_uses
            FROM access_codes
            WHERE code = %s
        ''', (code,))
        
        access_code = c.fetchone()
        
        if not access_code:
            conn.close()
            return jsonify({'error': 'Invalid access code'}), 404
        
        # Validate code
        if not access_code['is_active']:
            conn.close()
            return jsonify({'error': 'This access code has been revoked'}), 403
        
        # Allow expired codes to be reused - just create a new session with same expiration
        current_time = datetime.now()
        expires_at = access_code['expires_at']

        # If code is expired, extend it by the original duration from creation
        if current_time > access_code['expires_at']:
            # Calculate original duration and extend from now
            original_duration = access_code['expires_at'] - access_code['created_at']
            expires_at = current_time + original_duration
            logger.info(f"🔄 Extending expired access code: {code}")

        # In redeem_access_code function, update error messages:
        if access_code['used_count'] >= access_code['max_uses']:
            conn.close()
            return jsonify({'error': 'This access code has reached its maximum usage limit'}), 403
        
        # Create session
        email_address = access_code['email_address']
        session_token = secrets.token_urlsafe(32)
        
        # Insert session with access code flag
        c.execute('''
            INSERT INTO sessions (session_token, email_address, created_at, expires_at, last_activity, is_active, is_access_code)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        ''', (session_token, email_address, current_time, expires_at, current_time, True, True))
        
        # Update access code usage count
        c.execute('''
            UPDATE access_codes
            SET used_count = used_count + 1
            WHERE code = %s
        ''', (code,))
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Access code redeemed: {code} for {email_address} by device {device_id}")
        
        return jsonify({
            'success': True,
            'email': email_address,
            'session_token': session_token,
            'access_start_time': current_time.isoformat(),
            'expires_at': expires_at.isoformat(),
            'description': access_code['description'],
            'code': code
        })
        
    except Exception as e:
        logger.error(f"❌ Error redeeming access code: {e}")
        return jsonify({'error': 'Server error while processing access code'}), 500

@app.route('/api/admin/access-codes', methods=['GET'])
@admin_required
def get_access_codes():
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=RealDictCursor)
        
        c.execute('''
            SELECT code, email_address, description, created_at, expires_at, used_count, max_uses, is_active
            FROM access_codes
            ORDER BY created_at DESC
        ''')
                
        codes = []
        for row in c.fetchall():
            codes.append({
                'code': row['code'],
                'email_address': row['email_address'],
                'created_at': row['created_at'].isoformat(),
                'expires_at': row['expires_at'].isoformat(),
                'used_count': row['used_count'],
                'max_uses': row['max_uses'],
                'is_active': row['is_active'],
                'is_expired': row['expires_at'] < datetime.now(),
                'remaining_uses': row['max_uses'] - row['used_count']
            })
        
        conn.close()
        return jsonify({'access_codes': codes})
        
    except Exception as e:
        logger.error(f"❌ Error getting access codes: {e}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/admin/access-codes/<code>/revoke', methods=['POST'])
@admin_required
def revoke_access_code(code):
    try:
        conn = get_db()
        c = conn.cursor()
        
        # Check if code exists
        c.execute('SELECT code, email_address FROM access_codes WHERE code = %s', (code,))
        code_data = c.fetchone()
        
        if not code_data:
            conn.close()
            return jsonify({'error': 'Access code not found'}), 404
        
        email_address = code_data[1]
        
        # Revoke the code
        c.execute('''
            UPDATE access_codes 
            SET is_active = FALSE 
            WHERE code = %s
        ''', (code,))
        
        # ✅ ALSO END ALL ACTIVE SESSIONS USING THIS ACCESS CODE
        c.execute('''
            UPDATE sessions 
            SET is_active = FALSE 
            WHERE email_address = %s AND is_access_code = TRUE AND is_active = TRUE
        ''', (email_address,))
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Access code revoked: {code} and sessions ended for {email_address}")
        return jsonify({'success': True, 'message': f'Access code {code} revoked and sessions ended'})
        
    except Exception as e:
        logger.error(f"❌ Error revoking access code: {e}")
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
