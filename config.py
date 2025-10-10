import os

SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
DOMAIN = os.getenv('DOMAIN', 'yourdomain.com')
DB_PATH = os.getenv('DB_PATH', 'tempmail.db')
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY', '')
APP_PASSWORD = os.getenv('APP_PASSWORD', 'admin123')
