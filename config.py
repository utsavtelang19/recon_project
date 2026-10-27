import os
from dotenv import load_dotenv

# Load variables from .env file if present
load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

SECRET_KEY = os.getenv('SECRET_KEY', 'recon-cyber-vault-key-default-3389')

# Database parameters
DB_TYPE = os.getenv('DB_TYPE', 'auto').lower()
MYSQL_HOST = os.getenv('MYSQL_HOST', 'localhost')
MYSQL_PORT = int(os.getenv('MYSQL_PORT', 3306))
MYSQL_USER = os.getenv('MYSQL_USER', 'root')
MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD', '')
MYSQL_DB = os.getenv('MYSQL_DB', 'recon_db')
SQLITE_DB_PATH = os.path.join(BASE_DIR, os.getenv('SQLITE_DB_PATH', 'recon.db'))

# Daily scan limits per tier
PLAN_LIMITS = {
    'free': 50,       # 50 IP checks / day for free users
    'monthly': 200,   # 200 IP checks / day for monthly paid users
    'annual': 200,    # 200 IP checks / day for annual paid users
    'lifetime': 500   # 500 IP checks / day for lifetime paid users
}

PLAN_NAMES = {
    'free': 'Free Tier (50 checks/day)',
    'monthly': 'Monthly Pro (200 checks/day)',
    'annual': 'Annual Pro (200 checks/day)',
    'lifetime': 'Lifetime Elite (500 checks/day)'
}

PLAN_PRICING = {
    'free': {'price': '$0', 'period': 'Forever', 'checks': 50, 'badge': 'Free'},
    'monthly': {'price': '$19', 'period': 'per month', 'checks': 200, 'badge': 'Pro'},
    'annual': {'price': '$149', 'period': 'per year', 'checks': 200, 'badge': 'Pro Plus'},
    'lifetime': {'price': '$299', 'period': 'one-time', 'checks': 500, 'badge': 'Elite'}
}

def resolve_database_uri():
    """
    Attempts to connect to MySQL if configured/auto.
    If MySQL credentials are provided and valid, creates `recon_db` if not exists and connects.
    Otherwise gracefully falls back to SQLite so the app runs smoothly with zero setup.
    """
    if DB_TYPE in ('mysql', 'auto'):
        try:
            import pymysql
            # Test direct connection
            conn = pymysql.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                charset='utf8mb4',
                connect_timeout=3
            )
            with conn.cursor() as cursor:
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{MYSQL_DB}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
            conn.commit()
            conn.close()

            # Encode password if special characters present
            from urllib.parse import quote_plus
            encoded_password = quote_plus(MYSQL_PASSWORD)
            uri = f"mysql+pymysql://{MYSQL_USER}:{encoded_password}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}?charset=utf8mb4"
            print(f"[Database] Successfully connected to MySQL server ({MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}).")
            return uri, 'MySQL'
        except Exception as e:
            if DB_TYPE == 'mysql':
                print(f"[Database Warning] MySQL connection failed ({str(e)}). Falling back to SQLite...")
            else:
                print(f"[Database Notice] MySQL not configured with valid password ({str(e)}). Using SQLite (recon.db).")

    sqlite_uri = f"sqlite:///{SQLITE_DB_PATH.replace(os.sep, '/')}"
    print(f"[Database] Using SQLite database at: {SQLITE_DB_PATH}")
    return sqlite_uri, 'SQLite'

DATABASE_URI, ACTIVE_DB_TYPE = resolve_database_uri()

# Admin initial seed credentials
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@recon.local')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'Admin@123')
