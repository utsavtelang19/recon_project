# 🛡️ Reconnaissance Automation Terminal (v2.4)

An enterprise-grade network reconnaissance and security audit terminal built with Flask, SQLAlchemy, and Python. Features automated IP resolution, ICMP echo latency, DNS nameserver auditing, open port discovery, FTP anonymous authentication auditing, deep Nmap port audits, multi-tier user quotas, midnight renewal, role-based access control, and complete database logging.

---

## 🚀 Key Features

### 1. 🗄️ Database Integration & Scan Persistence
- **MySQL & SQLite Dual Support**:
  - Connects to **MySQL Server 9.2** automatically when configured in `.env`.
  - Seamless zero-config fallback to **SQLite** (`recon.db`) so the application runs immediately without requiring manual database installation.
- **Input & Result Logging**: Every scan target, port, timestamp, status, and raw terminal stream is saved to the `scan_logs` database table.

### 2. 🔐 User Registration & Authentication
- Secure registration (`/register`) with password hashing (`werkzeug.security`).
- Session-based authentication (`/login`, `/logout`).
- Protected endpoints: all scanning modules require an active authenticated session.
- **Default System Administrator**:
  - **Username**: `admin`
  - **Password**: `Admin@123`
  - *(Automatically seeded on first launch)*

### 3. ⏱️ Daily Quotas & 12:00 AM Midnight Renewal
- **Free Tier**: **50 IP checks per day**
- **Monthly Pro**: **200 IP checks per day**
- **Annual Pro**: **200 IP checks per day**
- **Lifetime Elite**: **500 IP checks per day**
- **Admin**: **Unlimited checks**
- **Automatic Midnight (12:00 AM) Token Renewal**: Quotas automatically reset to full allowance when the clock strikes 12:00:00 AM every calendar day.
- **Live Quota Countdown**: The UI features a real-time countdown timer tracking the exact hours, minutes, and seconds remaining until midnight renewal.

### 4. 👥 Role-Based Pages (Admin, Paid User, Free User)
- **Free User View (`/dashboard`)**:
  - 50 checks/day meter with dynamic warning thresholds.
  - Upgrade banners with quick access to pricing tiers.
  - Personal scan history.
  - Restricted from admin controls (returns 403 Forbidden).
- **Paid User View (`/dashboard`)**:
  - High-tier Pro/Elite badges (`200 checks/day` or `500 checks/day`).
  - Data export to CSV and JSON unlocked.
  - Priority scan processing.
- **Root Admin Console (`/admin`)**:
  - **User Directory**: View all registered users, emails, roles, plans, daily limits, and usage today.
  - **User Plan Modification**: Upgrade or downgrade any user between Free, Monthly 200, and Lifetime 500 tiers.
  - **Manual Quota Reset**: Instantly reset any user's daily usage to 0.
  - **Account Controls**: Suspend/activate accounts, delete abusive users.
  - **Global Scan Audit**: View and inspect all scans performed across all users.
  - **Emergency Force Reset**: One-click reset of all daily quotas across the entire system.

### 5. 💎 3-Tier Paid Subscription Options (`/plans`)
- **Monthly Pro**: $19 / month (200 checks/day, 30-day validity, data export).
- **Annual Pro**: $149 / year (200 checks/day, 365-day validity, 35% savings).
- **Lifetime Elite**: $299 one-time (500 checks/day, perpetual access, VIP priority queue).

---

## 🛠️ Quick Start Guide

### 1. Requirements
Ensure Python 3.10+ is installed with the required dependencies:
```bash
pip install flask flask-sqlalchemy pymysql python-dotenv python-nmap
```

### 2. Configuration (`.env`)
To use your local MySQL server, open `.env` and configure your password:
```ini
DB_TYPE=auto
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=your_mysql_password_here
MYSQL_DB=recon_db
```
*(If no password is provided, the application will automatically use local SQLite `recon.db` with zero configuration!)*

### 3. Launching the Application
```bash
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 📂 Project Structure

```
recon_project/
├── app.py                  # Main Flask application and API scan endpoints
├── config.py               # Database resolution (MySQL & SQLite fallback) and tier settings
├── models.py               # SQLAlchemy models (User, ScanLog) and quota reset logic
├── auth.py                 # Authentication blueprint, registration, login, role decorators
├── admin_routes.py         # Administrator console, user management, global audit routes
├── .env                    # Environment configuration file
├── .env.example            # Sample configuration template
├── static/
│   └── css/
│       └── terminal.css    # Responsive cyberpunk cybersecurity terminal theme
└── templates/
    ├── base.html           # Base layout with navbar, user badge, and live midnight countdown
    ├── login.html          # Authentication page with default admin credentials helper
    ├── register.html       # Operator registration (starts with 50 daily checks)
    ├── dashboard.html      # Main reconnaissance terminal with modules 1, 2, 3 and quota meter
    ├── plans.html          # Pricing page with Monthly ($19 / 200), Annual ($149 / 200), Lifetime ($299 / 500)
    ├── history.html        # Personal scan history with raw stream modal and CSV/JSON export
    └── admin.html          # Root administrator control center with user table and global scan logs
```
