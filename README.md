# CyberX-AI-Digital-Twin

## Project Overview

CyberX-AI-Digital-Twin is an integrated cybersecurity digital twin platform designed to simulate, detect, and analyze various cyber attack vectors. It allows cybersecurity researchers, developers, and educational institutions to test and validate security protocols in a fully isolated digital replica of their network environment. The project combines a Flask-based web application with AI/ML modules for attack detection, offering a safe environment for security testing and vulnerability assessment.

---

## Features

### User Management
- Secure user registration and login using Flask.
- Password hashing with bcrypt.
- Dual storage of user credentials using MySQL and LDAP for enhanced security.
- Session-based authentication using Flask-Login.

### Web Interface
- Intuitive and responsive HTML templates.
- Dedicated pages for home, registration, login, and contact.
- Real-time threat counter and risk level indicator (LOW / MEDIUM / HIGH).
- Live payload testing interface for all three attack types.
- Attack log dashboard showing the last 50 detected threats.

### Attack Detection Modules
- **SQL Injection Detection:** Uses machine learning techniques to identify SQL injection attempts, with live payload testing support.
- **XSS Attack Prediction:** Implements ensemble learning methods (Random Forest, Gradient Boosting, and XGBoost) to forecast cross-site scripting (XSS) attacks, with live payload prediction.
- **Session Hijacking Detection:** Leverages natural language processing (using BERT) on network logs to simulate and detect session hijacking attempts.

### Digital Twin-Based Attack Simulation

**Phase 1: Digital Twin Setup**
- Configure network security layers, including firewalls, IDS/IPS, and network segmentation.
- Isolate and validate the digital twin environment from production networks.
- Optimize network traffic patterns and latency settings.
- Virtualize servers, databases, and network devices for replicating real-world conditions.

**Phase 2: AI/ML-Driven Attack Model Training**
- Collect historical and novel attack data from trusted sources (e.g., MITRE ATT&CK, CVE databases).
- Preprocess, label, and structure data for model training.
- Develop and train AI/ML models to simulate various cyberattacks (e.g., SQL injection, XSS, session hijacking).

**Phase 3: Attack Simulation & Vulnerability Assessment**
- Execute simulated attack scenarios on the digital twin.
- Perform automated vulnerability scans and penetration tests.
- Capture data on system resilience and breach impacts.

**Phase 4: Insights & Recommendations**
- Generate actionable security insights and update remediation strategies.
- Implement automated remediation and define critical assets for continuous monitoring.

### Extensibility
- Modular design separating web functionalities from AI-agent detection modules.
- Clear structure enables the addition of new modules or enhancement of existing ones with minimal integration efforts.

---

## Installation and Setup

### Prerequisites
- Python 3.8 or later
- MySQL Server
- LDAP Server (for authentication)
- pip package manager

### Dependencies

Install the required Python packages:
```bash
pip install Flask flask-login flask-mail mysql-connector-python ldap3 bcrypt scikit-learn xgboost imbalanced-learn pandas transformers torch python-dotenv
```

Or if a `requirements.txt` is present:
```bash
pip install -r requirements.txt
```

### Configuration

**Environment Variables:**
Create a `.env` file in the root directory of the project with the following contents:
```
SECRET_KEY=your_secret_key_here
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_gmail_app_password
LDAP_PASSWORD=your_ldap_password
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_db_password
DB_NAME=registration_db
FLASK_DEBUG=False
```

> ⚠️ Never share or commit your `.env` file. It is already listed in `.gitignore`.

**MySQL Setup:**
Create the required database and tables:
```sql
CREATE DATABASE registration_db;

USE registration_db;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE attack_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100),
    attack_type VARCHAR(50),
    payload TEXT,
    result VARCHAR(50),
    confidence FLOAT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

**Dataset Paths:**
For the machine learning modules found in `/models/AI_agent1`, `/models/AI_agent2`, and `/models/AI_agent3`, update the dataset file paths as needed based on your environment.

---

## Running the Application

Start the Flask server by executing:
```bash
python app.py
```

The application will listen on `http://0.0.0.0:5001`. Open this address in your browser to access the system.

---

## Usage

### Web Interface
- **Homepage** (`/`): Landing page with project overview.
- **Registration** (`/register`): Create a new account. Passwords are hashed with bcrypt and stored in both MySQL and LDAP.
- **Login** (`/login`): Authenticate using your registered credentials.
- **Home/Dashboard** (`/home`): Main dashboard showing threat count, risk level, and all detection modules.
- **Attack Log** (`/attack_log`): View the last 50 detected attack attempts with timestamps.
- **Contact** (`/contact`): Send a message to the support team.

### Attack Simulation & Detection

| Route | Method | Description |
|-------|--------|-------------|
| `/sql` | POST | Run SQL Injection ML model on dataset |
| `/xss` | POST | Run XSS Attack ML model on dataset |
| `/session` | POST | Run Session Hijacking BERT model |
| `/sql_live` | POST | Test a custom SQL payload in real time |
| `/xss_live` | POST | Test a custom XSS payload in real time |
| `/session_live` | POST | Test a custom session payload in real time |

---

## Project Structure
```
CyberX-AI-Digital-Twin-main/
├── app.py                        # Main Flask app; routing, auth, attack detection.
├── .env                          # Environment variables (never commit this).
├── .gitignore                    # Git ignore rules.
├── requirements.txt              # Python dependencies.
├── README.md                     # Project documentation.
├── static/                       # Static assets.
│   └── style.css                 # Stylesheet.
├── templates/                    # HTML templates.
│   ├── index.html                # Landing page.
│   ├── home.html                 # Dashboard/home page.
│   ├── login.html                # Login page.
│   └── register.html             # Registration page.
└── models/                       # Machine learning modules.
    ├── AI_agent1/                # SQL Injection detection module.
    │   ├── __init__.py
    │   ├── sql_injection_detection.py
    │   └── advanced_generated_sql_injections.csv
    ├── AI_agent2/                # XSS Attack prediction module.
    │   ├── __init__.py
    │   ├── XSS_attack_prediction.py
    │   ├── train_model.py
    │   ├── Data_66_featurs.csv
    │   ├── model.pkl
    │   └── vectorizer.pkl
    └── AI_agent3/                # Session Hijacking detection module.
        ├── __init__.py
        ├── session_hijacking.py
        ├── LDAP.csv
        └── session_model.pkl
```

---

## Architecture and Design

### Backend
- Developed using Flask for handling HTTP requests and rendering HTML templates.
- Implements dual authentication storage via MySQL and LDAP.
- Flask-Login manages user sessions securely.
- Flask-Mail handles contact form email delivery.

### Security & Data Integrity
- Utilizes bcrypt for secure password hashing.
- Credentials and secrets managed via `.env` file using python-dotenv.
- Proper error handling for all database, LDAP, and mail operations.
- Input length validation on all live payload routes.
- All attack attempts logged to the database with timestamps.

### AI Modules
- Each module leverages modern ML frameworks (scikit-learn, XGBoost, and transformers) for simulating and detecting various cyberattacks.
- Modular design allows independent execution and testing of each attack simulation phase.
- Live payload testing routes allow real-time interaction with detection models.

### Digital Twin Integration
- Phased approach replicates a real-world network environment safely in an isolated setting.
- Supports a continuous feedback loop where outcomes drive AI model re-training and system configuration enhancements.
- Risk level dynamically updates based on detected threat count (LOW / MEDIUM / HIGH).

---

## Testing

**Unit Testing:**
Run tests using pytest:
```bash
pytest
```

**Manual Testing:**
Interact with the web pages by registering, logging in, and testing attack payloads via the live testing interface. Execute the machine learning modules to check data preprocessing and model performance.

---

## Author

**Mohammed Huzaifa**
AI-Powered Cybersecurity Digital Twin — Final Year Project

---

> ⚠️ This project is intended strictly for educational and research purposes in isolated environments. Do not deploy or use against real systems.