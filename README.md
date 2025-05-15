# Diabetes Prediction System with Zero Trust Security

A Flask-based web application that predicts the risk of diabetes using machine learning. The system ensures data security by integrating **Zero Trust Security (ZTS)** principles, protecting sensitive medical information through continuous authentication and encryption.

---

##  Features

-  Predicts diabetes risk using trained ML models
-  Implements Zero Trust Security architecture
-  Stores user and session data securely via SQLAlchemy
-  Uses Flask-Login and Flask-Bcrypt for authentication and hashing
-  Logs user activity and predictions
-  Environment variables managed with `python-dotenv`

---

##  Zero Trust Security (ZTS)

This system is built on the Zero Trust principle of **"never trust, always verify"**. It includes:

- **Identity and Access Management (IAM):** via Flask-Login and Bcrypt
- **Microsegmentation:** Role-based access control
- **Continuous Monitoring:** Logs and alerts
- **Encryption:** End-to-end data encryption for sensitive data




## ⚙️ Installation

### 1. Clone the repository


git clone https://github.com/YourUsername/YourRepoName.git
cd YourRepoName

### 2. Create and activate a virtual environment

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

### 3. Install the dependencies

pip install -r requirements.txt

### Running the App

python run.py

