# JWKS Server (Educational Project)

A simple RESTful JSON Web Key Set (JWKS) server built with **Python** and **Flask**. This project handles RSA key pair generation, serves unexpired public keys at the standard well-known endpoint, issues signed JWTs via `/auth`, and supports issuing tokens signed with expired keys using a query parameter.

---

## Prerequisites

Make sure you have **Python 3.8+** installed on your system.

---

## Installation & Setup

1. **Clone the repository and navigate into the project directory:**
   ```bash
   git clone https://github.com/crexpoxjr/JWKS_Server
   cd jwks-server

2. **Create virtual environment and install dependencies**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows, use: venv\Scripts\activate  
    pip install -r requirements.txt

3. **Run coverage test and/or run the server**
    ```bash
    pytest --cov=app --cov-report=term-missing
    python app.py

<img width="1009" height="414" alt="Screenshot from 2026-09-20 13-29-20" src="https://github.com/user-attachments/assets/a2880f8e-ed97-4f79-8fda-978ce2837346" />
