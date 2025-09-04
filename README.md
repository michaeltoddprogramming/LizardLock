### 1. Create Virtual Environment
```bash
python -m venv venv
```

### 2. Activate Virtual Environment
```bash
# On Linux/macOS
source venv/bin/activate

# On Windows
venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Generate Encryption Key (Optional) - This is done automatically
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > confidential.key
```

### 5. Run Database Migrations
```bash
python manage.py migrate
```

### 6. Create Superuser
```bash
python manage.py createsuperuser
```

### 7. Use my initial admin script
Run `python manage.py initial_admin_setup <yoursuperusername>`
You can skip making a super user and this script will trigger superuser creation.
Link up your authenticator app using the generated key.
Now you can login as a admin in terms of roles and are also a superuser that can access the /admin panel.


### 8. Start Development Server
```bash
python manage.py runserver
```

### Testing & Development
```bash
# Simulate anomalies for testing (spam failed logins, multiple IPs/users)
python generate_anomalies.py

# Encrypt existing MFA secrets (automatically handled)
python manage.py encrypt_mfa_secrets

# Populate user fields with mock/filler data
python manage.py populate_user_fields
```
