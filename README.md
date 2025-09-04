# Set up a virtual environment
python -m venv venv
source venv/bin/activate  # Use `venv\Scripts\activate` if on Windows...

# Install dependencies
pip install -r requirements.txt

# (Optional) Manually generate encryption key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > confidential.key

# Run database migrations
python manage.py migrate

# Make your super user - to approve your initial admin
python manage.py createsuperuser

you will go to 127.0.0.1:8000/admin - and find your waiting approval object and approve it

# Run the development server
python manage.py runserver

# Simulate anomalies for testing (spam failed logins, multiple IPs/users)
python generate_anomalies.py

# Encrypt existing MFA secrets (now done automatically)
python manage.py encrypt_mfa_secrets

# Populate user fields with mock/filler data
python manage.py populate_user_fields
