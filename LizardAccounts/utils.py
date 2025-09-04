import base64
import hmac
import struct
import hashlib
import time
import random
import urllib.parse
import secrets
import os
import mimetypes
import datetime
import qrcode
import ipaddress
from io import BytesIO
from cryptography.fernet import Fernet
from django.core.cache import cache
from django.conf import settings
from django.shortcuts import render
from django.db import models
from django.contrib.auth.models import User

from .models import Lizards, log_asset_access


def get_encryption_key():
    key = os.environ.get('LIZARDLOCK_ENCRYPTION_KEY')
    if key:
        try:
            decoded_key = base64.b64decode(key)
            if len(decoded_key) != 32:
                raise ValueError("Invalid key length")
            return key
        except:
            pass
    key_file = os.path.join(settings.BASE_DIR, 'confidential.key')
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            file_content = f.read()

            if len(file_content) == 44:

                return file_content
            elif len(file_content) == 32:

                return base64.b64encode(file_content)


    key = Fernet.generate_key()
    with open(key_file, 'wb') as f:
        f.write(key)
    os.chmod(key_file, 0o600)
    return key


FERNET = Fernet(get_encryption_key())

ACCESS_MATRIX = {
    'admin': {
        'images': ['create', 'read', 'write', 'delete', 'list'],
        'documents': ['create', 'read', 'write', 'delete', 'list'],
        'confidential': ['create', 'read', 'write', 'delete', 'list']
    },
    'manager': {
        'images': ['create', 'read', 'write', 'delete', 'list'],
        'documents': ['create', 'read', 'write', 'delete', 'list'],
        'confidential': ['create', 'read', 'write', 'list']
    },
    'user': {
        'images': ['read', 'write', 'list'],
        'documents': ['read', 'write', 'list'],
        'confidential': ['read', 'list']
    },
    'guest': {
        'images': ['read', 'list'],
        'documents': [],
        'confidential': []
    }
}


def generate_mfa_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode('utf-8')


def get_totp_token(secret):
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", int(time.time()) // 30)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    token = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return f"{token:06d}"


def get_totp_uri(username, secret, issuer="LizardLock"):
    safe_username = urllib.parse.quote(username, safe='@')
    return f"otpauth://totp/{issuer}:{safe_username}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


def qr_svg(data):
    img = qrcode.make(data)
    buf = BytesIO()
    img.save(buf, format='PNG')
    img_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{img_b64}"


def verify_mfa_code(secret, code):
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", int(time.time() // 30))
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    token = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return hmac.compare_digest(f"{token:06d}", code)


def set_mfa_verified(request, user):
    now = datetime.datetime.now(datetime.timezone.utc)
    request.session[f'mfa_verified_{user.id}'] = True
    request.session[f'mfa_verified_time_{user.id}'] = now.timestamp()
    request.session.set_expiry(600)


def is_mfa_verified(request, user, timeout=1800):
    verified = request.session.get(f'mfa_verified_{user.id}', False)
    timestamp = request.session.get(f'mfa_verified_time_{user.id}', 0)
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    if verified and (now - timestamp) < timeout:
        return True, None
    if verified and (now - timestamp) >= timeout:
        del request.session[f'mfa_verified_{user.id}']
        del request.session[f'mfa_verified_time_{user.id}']
        return False, "MFA verification timed out. Please verify again."
    return False, "MFA verification required for sensitive actions."


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            pass

    ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return '127.0.0.1'


def is_rate_limited(request, identifier, increment=True):
    ip = get_client_ip(request)
    key = f"rate_limit_{identifier}_{ip}"

    attempts = cache.get(key, 0)
    if attempts >= 5:
        return True

    if increment:
        cache.set(key, attempts + 1, timeout=300)
    return False


def check_access(user, asset_type, action):
    if not user.is_authenticated:
        return False

    try:
        lizard = Lizards.objects.get(user=user)
        if not lizard.is_approved:
            return False
        user_role = lizard.role
        allowed_actions = ACCESS_MATRIX.get(user_role, {}).get(asset_type, [])
        return action in allowed_actions
    except Lizards.DoesNotExist:
        return False


def require_mfa_for_sensitive_actions(view_func):
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            context = {'error': 'Authentication required'}
            return render(request, 'base/forbidden.html', context, status=401)
        action = request.POST.get('action') or request.GET.get('action')
        if action in ['create', 'write', 'delete']:
            mfa_ok, mfa_reason = is_mfa_verified(request, request.user)
            if not mfa_ok:
                try:
                    log_asset_access(request.user, 'unknown', 'unknown', action, request, False, False)
                except Exception as log_error:
                    import logging
                    logging.error(f"Failed to log MFA denial: {str(log_error)}")
                context = {'error': mfa_reason}
                return render(request, 'base/forbidden.html', context, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper


def validate_file_signature(file_content, expected_types):
    if len(file_content) < 8:
        return False, "File too small to validate"

    signatures = {
        'image/jpeg': [b'\xFF\xD8\xFF'],
        'image/png': [b'\x89PNG\r\n\x1a\n'],
        'image/gif': [b'GIF87a', b'GIF89a'],
        'application/pdf': [b'%PDF-'],
        'text/plain': [],
        'application/msword': [b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [
            b'PK\x03\x04'
        ]
    }

    for mime_type in expected_types:
        if mime_type in signatures:
            type_signatures = signatures[mime_type]

            if mime_type == 'text/plain':
                try:
                    file_content[:1024].decode('utf-8')
                    return True, ""
                except UnicodeDecodeError:
                    try:
                        file_content[:1024].decode('latin-1')
                        return True, ""
                    except:
                        continue

            for signature in type_signatures:
                if file_content.startswith(signature):
                    return True, ""

    return False, "File signature does not match expected type"


def validate_file(uploaded_file, allowed_types, max_size=5*1024*1024):
    if uploaded_file.size > max_size:
        return False, "File too large."

    if uploaded_file.content_type not in allowed_types:
        return False, "Invalid file type based on content type."

    try:
        file_content = uploaded_file.read(1024)
        uploaded_file.seek(0)

        valid, error = validate_file_signature(file_content, allowed_types)
        if not valid:
            return False, f"Invalid file signature: {error}"

    except Exception as e:
        return False, "Error validating file."

    if not uploaded_file.name or len(uploaded_file.name) > 255:
        return False, "Invalid file name."

    dangerous_extensions = ['.exe', '.bat', '.cmd', '.scr', '.vbs', '.js', '.jar', '.com', '.pif']
    file_ext = os.path.splitext(uploaded_file.name)[1].lower()
    if file_ext in dangerous_extensions:
        return False, "Dangerous file extension not allowed."

    return True, ""


def sanitize_filename(filename):
    if not filename:
        return "unnamed_file"
    filename = os.path.basename(filename)
    dangerous_chars = ['<', '>', ':', '"', '|', '?', '*', '\\', '/', '\0']
    for char in dangerous_chars:
        filename = filename.replace(char, '_')
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:250] + ext
    return filename
