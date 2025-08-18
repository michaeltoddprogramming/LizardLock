from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Lizards
import base64, hmac, struct, hashlib, time, random
import urllib.parse
import secrets
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_protect
import os
import mimetypes
from django.http import HttpResponse, JsonResponse, FileResponse, Http404
from django.core.files.base import ContentFile
from django.conf import settings
from cryptography.fernet import Fernet
from django.db import transaction
from .models import Lizards, ImageAsset, DocumentAsset, ConfidentialAsset, log_asset_access
from django.core.cache import cache
import datetime
import qrcode
from io import BytesIO
from django.utils.http import http_date
from django.views.decorators.cache import never_cache
import ipaddress
# File signature validation without external dependencies

def generate_mfa_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode('utf-8')  # Increased from 10 to 20 bytes

def get_totp_token(secret):
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", int(time.time()) // 30)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    token = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return f"{token:06d}"

def get_totp_uri(username, secret, issuer="LizardLock"):
    # Sanitize username to prevent injection
    safe_username = urllib.parse.quote(username, safe='@')
    return f"otpauth://totp/{issuer}:{safe_username}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"

def qr_svg(data):
    img = qrcode.make(data)
    buf = BytesIO()
    img.save(buf, format='PNG')
    img_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{img_b64}"

@csrf_protect
def register_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            secret = generate_mfa_secret()
            Lizards.objects.create(user=user, mfa_secret=secret)
            request.session['pending_user'] = user.username
            request.session['mfa_setup_required'] = True
            return redirect('two_factor')
    else:
        form = UserCreationForm()
    return render(request, 'accounts/register.html', {'form': form})

@csrf_protect
def two_factor_view(request):
    username = request.session.get('pending_user')
    if not username:
        return redirect('register')
    
    lizard = get_object_or_404(Lizards, user__username=username)
    totp_uri = get_totp_uri(username, lizard.mfa_secret)
    qr_url = qr_svg(totp_uri)
    mfa_verified = is_mfa_verified(request, lizard.user)[0]
    
    # Rate limiting for MFA setup
    if is_rate_limited(request, f"mfa_setup_{username}"):
        messages.error(request, "Too many attempts. Please wait before trying again.")
        return render(request, 'accounts/two_factor.html', {
            'totp_uri': totp_uri,
            'qr_url': qr_url,
            'mfa_verified': False,
            'is_approved': False,
            'username': username,
            'rate_limited': True
        })
    
    if request.method == 'POST':
        code = request.POST.get('code', '').strip()
        if code and len(code) == 6 and code.isdigit():
            if verify_mfa_code(lizard.mfa_secret, code):
                set_mfa_verified(request, lizard.user)
                request.session.pop('mfa_setup_required', None)
                return redirect('two_factor')
            else:
                messages.error(request, "Invalid MFA code. Please try again.")
        else:   
            messages.error(request, "Please enter a valid 6-digit code.")
    
    is_approved = lizard.is_approved if is_mfa_verified(request, lizard.user)[0] else False
    return render(request, 'accounts/two_factor.html', {
        'totp_uri': totp_uri,
        'qr_url': qr_url,
        'mfa_verified': is_mfa_verified(request, lizard.user)[0],
        'is_approved': is_approved,
        'username': username,
        'rate_limited': False
    })

@csrf_protect
def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            lizard, created = Lizards.objects.get_or_create(user=user)
            if created:
                # If user doesn't have MFA setup, require it
                lizard.mfa_secret = generate_mfa_secret()
                lizard.save()
                request.session['pending_user'] = user.username
                request.session['mfa_setup_required'] = True
                return redirect('two_factor')
            
            if lizard.is_approved:
                request.session['mfa_user'] = user.username
                return redirect('verify')
            else:
                messages.error(request, "Your account is not approved yet.")
        else:
            messages.error(request, "Invalid credentials.")
    else:
        form = AuthenticationForm()
    return render(request, 'accounts/login.html', {'form': form})

@csrf_protect
def verify_view(request):
    username = request.session.get('mfa_user')
    if not username:
        return redirect('login')
    
    if request.method == 'POST':
        if is_rate_limited(request, f"mfa_login_{username}"):
            messages.error(request, "Too many attempts. Please try again later.")
            return render(request, 'accounts/verify.html', {'rate_limited': True})
        
        code = request.POST.get('code', '').strip()
        if code and len(code) == 6 and code.isdigit():
            lizard = get_object_or_404(Lizards, user__username=username)
            if verify_mfa_code(lizard.mfa_secret, code):
                login(request, lizard.user)
                set_mfa_verified(request, lizard.user)
                request.session.pop('mfa_user', None)
                # Clear rate limiting on successful login
                cache.delete(f"mfa_attempts_mfa_login_{username}_{get_client_ip(request)}")
                return redirect('dashboard')
            else:
                messages.error(request, "Invalid MFA code.")
        else:
            messages.error(request, "Please enter a valid 6-digit code.")
    
    return render(request, 'accounts/verify.html', {'rate_limited': False})

@login_required
@csrf_protect
def manage_view(request):
    lizard = get_object_or_404(Lizards, user=request.user)
    mfa_verified = is_mfa_verified(request, lizard.user)
    
    if lizard.role not in ['admin', 'manager']:
        return render(request, 'accounts/forbidden.html')
    
    if request.method == 'POST':
        # Require fresh MFA for admin actions
        mfa_code = request.POST.get('mfa_code', '').strip()
        if not mfa_verified:
            if mfa_code and len(mfa_code) == 6 and mfa_code.isdigit():
                if verify_mfa_code(lizard.mfa_secret, mfa_code):
                    set_mfa_verified(request, lizard.user)
                    return redirect('manage') 
                else:
                    messages.error(request, "Invalid MFA code.")
            else:
                messages.error(request, "MFA code required for admin actions.")
            
            pending = Lizards.objects.filter(is_approved=False)
            users = Lizards.objects.filter(is_approved=True)
            return render(request, 'accounts/manage.html', {
                'pending': pending,
                'users': users,
                'mfa_required': True
            })
        
        action = request.POST.get('action')
        lizard_id = request.POST.get('lizard_id')
        
        # Validate lizard_id
        if not lizard_id or not lizard_id.isdigit():
            messages.error(request, "Invalid user ID.")
            return redirect('manage')
        
        target = get_object_or_404(Lizards, id=lizard_id)
        
        # Prevent self-modification
        if target.user == request.user:
            messages.error(request, "You cannot modify your own account.")
        else:
            if action == 'approve':
                target.is_approved = True
                target.save()
                messages.success(request, f"Approved {target.user.username}")
                log_asset_access(request.user, 'admin', 'user_management', f'approve_{target.user.username}', request, True, True)
            elif action == 'revoke':
                target.is_approved = False
                target.save()
                messages.success(request, f"Revoked {target.user.username}")
                log_asset_access(request.user, 'admin', 'user_management', f'revoke_{target.user.username}', request, True, True)
            elif action == 'role':
                new_role = request.POST.get('role')
                if new_role in dict(Lizards.ROLE_CHOICES):
                    old_role = target.role
                    target.role = new_role
                    target.save()
                    messages.success(request, f"Changed role for {target.user.username} from {old_role} to {new_role}")
                    log_asset_access(request.user, 'admin', 'user_management', f'role_change_{target.user.username}_{old_role}_to_{new_role}', request, True, True)
                else:
                    messages.error(request, "Invalid role.")
        
        return redirect('manage')
    
    pending = Lizards.objects.filter(is_approved=False)
    users = Lizards.objects.filter(is_approved=True)
    return render(request, 'accounts/manage.html', {
        'pending': pending,
        'users': users,
        'mfa_required': not mfa_verified
    })

def verify_mfa_code(secret, code):
    # Reduced time window for better security - only current time window
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
    request.session.set_expiry(600)  # Session expires in 10 minutes

def is_mfa_verified(request, user, timeout=1800):
    verified = request.session.get(f'mfa_verified_{user.id}', False)
    timestamp = request.session.get(f'mfa_verified_time_{user.id}', 0)
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    if verified and (now - timestamp) < timeout:
        return True, None
    if verified and (now - timestamp) >= timeout:
        # Timed out
        del request.session[f'mfa_verified_{user.id}']
        del request.session[f'mfa_verified_time_{user.id}']
        return False, "MFA verification timed out. Please verify again."
    return False, "MFA verification required for sensitive actions."

def get_encryption_key():
    key = os.environ.get('LIZARDLOCK_ENCRYPTION_KEY')
    if key:
        try:
            # Validate key format
            decoded_key = base64.b64decode(key)
            if len(decoded_key) != 32:
                raise ValueError("Invalid key length")
            return decoded_key
        except:
            pass
    
    # fallback to file for dev - with better security
    key_file = os.path.join(settings.BASE_DIR, 'confidential.key')
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            key = f.read()
            if len(key) == 32:
                return key
    
    # Generate new key with proper permissions
    key = Fernet.generate_key()
    with open(key_file, 'wb') as f:
        f.write(key)
    os.chmod(key_file, 0o600)  # Read/write for owner only
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
            return render(request, 'accounts/forbidden.html', context, status=401)
        action = request.POST.get('action') or request.GET.get('action')
        if action in ['create', 'write', 'delete']:
            mfa_ok, mfa_reason = is_mfa_verified(request, request.user)
            if not mfa_ok:
                log_asset_access(request.user, 'unknown', 'unknown', action, request, False, False)
                context = {'error': mfa_reason}
                return render(request, 'accounts/forbidden.html', context, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper

def validate_file_signature(file_content, expected_types):
    """Validate file using magic numbers/signatures"""
    if len(file_content) < 8:
        return False, "File too small to validate"
    
    # Common file signatures (magic numbers)
    signatures = {
        'image/jpeg': [b'\xFF\xD8\xFF'],
        'image/png': [b'\x89PNG\r\n\x1a\n'],
        'image/gif': [b'GIF87a', b'GIF89a'],
        'application/pdf': [b'%PDF-'],
        'text/plain': [],  # Text files don't have a reliable signature
        'application/msword': [b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'],  # Office compound document
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [
            b'PK\x03\x04'  # ZIP-based format
        ]
    }
    
    for mime_type in expected_types:
        if mime_type in signatures:
            type_signatures = signatures[mime_type]
            
            # Text files - do basic text validation
            if mime_type == 'text/plain':
                try:
                    # Try to decode as text
                    file_content[:1024].decode('utf-8')
                    return True, ""
                except UnicodeDecodeError:
                    # Try other common encodings
                    try:
                        file_content[:1024].decode('latin-1')
                        return True, ""
                    except:
                        continue
            
            # Check magic numbers
            for signature in type_signatures:
                if file_content.startswith(signature):
                    return True, ""
    
    return False, "File signature does not match expected type"

def validate_file(uploaded_file, allowed_types, max_size=5*1024*1024):
    # Size check
    if uploaded_file.size > max_size:
        return False, "File too large."
    
    # MIME type check (basic)
    if uploaded_file.content_type not in allowed_types:
        return False, "Invalid file type based on content type."
    
    # File signature validation
    try:
        file_content = uploaded_file.read(1024)  # Read first 1KB
        uploaded_file.seek(0)  # Reset file pointer
        
        valid, error = validate_file_signature(file_content, allowed_types)
        if not valid:
            return False, f"Invalid file signature: {error}"
        
    except Exception as e:
        return False, "Error validating file."
    
    # File name validation
    if not uploaded_file.name or len(uploaded_file.name) > 255:
        return False, "Invalid file name."
    
    # Check for dangerous file extensions
    dangerous_extensions = ['.exe', '.bat', '.cmd', '.scr', '.vbs', '.js', '.jar', '.com', '.pif']
    file_ext = os.path.splitext(uploaded_file.name)[1].lower()
    if file_ext in dangerous_extensions:
        return False, "Dangerous file extension not allowed."
    
    return True, ""

def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal and other attacks"""
    if not filename:
        return "unnamed_file"
    
    # Remove path components
    filename = os.path.basename(filename)
    
    # Remove or replace dangerous characters
    dangerous_chars = ['<', '>', ':', '"', '|', '?', '*', '\\', '/', '\0']
    for char in dangerous_chars:
        filename = filename.replace(char, '_')
    
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:250] + ext
    
    return filename

@login_required
@csrf_protect
@require_mfa_for_sensitive_actions
def images_view(request):
    action = request.POST.get('action') or request.GET.get('action', 'list')
    context = {'files': [], 'error': None}
    try:
        lizard = Lizards.objects.get(user=request.user)
        user_permissions = ACCESS_MATRIX.get(lizard.role, {})
    except Lizards.DoesNotExist:
        user_permissions = {}
    if not check_access(request.user, 'images', action):
        context['error'] = 'Access denied'
        context['user_permissions'] = user_permissions
        log_asset_access(request.user, 'images', 'unknown', action, request, False, is_mfa_verified(request, request.user)[0])
        return render(request, 'accounts/forbidden.html', context)
    
    try:
        if action == 'list':
            images = ImageAsset.objects.all()
            context['files'] = [{
                'id': img.id,
                'name': img.name,
                'uploaded_at': img.uploaded_at,
                'size': img.file.size if img.file else 0,
            } for img in images]
            
        elif action == 'read':
            image_id = request.GET.get('id')
            if not image_id or not image_id.isdigit():
                context['error'] = 'Valid image ID required'
            else:
                return redirect('serve_image', image_id=image_id)
                
        elif action == 'create' and request.method == 'POST':
            if 'file' not in request.FILES:
                context['error'] = 'No file provided'
            else:
                name = request.POST.get('name', '').strip()
                if not name:
                    context['error'] = 'Name required'
                else:
                    uploaded_file = request.FILES['file']
                    uploaded_file.name = sanitize_filename(uploaded_file.name)
                    valid, error = validate_file(uploaded_file, ['image/jpeg', 'image/png', 'image/gif'])
                    if not valid:
                        context['error'] = error
                    else:
                        with transaction.atomic():
                            ImageAsset.objects.create(
                                owner=request.user,  # <-- add this line
                                file=uploaded_file,
                                name=name[:255]
                            )
                        log_asset_access(request.user, 'images', name, 'create', request, True, is_mfa_verified(request, request.user)[0])
                        return redirect('images')
                        
        elif action == 'write' and request.method == 'POST':
            image_id = request.POST.get('id')
            if not image_id or not image_id.isdigit() or 'file' not in request.FILES:
                context['error'] = 'Valid image ID and file required'
            else:
                try:
                    image = ImageAsset.objects.get(id=image_id)
                    old_file = image.file
                    uploaded_file = request.FILES['file']
                    uploaded_file.name = sanitize_filename(uploaded_file.name)
                    
                    valid, error = validate_file(uploaded_file, ['image/jpeg', 'image/png', 'image/gif'])
                    if not valid:
                        context['error'] = error
                    else:
                        image.file = uploaded_file
                        image.save()
                        if old_file:
                            try:
                                old_file.close()  # Ensure file handle is released
                            except Exception:
                                pass
                            old_file.delete()
                        log_asset_access(request.user, 'images', image.name, 'write', request, True, is_mfa_verified(request, request.user)[0])
                        return redirect('images')
                except ImageAsset.DoesNotExist:
                    context['error'] = 'Image not found'
                    
        elif action == 'delete' and request.method == 'POST':
            image_id = request.POST.get('id')
            if not image_id or not image_id.isdigit():
                context['error'] = 'Valid image ID required'
            else:
                try:
                    image = ImageAsset.objects.get(id=image_id)
                    image_name = image.name
                    if image.file:
                        try:
                            image.file.close()  # Ensure file handle is released
                        except Exception:
                            pass
                        image.file.delete(save=False)  # Don't update the model, just delete the file
                    image.delete()
                    log_asset_access(request.user, 'images', image_name, 'delete', request, True, is_mfa_verified(request, request.user)[0])
                    return redirect('images')
                except ImageAsset.DoesNotExist:
                    context['error'] = 'Image not found'
                    
    except Exception as e:
        context['error'] = "An error occurred."
        # Log the actual error for debugging (not shown to user)
        import logging
        logging.error(f"Images view error: {str(e)}")
    
    # Always refresh file list for display
    if not context.get('error'):
        images = ImageAsset.objects.all()
        context['files'] = [{
            'id': img.id,
            'name': img.name,
            'uploaded_at': img.uploaded_at,
            'size': img.file.size if img.file else 0
        } for img in images]
    
    context['user_permissions'] = user_permissions
    return render(request, 'accounts/images.html', context)

@login_required
@csrf_protect
@require_mfa_for_sensitive_actions
def documents_view(request):
    action = request.POST.get('action') or request.GET.get('action', 'list')
    context = {'files': [], 'error': None}
    
    try:
        lizard = Lizards.objects.get(user=request.user)
        user_permissions = ACCESS_MATRIX.get(lizard.role, {})
    except Lizards.DoesNotExist:
        user_permissions = {}
    
    if not check_access(request.user, 'documents', action):
        context['error'] = 'Access denied'
        context['user_permissions'] = user_permissions
        log_asset_access(request.user, 'documents', 'unknown', action, request, False, is_mfa_verified(request, request.user)[0])
        return render(request, 'accounts/documents.html', context)
    
    try:
        if action == 'list':
            documents = DocumentAsset.objects.all()
            context['files'] = [{
                'id': doc.id,
                'name': doc.name,
                'uploaded_at': doc.uploaded_at,
                'size': doc.file.size if doc.file else 0
            } for doc in documents]
            
        elif action == 'read':
            doc_id = request.GET.get('id')
            if not doc_id or not doc_id.isdigit():
                context['error'] = 'Valid document ID required'
            else:
                return redirect('serve_document', document_id=doc_id)
                
        elif action == 'create' and request.method == 'POST':
            if 'file' not in request.FILES:
                context['error'] = 'No file provided'
            else:
                name = request.POST.get('name', '').strip()
                if not name:
                    context['error'] = 'Name required'
                else:
                    uploaded_file = request.FILES['file']
                    uploaded_file.name = sanitize_filename(uploaded_file.name)
                    
                    valid, error = validate_file(uploaded_file, [
                        'application/pdf', 'text/plain', 'application/msword',
                        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                    ])
                    if not valid:
                        context['error'] = error
                    else:
                        with transaction.atomic():
                            DocumentAsset.objects.create(
                                owner=request.user,
                                file=uploaded_file,
                                name=name[:255]
                            )
                        log_asset_access(request.user, 'documents', name, 'create', request, True, is_mfa_verified(request, request.user)[0])
                        return redirect('documents')
                        
        elif action == 'write' and request.method == 'POST':
            doc_id = request.POST.get('id')
            if not doc_id or not doc_id.isdigit() or 'file' not in request.FILES:
                context['error'] = 'Valid document ID and file required'
            else:
                try:
                    document = DocumentAsset.objects.get(id=doc_id)
                    old_file = document.file
                    uploaded_file = request.FILES['file']
                    uploaded_file.name = sanitize_filename(uploaded_file.name)
                    
                    valid, error = validate_file(uploaded_file, [
                        'application/pdf', 'text/plain', 'application/msword',
                        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                    ])
                    if not valid:
                        context['error'] = error
                    else:
                        document.file = uploaded_file
                        document.save()  # Save the new file
                        if old_file:
                            try:
                                old_file.close()  # Ensure file handle is released
                            except Exception:
                                pass
                            old_file.delete(save=False)  # Don't update the model, just delete the file
                        log_asset_access(request.user, 'documents', document.name, 'write', request, True, is_mfa_verified(request, request.user)[0])
                        return redirect('documents')
                except DocumentAsset.DoesNotExist:
                    context['error'] = 'Document not found'
                    
        elif action == 'delete' and request.method == 'POST':
            doc_id = request.POST.get('id')
            if not doc_id or not doc_id.isdigit():
                context['error'] = 'Valid document ID required'
            else:
                try:
                    document = DocumentAsset.objects.get(id=doc_id)
                    doc_name = document.name
                    if document.file:
                        try:
                            document.file.close()  # Ensure file handle is released
                        except Exception:
                            pass
                        document.file.delete()
                    document.delete()
                    log_asset_access(request.user, 'documents', doc_name, 'delete', request, True, is_mfa_verified(request, request.user)[0])
                    return redirect('documents')
                except DocumentAsset.DoesNotExist:
                    context['error'] = 'Document not found'
                    
    except Exception as e:
        context['error'] = "An error occurred."
        import logging
        logging.error(f"Documents view error: {str(e)}")
    
    if not context.get('error'):
        documents = DocumentAsset.objects.all()
        context['files'] = [{
            'id': doc.id,
            'name': doc.name,
            'uploaded_at': doc.uploaded_at,
            'size': doc.file.size if doc.file else 0
        } for doc in documents]
    
    context['user_permissions'] = user_permissions
    return render(request, 'accounts/documents.html', context)

@login_required
@csrf_protect
@require_mfa_for_sensitive_actions
def confidential_view(request):
    action = request.POST.get('action') or request.GET.get('action', 'list')
    context = {'files': [], 'error': None, 'view_content': None, 'view_name': None}
    
    if not check_access(request.user, 'confidential', action):
        context['error'] = 'Access denied'
        log_asset_access(request.user, 'confidential', 'unknown', action, request, False, is_mfa_verified(request, request.user))
        return render(request, 'accounts/confidential.html', context)
    
    # Always require MFA for confidential access
    if not is_mfa_verified(request, request.user):
        context['error'] = 'MFA verification required for confidential access'
        return render(request, 'accounts/confidential.html', context)
    
    try:
        if action == 'list':
            confidential_files = ConfidentialAsset.objects.all()
            context['files'] = [{
                'id': conf.id,
                'name': conf.name,
                'uploaded_at': conf.uploaded_at,
                'size': conf.encrypted_file.size if conf.encrypted_file else 0
            } for conf in confidential_files]
            
        elif action == 'read':
            conf_id = request.GET.get('id')
            if not conf_id or not conf_id.isdigit():
                context['error'] = 'Valid confidential file ID required'
            else:
                try:
                    confidential = ConfidentialAsset.objects.get(id=conf_id)
                    encrypted_content = confidential.encrypted_file.read()
                    decrypted_content = FERNET.decrypt(encrypted_content).decode('utf-8')
                    context['view_content'] = decrypted_content
                    context['view_name'] = confidential.name
                    log_asset_access(request.user, 'confidential', confidential.name, 'read', request, True, True)
                except ConfidentialAsset.DoesNotExist:
                    context['error'] = 'Confidential file not found'
                except Exception as e:
                    context['error'] = 'Error decrypting file'
                    
        elif action == 'create' and request.method == 'POST':
            name = request.POST.get('name', '').strip()
            content = request.POST.get('content', '')
            
            if not name:
                context['error'] = 'Name required'
            elif len(content) > 1024 * 1024:  # 1MB limit for confidential text
                context['error'] = 'Content too large'
            else:
                try:
                    # Sanitize name
                    name = sanitize_filename(name)[:255]
                    encrypted_content = FERNET.encrypt(content.encode('utf-8'))
                    encrypted_file = ContentFile(encrypted_content, name=f"{name}.enc")
                    
                    ConfidentialAsset.objects.create(
                        encrypted_file=encrypted_file,
                        name=name,
                        encryption_metadata='Fernet AES-128'
                    )
                    log_asset_access(request.user, 'confidential', name, 'create', request, True, True)
                    return redirect('confidential')
                except Exception as e:
                    context['error'] = 'Error creating confidential file'
                    
        elif action == 'write' and request.method == 'POST':
            conf_id = request.POST.get('id')
            content = request.POST.get('content', '')
            
            if not conf_id or not conf_id.isdigit():
                context['error'] = 'Valid confidential file ID required'
            elif len(content) > 1024 * 1024:
                context['error'] = 'Content too large'
            else:
                try:
                    confidential = ConfidentialAsset.objects.get(id=conf_id)
                    encrypted_content = FERNET.encrypt(content.encode('utf-8'))
                    old_file = confidential.encrypted_file
                    
                    confidential.encrypted_file = ContentFile(encrypted_content, name=f"{confidential.name}.enc")
                    confidential.save()
                    
                    if old_file:
                        old_file.delete()
                    
                    log_asset_access(request.user, 'confidential', confidential.name, 'write', request, True, True)
                    return redirect('confidential')
                except ConfidentialAsset.DoesNotExist:
                    context['error'] = 'Confidential file not found'
                except Exception as e:
                    context['error'] = 'Error updating confidential file'
                    
        elif action == 'delete' and request.method == 'POST':
            conf_id = request.POST.get('id')
            if not conf_id or not conf_id.isdigit():
                context['error'] = 'Valid confidential file ID required'
            else:
                try:
                    confidential = ConfidentialAsset.objects.get(id=conf_id)
                    conf_name = confidential.name
                    if confidential.encrypted_file:
                        confidential.encrypted_file.delete()
                    confidential.delete()
                    log_asset_access(request.user, 'confidential', conf_name, 'delete', request, True, True)
                    return redirect('confidential')
                except ConfidentialAsset.DoesNotExist:
                    context['error'] = 'Confidential file not found'
                    
    except Exception as e:
        context['error'] = "An error occurred."
        import logging
        logging.error(f"Confidential view error: {str(e)}")
    
    # Always refresh file list
    confidential_files = ConfidentialAsset.objects.all()
    context['files'] = [{
        'id': conf.id,
        'name': conf.name,
        'uploaded_at': conf.uploaded_at,
        'size': conf.encrypted_file.size if conf.encrypted_file else 0
    } for conf in confidential_files]
    
    return render(request, 'accounts/confidential.html', context)

@require_POST
@csrf_protect
def custom_logout(request):
    # Log the logout action
    if request.user.is_authenticated:
        log_asset_access(request.user, 'auth', 'logout', 'logout', request, True, is_mfa_verified(request, request.user)[0])
    
    logout(request)
    
    # Clear all MFA and session data
    for key in list(request.session.keys()):
        if key.startswith('mfa_verified_') or key in ['pending_user', 'mfa_user', 'mfa_setup_required']:
            request.session.pop(key, None)
    
    request.session.flush()  # Complete session cleanup
    return redirect('login')

@login_required
def dashboard_view(request):
    try:
        lizard = Lizards.objects.get(user=request.user)
        user_permissions = ACCESS_MATRIX.get(lizard.role, {})
        role = lizard.role
    except Lizards.DoesNotExist:
        user_permissions = {}
        role = 'guest'
    
    # Log dashboard access
    log_asset_access(request.user, 'dashboard', 'access', 'read', request, True, is_mfa_verified(request, request.user)[0])  # <-- FIXED

    return render(request, 'accounts/dashboard.html', {
        'user_permissions': user_permissions,
        'role': role,
        'mfa_verified': is_mfa_verified(request, request.user)[0]  # <-- FIXED
    })

def get_client_ip(request):
    """Get client IP with proper validation"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Take the first IP and validate it
        ip = x_forwarded_for.split(',')[0].strip()
        # Basic IP validation
        
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

def is_rate_limited(request, identifier):
    """Improved rate limiting with better key management"""
    ip = get_client_ip(request)
    key = f"rate_limit_{identifier}_{ip}"
    
    attempts = cache.get(key, 0)
    if attempts >= 5:
        return True
    
    cache.set(key, attempts + 1, timeout=300)  # 5 minute window
    return False

@login_required
@csrf_protect
@never_cache
def serve_image(request, image_id):
    """Secure image serving with proper validation"""
    try:
        image = ImageAsset.objects.get(id=image_id)
        
        if not check_access(request.user, 'images', 'read'):
            log_asset_access(request.user, 'images', image.name, 'read', request, False, is_mfa_verified(request, request.user)[0])
            raise Http404("Access denied")

        log_asset_access(request.user, 'images', image.name, 'read', request, True, is_mfa_verified(request, request.user)[0])

        if not image.file:
            raise Http404("Image file not found")
        
        try:
            image.file.seek(0)
            file_content = image.file.read()
        except Exception:
            raise Http404("Error reading image file")
        
        # Verify file is actually an image using signatures
        valid_image, _ = validate_file_signature(file_content[:1024], ['image/jpeg', 'image/png', 'image/gif'])
        if not valid_image:
            raise Http404("Invalid image file")
        
        file_hash = hashlib.sha256(file_content).hexdigest()
        
        response = HttpResponse(
            file_content, 
            content_type=mimetypes.guess_type(image.name)[0] or 'application/octet-stream'
        )
        
        # Sanitize filename for header
        safe_filename = sanitize_filename(image.name)
        response['Content-Disposition'] = f'inline; filename="{safe_filename}"'
        response['X-Content-Hash'] = file_hash
        response['X-Frame-Options'] = 'DENY'
        response['X-Content-Type-Options'] = 'nosniff'
        response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response['Pragma'] = 'no-cache'
        response['Expires'] = '0'
        
        return response
        
    except ImageAsset.DoesNotExist:
        raise Http404("Image not found")

@login_required  
@csrf_protect
@never_cache
def serve_document(request, document_id):
    """Secure document serving with proper validation"""
    
    try:
        document = DocumentAsset.objects.get(id=document_id)
        
        if not check_access(request.user, 'documents', 'read'):
            log_asset_access(request.user, 'documents', document.name, 'read', request, False, is_mfa_verified(request, request.user)[0])
            raise Http404("Access denied")

        log_asset_access(request.user, 'documents', document.name, 'read', request, True, is_mfa_verified(request, request.user)[0])

        if not document.file:
            raise Http404("Document file not found")
        
        try:
            document.file.seek(0)
            file_content = document.file.read()
        except Exception:
            raise Http404("Error reading document file")
        
        # Verify file type using signatures
        allowed_doc_types = [
            'application/pdf', 
            'text/plain', 
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ]
        
        valid_doc, _ = validate_file_signature(file_content[:1024], allowed_doc_types)
        if not valid_doc:
            raise Http404("Invalid document file type")
        
        file_hash = hashlib.sha256(file_content).hexdigest()
        
        response = HttpResponse(
            file_content, 
            content_type=mimetypes.guess_type(document.name)[0] or 'application/octet-stream'
        )
        
        safe_filename = sanitize_filename(document.name)
        response['Content-Disposition'] = f'attachment; filename="{safe_filename}"'
        response['X-Content-Hash'] = file_hash
        response['X-Frame-Options'] = 'DENY'
        response['X-Content-Type-Options'] = 'nosniff'
        response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response['Pragma'] = 'no-cache'
        response['Expires'] = '0'
        
        return response
        
    except DocumentAsset.DoesNotExist:
        raise Http404("Document not found")

@login_required
@csrf_protect
def image_preview(request, image_id):
    """Secure image preview with proper validation"""
    if not image_id.isdigit():
        return render(request, 'accounts/forbidden.html')
    
    try:
        image = get_object_or_404(ImageAsset, id=image_id)
        
        if not check_access(request.user, 'images', 'read'):
            log_asset_access(request.user, 'images', image.name, 'preview', request, False, is_mfa_verified(request, request.user[0]))
            return render(request, 'accounts/forbidden.html')

        log_asset_access(request.user, 'images', image.name, 'preview', request, True, is_mfa_verified(request, request.user[0]))

        return render(request, 'accounts/image_view.html', {'image': image})
    
    except Exception:
        return render(request, 'accounts/forbidden.html')

# Additional security function for analytics endpoint
@login_required
@csrf_protect
def analytics_view(request):
    """Analytics endpoint with anomaly detection"""
    lizard = get_object_or_404(Lizards, user=request.user)
    
    # Only admins can access analytics
    if lizard.role != 'admin':
        return render(request, 'accounts/forbidden.html')

    if not is_mfa_verified(request, request.user[0]):
        messages.error(request, "MFA verification required for analytics access.")
        return redirect('dashboard')
    
    # Get access logs for analysis
    from .models import AccessLog  # Assuming you have an AccessLog model
    
    try:
        # Basic analytics data
        recent_logs = AccessLog.objects.all().order_by('-timestamp')[:100]
        
        # Simple anomaly detection
        anomalies = detect_anomalies(recent_logs)
        
        context = {
            'logs': recent_logs,
            'anomalies': anomalies,
            'log_count': AccessLog.objects.count()
        }
        
        return render(request, 'accounts/analytics.html', context)
        
    except Exception as e:
        messages.error(request, "Error accessing analytics data.")
        return redirect('dashboard')

def detect_anomalies(logs):
    """Simple rule-based anomaly detection"""
    anomalies = []
    
    if not logs:
        return anomalies
    
    # Group logs by user and IP
    user_activity = {}
    ip_activity = {}
    
    for log in logs:
        # User activity tracking
        user_key = f"{log.user.username if log.user else 'anonymous'}"
        if user_key not in user_activity:
            user_activity[user_key] = {'failed_attempts': 0, 'actions': [], 'ips': set()}
        
        user_activity[user_key]['actions'].append(log.action)
        user_activity[user_key]['ips'].add(log.ip_address)
        
        if not log.success:
            user_activity[user_key]['failed_attempts'] += 1
        
        # IP activity tracking
        ip_key = log.ip_address
        if ip_key not in ip_activity:
            ip_activity[ip_key] = {'users': set(), 'failed_attempts': 0}
        
        if log.user:
            ip_activity[ip_key]['users'].add(log.user.username)
        
        if not log.success:
            ip_activity[ip_key]['failed_attempts'] += 1
    
    # Detect anomalies
    for user, activity in user_activity.items():
        # Multiple failed attempts
        if activity['failed_attempts'] > 5:
            anomalies.append({
                'type': 'Multiple Failed Attempts',
                'description': f"User {user} has {activity['failed_attempts']} failed attempts",
                'severity': 'HIGH'
            })
        
        # Multiple IPs for same user
        if len(activity['ips']) > 3:
            anomalies.append({
                'type': 'Multiple IP Addresses',
                'description': f"User {user} accessed from {len(activity['ips'])} different IPs",
                'severity': 'MEDIUM'
            })
    
    for ip, activity in ip_activity.items():
        # Multiple users from same IP
        if len(activity['users']) > 5:
            anomalies.append({
                'type': 'Multiple Users Same IP',
                'description': f"IP {ip} used by {len(activity['users'])} different users",
                'severity': 'MEDIUM'
            })
        
        # High failure rate from IP
        if activity['failed_attempts'] > 10:
            anomalies.append({
                'type': 'High Failure Rate',
                'description': f"IP {ip} has {activity['failed_attempts']} failed attempts",
                'severity': 'HIGH'
            })
    
    return anomalies