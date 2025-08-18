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

def generate_mfa_secret():
    return base64.b32encode(secrets.token_bytes(10)).decode('utf-8')

def get_totp_token(secret):
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", int(time.time()) // 30)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    token = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return f"{token:06d}"

def get_totp_uri(username, secret, issuer="LizardLock"):
    return f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"

def qr_svg(data):
    # USING AN API - QR-CODE IS NOT A STANDARD LIBRARY
    url = "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=" + urllib.parse.quote(data)
    return url

def home(request):
    return render(request, 'accounts/dashboard.html')

def register_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            secret = generate_mfa_secret()
            Lizards.objects.create(user=user, mfa_secret=secret)
            request.session['pending_user'] = user.username
            return redirect('two_factor')
    else:
        form = UserCreationForm()
    return render(request, 'accounts/register.html', {'form': form})

def two_factor_view(request):
    username = request.session.get('pending_user')
    if not username:
        return redirect('register')
    lizard = get_object_or_404(Lizards, user__username=username)
    totp_uri = get_totp_uri(username, lizard.mfa_secret)
    qr_url = qr_svg(totp_uri)
    mfa_verified = is_mfa_verified(request, lizard.user)
    if request.method == 'POST':
        code = request.POST.get('code')
        if code and verify_mfa_code(lizard.mfa_secret, code):
            set_mfa_verified(request, lizard.user)
            return redirect('two_factor')
        else:
            messages.error(request, "Invalid MFA code. Please try again.")
    is_approved = lizard.is_approved if is_mfa_verified(request, lizard.user) else False
    return render(request, 'accounts/two_factor.html', {
        'totp_uri': totp_uri,
        'qr_url': qr_url,
        'mfa_verified': is_mfa_verified(request, lizard.user),
        'is_approved': is_approved,
        'username': username
    })

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            lizard, created = Lizards.objects.get_or_create(user=user)
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

def verify_view(request):
    username = request.session.get('mfa_user')
    if not username:
        return redirect('login')
    attempt_key = f'mfa_attempts_{username}'
    if request.method == 'POST':
        request.session[attempt_key] = request.session.get(attempt_key, 0) + 1
        if request.session[attempt_key] > 5:
            messages.error(request, "Too many attempts. Please try again later.")
            return render(request, 'accounts/verify.html')
        code = request.POST.get('code')
        lizard = get_object_or_404(Lizards, user__username=username)
        if code and verify_mfa_code(lizard.mfa_secret, code):
            login(request, lizard.user)
            request.session.pop('mfa_user', None)
            request.session.pop(attempt_key, None)
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid MFA code.")
    return render(request, 'accounts/verify.html')

@login_required
def manage_view(request):
    lizard = get_object_or_404(Lizards, user=request.user)
    mfa_verified = is_mfa_verified(request, lizard.user)
    if lizard.role not in ['admin', 'manager']:
        return render(request, 'accounts/forbidden.html')
    if request.method == 'POST':
        mfa_code = request.POST.get('mfa_code')
        if not mfa_verified:
            if mfa_code and verify_mfa_code(lizard.mfa_secret, mfa_code):
                set_mfa_verified(request, lizard.user)
                return redirect('manage') 
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
        target = get_object_or_404(Lizards, id=lizard_id)
        # Prevent self-approval and self-role change
        if target.user == request.user and action in ['approve', 'revoke', 'role']:
            messages.error(request, "You cannot approve, revoke, or change your own role.")
        else:
            if action == 'approve':
                target.is_approved = True
                target.save()
                messages.success(request, f"Approved {target.user.username}")
            elif action == 'revoke':
                target.is_approved = False
                target.save()
                messages.success(request, f"Revoked {target.user.username}")
            elif action == 'role':
                new_role = request.POST.get('role')
                if new_role in dict(Lizards.ROLE_CHOICES):
                    target.role = new_role
                    target.save()
                    messages.success(request, f"Changed role for {target.user.username} to {new_role}")
        return redirect('manage')
    pending = Lizards.objects.filter(is_approved=False)
    users = Lizards.objects.filter(is_approved=True)
    return render(request, 'accounts/manage.html', {
        'pending': pending,
        'users': users,
        'mfa_required': not mfa_verified
    })

def verify_mfa_code(secret, code):
    expected = get_totp_token(secret)
    return hmac.compare_digest(expected, code)

def set_mfa_verified(request, user):
    request.session[f'mfa_verified_{user.id}'] = True

def is_mfa_verified(request, user):
    return request.session.get(f'mfa_verified_{user.id}', False)

@require_POST
@csrf_protect
def custom_logout(request):
    logout(request)
    for key in list(request.session.keys()):
        if key.startswith('mfa_verified_') or key in ['pending_user', 'mfa_user']:
            request.session.pop(key, None)
    return redirect('login')