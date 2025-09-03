from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_protect

from ..models import Lizards
from ..utils import (
    generate_mfa_secret, get_totp_uri, qr_svg, verify_mfa_code,
    set_mfa_verified, is_mfa_verified, is_rate_limited, log_asset_access
)


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
    return render(request, 'auth/register.html', {'form': form})


@csrf_protect
def two_factor_view(request):
    username = request.session.get('pending_user')
    if not username:
        return redirect('register')

    lizard = get_object_or_404(Lizards, user__username=username)
    totp_uri = get_totp_uri(username, lizard.mfa_secret)
    qr_url = qr_svg(totp_uri)
    mfa_verified = is_mfa_verified(request, lizard.user)[0]

    if is_rate_limited(request, f"mfa_setup_{username}"):
        messages.error(request, "Too many attempts. Please wait before trying again.")
        return render(request, 'auth/two_factor.html', {
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
    return render(request, 'auth/two_factor.html', {
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
    return render(request, 'auth/login.html', {'form': form})


@csrf_protect
def verify_view(request):
    username = request.session.get('mfa_user')
    if not username:
        return redirect('login')

    if request.method == 'POST':
        if is_rate_limited(request, f"mfa_login_{username}"):
            messages.error(request, "Too many attempts. Please try again later.")
            return render(request, 'auth/verify.html', {'rate_limited': True})

        code = request.POST.get('code', '').strip()
        if code and len(code) == 6 and code.isdigit():
            lizard = get_object_or_404(Lizards, user__username=username)
            if verify_mfa_code(lizard.mfa_secret, code):
                login(request, lizard.user)
                set_mfa_verified(request, lizard.user)
                request.session.pop('mfa_user', None)
                from ..utils import get_client_ip, cache
                cache.delete(f"mfa_attempts_mfa_login_{username}_{get_client_ip(request)}")
                return redirect('dashboard')
            else:
                messages.error(request, "Invalid MFA code.")
        else:
            messages.error(request, "Please enter a valid 6-digit code.")

    return render(request, 'auth/verify.html', {'rate_limited': False})


@require_POST
@csrf_protect
def custom_logout(request):
    if request.user.is_authenticated:
        try:
            log_asset_access(request.user, 'auth', 'logout', 'logout', request, True, is_mfa_verified(request, request.user)[0])
        except Exception as log_error:
            import logging
            logging.error(f"Failed to log logout: {str(log_error)}")

    logout(request)

    for key in list(request.session.keys()):
        if key.startswith('mfa_verified_') or key in ['pending_user', 'mfa_user', 'mfa_setup_required']:
            request.session.pop(key, None)

    request.session.flush()
    return redirect('login')
