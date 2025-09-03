from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.csrf import csrf_protect

from ..models import Lizards, AssetAccessLog
from ..utils import (
    is_mfa_verified, verify_mfa_code, set_mfa_verified,
    log_asset_access, ACCESS_MATRIX
)


@login_required
def dashboard_view(request):
    try:
        lizard = Lizards.objects.get(user=request.user)
        user_permissions = ACCESS_MATRIX.get(lizard.role, {})
        role = lizard.role
    except Lizards.DoesNotExist:
        user_permissions = {}
        role = 'guest'

    try:
        log_asset_access(request.user, 'dashboard', 'access', 'read', request, True, is_mfa_verified(request, request.user)[0])
    except Exception as log_error:
        import logging
        logging.error(f"Failed to log dashboard access: {str(log_error)}")

    return render(request, 'management/dashboard.html', {
        'user_permissions': user_permissions,
        'role': role,
        'mfa_verified': is_mfa_verified(request, request.user)[0]
    })


@login_required
@csrf_protect
def manage_view(request):
    lizard = get_object_or_404(Lizards, user=request.user)
    mfa_verified = is_mfa_verified(request, lizard.user)

    if lizard.role not in ['admin', 'manager']:
        return render(request, 'base/forbidden.html')

    if request.method == 'POST':
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
            return render(request, 'management/manage.html', {
                'pending': pending,
                'users': users,
                'mfa_required': True
            })

        action = request.POST.get('action')
        lizard_id = request.POST.get('lizard_id')

        if not lizard_id or not lizard_id.isdigit():
            messages.error(request, "Invalid user ID.")
            return redirect('manage')

        target = get_object_or_404(Lizards, id=lizard_id)

        if target.user == request.user:
            messages.error(request, "You cannot modify your own account.")
        else:
            if action == 'approve':
                target.is_approved = True
                target.save()
                messages.success(request, f"Approved {target.user.username}")
                try:
                    log_asset_access(request.user, 'admin', 'user_management', f'approve_{target.user.username}', request, True, True)
                except Exception as log_error:
                    import logging
                    logging.error(f"Failed to log user approval: {str(log_error)}")
            elif action == 'revoke':
                target.is_approved = False
                target.save()
                messages.success(request, f"Revoked {target.user.username}")
                try:
                    log_asset_access(request.user, 'admin', 'user_management', f'revoke_{target.user.username}', request, True, True)
                except Exception as log_error:
                    import logging
                    logging.error(f"Failed to log user revocation: {str(log_error)}")
            elif action == 'role':
                new_role = request.POST.get('role')
                if new_role in dict(Lizards.ROLE_CHOICES):
                    old_role = target.role
                    target.role = new_role
                    target.save()
                    messages.success(request, f"Changed role for {target.user.username} from {old_role} to {new_role}")
                    try:
                        log_asset_access(request.user, 'admin', 'user_management', f'role_change_{target.user.username}_{old_role}_to_{new_role}', request, True, True)
                    except Exception as log_error:
                        import logging
                        logging.error(f"Failed to log role change: {str(log_error)}")
                else:
                    messages.error(request, "Invalid role.")

        return redirect('manage')

    pending = Lizards.objects.filter(is_approved=False)
    users = Lizards.objects.filter(is_approved=True)
    return render(request, 'management/manage.html', {
        'pending': pending,
        'users': users,
        'mfa_required': not mfa_verified
    })


@login_required
@csrf_protect
def analytics_view(request):
    lizard = get_object_or_404(Lizards, user=request.user)

    if lizard.role != 'admin':
        return render(request, 'base/forbidden.html')

    if not is_mfa_verified(request, request.user)[0]:
        messages.error(request, "MFA verification required for analytics access.")
        return redirect('dashboard')

    try:
        recent_logs = AssetAccessLog.objects.all().order_by('-timestamp')[:100]
        anomalies = detect_anomalies(recent_logs)

        context = {
            'logs': recent_logs,
            'anomalies': anomalies,
            'log_count': AssetAccessLog.objects.count()
        }

        return render(request, 'management/analytics.html', context)

    except Exception as e:
        messages.error(request, "Error accessing analytics data.")
        return redirect('dashboard')


def detect_anomalies(logs):
    anomalies = []

    if not logs:
        return anomalies

    user_activity = {}
    ip_activity = {}

    for log in logs:
        user_key = f"{log.user.username if log.user else 'anonymous'}"
        if user_key not in user_activity:
            user_activity[user_key] = {'failed_attempts': 0, 'actions': [], 'ips': set()}

        user_activity[user_key]['actions'].append(log.operation)
        user_activity[user_key]['ips'].add(log.ip_address)

        if not log.success:
            user_activity[user_key]['failed_attempts'] += 1

        ip_key = log.ip_address
        if ip_key not in ip_activity:
            ip_activity[ip_key] = {'users': set(), 'failed_attempts': 0}

        if log.user:
            ip_activity[ip_key]['users'].add(log.user.username)

        if not log.success:
            ip_activity[ip_key]['failed_attempts'] += 1

    for user, activity in user_activity.items():
        if activity['failed_attempts'] > 5:
            anomalies.append({
                'type': 'Multiple Failed Attempts',
                'description': f"User {user} has {activity['failed_attempts']} failed attempts",
                'severity': 'HIGH'
            })

        if len(activity['ips']) > 3:
            anomalies.append({
                'type': 'Multiple IP Addresses',
                'description': f"User {user} accessed from {len(activity['ips'])} different IPs",
                'severity': 'MEDIUM'
            })

    for ip, activity in ip_activity.items():
        if len(activity['users']) > 5:
            anomalies.append({
                'type': 'Multiple Users Same IP',
                'description': f"IP {ip} used by {len(activity['users'])} different users",
                'severity': 'MEDIUM'
            })

        if activity['failed_attempts'] > 10:
            anomalies.append({
                'type': 'High Failure Rate',
                'description': f"IP {ip} has {activity['failed_attempts']} failed attempts",
                'severity': 'HIGH'
            })

    return anomalies
