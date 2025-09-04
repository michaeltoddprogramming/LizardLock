import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LizardLock.settings')
django.setup()

from LizardAccounts.models import AssetAccessLog
from django.contrib.auth.models import User

def create_test_anomalies():
    user, _ = User.objects.get_or_create(username='anomaly_test', defaults={
        'email': 'test@example.com',
        'first_name': 'Test',
        'last_name': 'User'
    })
    
    print("Creating failed login attempts...")
    for i in range(7):
        AssetAccessLog.objects.create(
            user=user,
            asset_type='auth',
            asset_name='login',
            operation='login',
            ip_address='127.0.0.1',
            success=False,
            mfa_verified=False
        )
    
    ips = ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4', '192.168.1.5']
    for ip in ips:
        AssetAccessLog.objects.create(
            user=user,
            asset_type='images',
            asset_name='test.jpg',
            operation='read',
            ip_address=ip,
            success=True,
            mfa_verified=True
        )
    
    for i in range(12):
        AssetAccessLog.objects.create(
            user=user,
            asset_type='auth',
            asset_name='login',
            operation='login',
            ip_address='10.0.0.1',
            success=False,
            mfa_verified=False
        )
    
    print("Creating multiple users from same IP...")
    for i in range(6):
        test_user, _ = User.objects.get_or_create(
            username=f'multi_user_{i}', 
            defaults={
                'email': f'user{i}@example.com',
                'first_name': f'User{i}',
                'last_name': 'Test'
            }
        )
        AssetAccessLog.objects.create(
            user=test_user,
            asset_type='images',
            asset_name='shared_access.jpg',
            operation='read',
            ip_address='192.168.100.50',
            success=True,
            mfa_verified=True
        )
    
    print("I AM ABOUT TO HARM MYSELF!!!")
    print("I AM ACTIVELY GOING TO ATTACK MY OWN SITE")
    print("EXPECTED")
    print("Multiple Failed Attempts (HIGH)")
    print("Multiple IP Addresses (MEDIUM)")  
    print("High Failure Rate (HIGH)")
    print("Multiple Users Same IP (MEDIUM)")

if __name__ == "__main__":
    create_test_anomalies()