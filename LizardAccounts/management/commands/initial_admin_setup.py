from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from LizardAccounts.models import Lizards
from LizardAccounts.utils import generate_mfa_secret, get_totp_uri, qr_svg
import qrcode
from io import BytesIO
import base64

class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument('username', type=str, help='Username of the admin user')

    def handle(self, *args, **options):
        username = options['username']
        
        try:
            user = User.objects.get(username=username)
            lizard, created = Lizards.objects.get_or_create(
                user=user,
                defaults={
                    'role': 'admin',
                    'is_approved': True
                }
            )
            
            if not lizard.get_mfa_secret():
                secret = generate_mfa_secret()
                lizard.set_mfa_secret(secret)
                lizard.save()
            
            totp_uri = get_totp_uri(username, lizard.get_mfa_secret())
            
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(totp_uri)
            qr.make(fit=True)
            
            self.stdout.write(self.style.SUCCESS(f'Admin user {username} set up successfully!'))
            self.stdout.write(f'MFA Secret: {lizard.get_mfa_secret()}')
            self.stdout.write(f'TOTP URI: {totp_uri}')
            self.stdout.write('Add this secret to your authenticator app manually')
            
        except User.DoesNotExist:
            self.stdout.write(
                self.style.ERROR(f'User {username} does not exist. Create it first with createsuperuser.')
            )