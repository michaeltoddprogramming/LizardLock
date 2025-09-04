from django.core.management.base import BaseCommand
from LizardAccounts.models import Lizards
from LizardAccounts.utils import FERNET
import base64

class Command(BaseCommand):
    help = 'Encrypt existing MFA secrets in place'

    def handle(self, *args, **options):
        lizards_with_plaintext = Lizards.objects.filter(
            mfa_secret__isnull=False
        ).exclude(mfa_secret='')
        
        count = 0
        for lizard in lizards_with_plaintext:
            if lizard.mfa_secret:
                try:
                    base64.b64decode(lizard.mfa_secret.encode('utf-8'))
                    FERNET.decrypt(base64.b64decode(lizard.mfa_secret.encode('utf-8')))
                    continue
                except:
                    plaintext_secret = lizard.mfa_secret
                    encrypted_secret = FERNET.encrypt(plaintext_secret.encode('utf-8'))
                    lizard.mfa_secret = base64.b64encode(encrypted_secret).decode('utf-8')
                    lizard.save()
                    count += 1
                    self.stdout.write(f"Encrypted MFA secret for user: {lizard.user.username}")
        
        self.stdout.write(
            self.style.SUCCESS(f'Successfully encrypted {count} MFA secrets in place')
        )