from django.apps import AppConfig
from django.db.models.signals import post_save


class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'LizardAccounts'

    def ready(self):
        # Import here to avoid AppRegistryNotReady
        from django.contrib.auth.models import User
        from .models import Lizards
        from .utils import generate_mfa_secret
        
        post_save.connect(create_lizard_for_superuser, sender=User)


def create_lizard_for_superuser(sender, instance, created, **kwargs):
    if created and instance.is_superuser:
        from .models import Lizards
        from .utils import generate_mfa_secret
        
        Lizards.objects.get_or_create(
            user=instance,
            defaults={
                'role': 'admin',
                'is_approved': True,
                'mfa_secret': generate_mfa_secret()
            }
        )
