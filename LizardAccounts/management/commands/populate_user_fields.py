from django.core.management.base import BaseCommand
from django.contrib.auth.models import User

class Command(BaseCommand):
    help = 'Populate missing user fields for existing users'

    def handle(self, *args, **options):
        updated_count = 0
        
        for user in User.objects.all():
            needs_update = False
            
            if not user.first_name:
                user.first_name = f"User{user.id}"
                needs_update = True
                
            if not user.last_name:
                user.last_name = "Unknown"
                needs_update = True
                
            if not user.email:
                user.email = f"user{user.id}@example.com"
                needs_update = True
                
            if needs_update:
                user.save()
                updated_count += 1
                self.stdout.write(f"Updated user: {user.username}")
        
        self.stdout.write(
            self.style.SUCCESS(f'Successfully updated {updated_count} users')
        )