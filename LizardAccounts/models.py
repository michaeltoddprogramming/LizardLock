from django.db import models
from django.contrib.auth.models import User

class Lizards(models.Model):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('manager', 'Manager'),
        ('user', 'User'),
        ('guest', 'Guest'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='guest')
    is_approved = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=32, blank=True, null=True)