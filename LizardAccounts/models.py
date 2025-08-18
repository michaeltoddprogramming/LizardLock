from django.db import models
from django.contrib.auth.models import User
import hashlib

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

class AssetAccessLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    asset_type = models.CharField(max_length=32)
    asset_name = models.CharField(max_length=255)
    operation = models.CharField(max_length=32)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=256, blank=True)
    success = models.BooleanField(default=False)
    mfa_verified = models.BooleanField(default=False)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['asset_type', 'operation']),
            models.Index(fields=['timestamp']),
        ]

def log_asset_access(user, asset_type, asset_name, operation, request, success, mfa_verified):
    # Improved IP detection for proxies/load balancers
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    agent = request.META.get('HTTP_USER_AGENT', '')[:255]
    AssetAccessLog.objects.create(
        user=user,
        asset_type=asset_type,
        asset_name=asset_name,
        operation=operation,
        ip_address=ip,
        user_agent=agent,
        success=success,
        mfa_verified=mfa_verified
    )

class ImageAsset(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.ImageField(upload_to='')
    name = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    sha256 = models.CharField(max_length=64, blank=True)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        if self.file:
            self.sha256 = self.compute_hash()
            super().save(update_fields=['sha256'])

    def compute_hash(self):
        hasher = hashlib.sha256()
        for chunk in self.file.chunks():
            hasher.update(chunk)
        return hasher.hexdigest()

    def verify_integrity(self):
        if not self.sha256:
            return False
        current_hash = self.compute_hash()
        return current_hash == self.sha256

class DocumentAsset(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to='documents/')
    name = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    sha256 = models.CharField(max_length=64, blank=True)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        if self.file:
            self.sha256 = self.compute_hash()
            super().save(update_fields=['sha256'])

    def compute_hash(self):
        hasher = hashlib.sha256()
        for chunk in self.file.chunks():
            hasher.update(chunk)
        return hasher.hexdigest()

    def verify_integrity(self):
        if not self.sha256:
            return False
        current_hash = self.compute_hash()
        return current_hash == self.sha256

class ConfidentialAsset(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    encrypted_file = models.FileField(upload_to='confidential/')
    name = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    sha256 = models.CharField(max_length=64, blank=True)
    encryption_metadata = models.TextField(blank=True)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        if self.encrypted_file:
            self.sha256 = self.compute_hash()
            super().save(update_fields=['sha256'])

    def compute_hash(self):
        hasher = hashlib.sha256()
        for chunk in self.encrypted_file.chunks():
            hasher.update(chunk)
        return hasher.hexdigest()

    def verify_integrity(self):
        if not self.sha256:
            return False
        current_hash = self.compute_hash()
        return current_hash == self.sha256