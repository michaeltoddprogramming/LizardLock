from django.contrib import admin
from django.contrib.admin.sites import AdminSite
from .models import Lizards

class SecureAdminSite(AdminSite):
    def has_permission(self, request):
        return request.user.is_superuser and super().has_permission(request)

admin.site = SecureAdminSite()
admin.site.register(Lizards)
