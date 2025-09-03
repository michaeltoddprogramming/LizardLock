from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [

    path('', include('LizardAccounts.auth.urls')),


    path('', include('LizardAccounts.management.urls')),


    path('', include('LizardAccounts.assets.urls')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
