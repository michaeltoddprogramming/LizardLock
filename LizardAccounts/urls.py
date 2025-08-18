from . import views
from .views import custom_logout
from django.urls import path
from django.contrib.auth.views import LogoutView
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.dashboard_view, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('two_factor/', views.two_factor_view, name='two_factor'),
    path('verify/', views.verify_view, name='verify'),
    path('manage/', views.manage_view, name='manage'),
    path('logout/', custom_logout, name='logout'),
    path('images/', views.images_view, name='images'),
    path('documents/', views.documents_view, name='documents'),
    path('confidential/', views.confidential_view, name='confidential'),
    path('images/serve/<int:image_id>/', views.serve_image, name='serve_image'),
    path('documents/serve/<int:document_id>/', views.serve_document, name='serve_document'),
    path('images/preview/<int:image_id>/', views.image_preview, name='image_preview'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)