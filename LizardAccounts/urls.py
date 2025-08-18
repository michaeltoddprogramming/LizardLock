from . import views
from .views import custom_logout
from django.urls import path
from django.contrib.auth.views import LogoutView

urlpatterns = [
    path('', views.home, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('two_factor/', views.two_factor_view, name='two_factor'),
    path('verify/', views.verify_view, name='verify'),
    path('manage/', views.manage_view, name='manage'),
    path('logout/', custom_logout, name='logout'),
]