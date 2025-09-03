from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('two_factor/', views.two_factor_view, name='two_factor'),
    path('verify/', views.verify_view, name='verify'),
    path('logout/', views.custom_logout, name='logout'),
]
