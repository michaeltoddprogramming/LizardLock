from django.urls import path
from . import views
from ..auth.views import custom_logout

urlpatterns = [
    path('', views.dashboard_view, name='dashboard'),
    path('manage/', views.manage_view, name='manage'),
    path('analytics/', views.analytics_view, name='analytics'),
    path('logout/', custom_logout, name='logout'),
]
