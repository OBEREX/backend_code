# File: users/urls.py

from django.urls import path
from . import views

app_name = 'users'

urlpatterns = [
    # Profile management
    path('profile/', views.ProfileDetailView.as_view(), name='profile_detail'),
    path('profile/update/', views.ProfileUpdateView.as_view(), name='profile_update'),
    path('change-password/', views.ChangePasswordView.as_view(), name='change_password'),
    
    # Settings
    path('settings/', views.UserSettingsView.as_view(), name='user_settings'),
    path('settings/notifications/', views.NotificationSettingsView.as_view(), name='notification_settings'),
]