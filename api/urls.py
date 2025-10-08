# File: api/urls.py

from django.urls import path, include
from . import views

app_name = 'api'

urlpatterns = [
    # API Root
    path('', views.APIRootView.as_view(), name='api_root'),
    
    # Version 1 API
    path('v1/', include([
        path('auth/', include('auth_integration.urls')),
        path('users/', include('users.urls')),
        path('dashboard/', include('dashboard.urls')),
        path('test/', views.ProtectedTestView.as_view(), name='protected_test'),
        # Future modules will be added here
        # path('inventory/', include('inventory.urls')),
        # path('analytics/', include('analytics.urls')),
    ])),
]