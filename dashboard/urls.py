# File: dashboard/urls.py

from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    # Dashboard endpoints
    path('overview/', views.DashboardOverviewView.as_view(), name='overview'),
    path('scan-activity/', views.ScanActivityView.as_view(), name='scan_activity'),
    path('category-distribution/', views.CategoryDistributionView.as_view(), name='category_distribution'),
    path('system-status/', views.SystemStatusView.as_view(), name='system_status'),
]