from django.urls import path
from . import views

app_name = 'auth_integration'

urlpatterns = [
    # Authentication endpoints
    path('signup/', views.SignUpView.as_view(), name='signup'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('forgot-password/', views.ForgotPasswordView.as_view(), name='forgot_password'),
    path('reset-password/', views.ResetPasswordView.as_view(), name='reset_password'),
    path('verify-otp/', views.VerifyOTPView.as_view(), name='verify_otp'),
    path('resend-otp/', views.ResendOTPView.as_view(), name='resend_otp'),
    
    # Token management
    path('refresh/', views.TokenRefreshView.as_view(), name='refresh_token'),
    
    # User profile
    path('profile/', views.UserProfileView.as_view(), name='user_profile'),
    
    # Webhooks
    path('webhook/', views.SupabaseWebhookView.as_view(), name='supabase_webhook'),
    
    # Health check
    path('health/', views.HealthCheckView.as_view(), name='health_check'),
    
    # Test endpoint (DEBUG only)
    path('test-email/', views.TestEmailView.as_view(), name='test_email'),
]