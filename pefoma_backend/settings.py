import os
import environ
from pathlib import Path


# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Environment variables
env = environ.Env(
    DEBUG=(bool, False),
    ALLOWED_HOSTS=(list, []),
)

# Read .env file
environ.Env.read_env(BASE_DIR / '.env')

# Token Provider: 'supabase', 'django', or 'hybrid'
TOKEN_PROVIDER = env('TOKEN_PROVIDER', default="hybrid")

# Token Provider Mode (for hybrid provider)
# 'supabase': Use only Supabase tokens
# 'django': Use only Django custom tokens
# 'hybrid': Try both (useful during migration)
TOKEN_PROVIDER_MODE = env('TOKEN_PROVIDER_MODE', default='supabase')

# Django Token Settings (when using custom provider)
DJANGO_ACCESS_TOKEN_TTL_MINUTES = env.int('DJANGO_ACCESS_TOKEN_TTL_MINUTES', default=15)
DJANGO_REFRESH_TOKEN_TTL_DAYS = env.int('DJANGO_REFRESH_TOKEN_TTL_DAYS', default=7)

# Email Provider: 'supabase', 'sendgrid', 'aws', 'django'
EMAIL_PROVIDER = env('EMAIL_PROVIDER', default='supabase')

# Microsoft Graph API Configuration
EMAIL_PROVIDER = env('EMAIL_PROVIDER', default='microsoft_graph')

MICROSOFT_TENANT_ID = env('MICROSOFT_TENANT_ID')
MICROSOFT_CLIENT_ID = env('MICROSOFT_CLIENT_ID')
MICROSOFT_CLIENT_SECRET = env('MICROSOFT_CLIENT_SECRET')
MICROSOFT_SENDER_EMAIL = env('MICROSOFT_SENDER_EMAIL')
MICROSOFT_SENDER_NAME = env('MICROSOFT_SENDER_NAME', default='Pefoma')

# Optional test configuration
MICROSOFT_TEST_EMAIL = env('MICROSOFT_TEST_EMAIL', default='')

# Email rate limiting (messages per minute)
EMAIL_RATE_LIMIT = env.int('EMAIL_RATE_LIMIT', default=30)

# Update the email service integration
if EMAIL_PROVIDER == 'microsoft_graph':
    # Ensure required Microsoft settings are present
    if not all([MICROSOFT_TENANT_ID, MICROSOFT_CLIENT_ID, 
                MICROSOFT_CLIENT_SECRET, MICROSOFT_SENDER_EMAIL]):
        raise ImproperlyConfigured(
            "Microsoft Graph email provider requires all MICROSOFT_* settings"
        )



# Twilio Configuration (for SMS OTP - future use)
TWILIO_ACCOUNT_SID = env('TWILIO_ACCOUNT_SID', default='')
TWILIO_AUTH_TOKEN = env('TWILIO_AUTH_TOKEN', default='')
TWILIO_PHONE_NUMBER = env('TWILIO_PHONE_NUMBER', default='')


# Profile Sync Strategy: 'supabase_wins', 'django_wins', 'merge', 'manual'
PROFILE_SYNC_STRATEGY = env('PROFILE_SYNC_STRATEGY', default='merge')

# Enable profile sync via webhooks
ENABLE_PROFILE_SYNC = env.bool('ENABLE_PROFILE_SYNC', default=True)

# Webhook signature verification
SUPABASE_WEBHOOK_SECRET = env('SUPABASE_WEBHOOK_SECRET', default='')
VERIFY_WEBHOOK_SIGNATURE = env.bool('VERIFY_WEBHOOK_SIGNATURE', default=True)

# Guest user settings
ENABLE_GUEST_USERS = env.bool('ENABLE_GUEST_USERS', default=True)


# Security
SECRET_KEY = env('DJANGO_SECRET_KEY')
DEBUG = env('DEBUG')
ALLOWED_HOSTS = env('ALLOWED_HOSTS')

# Session management
SESSION_IDLE_TIMEOUT_MINUTES = env.int('SESSION_IDLE_TIMEOUT_MINUTES', default=30)
SESSION_ABSOLUTE_TIMEOUT_HOURS = env.int('SESSION_ABSOLUTE_TIMEOUT_HOURS', default=24)

# OTP rate limiting
OTP_MAX_REQUESTS_PER_HOUR = env.int('OTP_MAX_REQUESTS_PER_HOUR', default=3)
OTP_COOLDOWN_MINUTES = env.int('OTP_COOLDOWN_MINUTES', default=5)

# Password reset rate limiting  
PASSWORD_RESET_MAX_REQUESTS_PER_HOUR = env.int('PASSWORD_RESET_MAX_REQUESTS_PER_HOUR', default=3)

# API rate limiting (requests per minute)
API_RATE_LIMIT = {
    'guest': env.int('API_RATE_LIMIT_GUEST', default=10),
    'free': env.int('API_RATE_LIMIT_FREE', default=60),
    'premium': env.int('API_RATE_LIMIT_PREMIUM', default=300),
    'enterprise': env.int('API_RATE_LIMIT_ENTERPRISE', default=1000),
}

FEATURE_FLAGS = {
    'ENABLE_OTP_LOGIN': env.bool('ENABLE_OTP_LOGIN', default=False),
    'ENABLE_SOCIAL_AUTH': env.bool('ENABLE_SOCIAL_AUTH', default=False),
    'ENABLE_2FA': env.bool('ENABLE_2FA', default=False),
    'ENABLE_CHAT': env.bool('ENABLE_CHAT', default=True),
    'ENABLE_GUEST_CHAT': env.bool('ENABLE_GUEST_CHAT', default=True),
}

# Supabase Configuration
SUPABASE_URL = env('SUPABASE_URL')
SUPABASE_ANON_KEY = env('SUPABASE_ANON_KEY')
SUPABASE_SERVICE_ROLE_KEY = env('SUPABASE_SERVICE_ROLE_KEY')
SUPABASE_JWT_SECRET = env('SUPABASE_JWT_SECRET')

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third-party apps
    'rest_framework',
    'drf_yasg',
    'corsheaders',
    'django_extensions',
    
    # Local apps
    'auth_integration',
    'users',
    'api',
    'dashboard',
    'common'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'auth_integration.middleware.SupabaseJWTMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'pefoma_backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'pefoma_backend.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env.db()['NAME'],
        'USER': env.db()['USER'],
        'PASSWORD': env.db()['PASSWORD'],
        'HOST': env.db()['HOST'],
        'PORT': env.db()['PORT'],
        'OPTIONS': {
            'sslmode': 'require',
        },
    }
}

# REST Framework Configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'auth_integration.authentication.SupabaseAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
}

# CORS Configuration for Development
CORS_ALLOW_ALL_ORIGINS = DEBUG  # Only in development
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",  # React dev server
    "http://127.0.0.1:3000",  # Alternative localhost
    "https://pefoma-web.vercel.app",  # Production frontend
    # Add your production domain here
]

CORS_ALLOW_CREDENTIALS = True

# Allow specific headers that your frontend sends
CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

# Allow specific methods
CORS_ALLOWED_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Structured logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'json': {
            '()': 'pythonjsonlogger.jsonlogger.JsonFormatter',
            'format': '%(asctime)s %(name)s %(levelname)s %(message)s'
        }
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'django.log',
            'maxBytes': 1024 * 1024 * 10,  # 10MB
            'backupCount': 10,
            'formatter': 'json' if not DEBUG else 'verbose',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'auth_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'auth.log',
            'maxBytes': 1024 * 1024 * 10,  # 10MB
            'backupCount': 10,
            'formatter': 'json',
        },
        'webhook_file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'webhooks.log',
            'maxBytes': 1024 * 1024 * 5,  # 5MB
            'backupCount': 5,
            'formatter': 'json',
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'auth_integration': {
            'handlers': ['console', 'auth_file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'auth_integration.webhook': {
            'handlers': ['webhook_file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'profile_sync': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'microsoft_graph' : {
            'handlers': ['console', 'file'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        }
    },
}

# Create logs directory
os.makedirs(BASE_DIR / 'logs', exist_ok=True)

# Cache Configuration
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': env('REDIS_URL', default='redis://localhost:5432/1'),
    }
}

# Session Configuration
SESSION_COOKIE_AGE = 86400  # 24 hours
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True

# Security Settings
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Custom Settings
SUPABASE_WEBHOOK_SECRET = env('SUPABASE_WEBHOOK_SECRET', default='')
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10MB