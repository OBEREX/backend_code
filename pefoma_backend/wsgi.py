# File: pefoma_backend/wsgi.py

import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pefoma_backend.settings')

application = get_wsgi_application()