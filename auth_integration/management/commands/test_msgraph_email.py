"""
Django management command to test Microsoft Graph email configuration.

Usage:
    python manage.py test_msgraph_email --test-all
    python manage.py test_msgraph_email --test-connection
    python manage.py test_msgraph_email --send-otp your@email.com
"""

from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from common.microsoft_graph_email_fixed import MicrosoftGraphEmailProvider
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Test Microsoft Graph email configuration'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--test-all',
            action='store_true',
            help='Run all tests'
        )
        parser.add_argument(
            '--test-connection',
            action='store_true',
            help='Test API connection only'
        )
        parser.add_argument(
            '--send-otp',
            type=str,
            help='Send test OTP to specified email'
        )
        parser.add_argument(
            '--send-bulk',
            type=str,
            help='Send bulk test emails (comma-separated emails)'
        )
        parser.add_argument(
            '--check-permissions',
            action='store_true',
            help='Check API permissions'
        )
    
    def handle(self, *args, **options):
        self.stdout.write(self.style.MIGRATE_HEADING('\n' + '='*60))
        self.stdout.write(self.style.MIGRATE_HEADING('MICROSOFT GRAPH EMAIL CONFIGURATION TEST'))
        self.stdout.write(self.style.MIGRATE_HEADING('='*60 + '\n'))
        
        # Initialize provider
        try:
            provider = MicrosoftGraphEmailProvider()
            self.stdout.write(self.style.SUCCESS('Provider initialized successfully'))
        except ValueError as e:
            self.stdout.write(self.style.ERROR(f'Configuration Error: {str(e)}'))
            self.print_configuration_help()
            return
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Initialization Error: {str(e)}'))
            return
        
        # Run tests based on options
        if options['test_all']:
            self.test_connection(provider)
            self.check_permissions(provider)
            self.test_token_acquisition(provider)
            self.test_send_email(provider)
            
        elif options['test_connection']:
            self.test_connection(provider)
            
        elif options['send_otp']:
            self.test_send_otp(provider, options['send_otp'])
            
        elif options['send_bulk']:
            emails = options['send_bulk'].split(',')
            self.test_bulk_send(provider, emails)
            
        elif options['check_permissions']:
            self.check_permissions(provider)
            
        else:
            self.test_connection(provider)
            self.check_permissions(provider)
    
    def test_connection(self, provider):
        """Test basic API connection."""
        self.stdout.write('\n' + self.style.MIGRATE_LABEL('Testing API Connection...'))
        
        try:
            if provider.test_connection():
                self.stdout.write(self.style.SUCCESS('API connection successful'))
                self.stdout.write(f'  Tenant ID: {provider.tenant_id}')
                self.stdout.write(f'  Client ID: {provider.client_id}')
                self.stdout.write(f'  Sender: {provider.sender_email}')
            else:
                self.stdout.write(self.style.ERROR('API connection failed'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Connection test error: {str(e)}'))
    
    def test_token_acquisition(self, provider):
        """Test OAuth token acquisition."""
        self.stdout.write('\n' + self.style.MIGRATE_LABEL('Testing Token Acquisition...'))
        
        try:
            token = provider._get_access_token()
            if token:
                self.stdout.write(self.style.SUCCESS('Token acquired successfully'))
                self.stdout.write(f'  Token length: {len(token)} characters')
                self.stdout.write(f'  Token preview: {token[:20]}...')
            else:
                self.stdout.write(self.style.ERROR('Failed to acquire token'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Token acquisition error: {str(e)}'))
    
    def check_permissions(self, provider):
        """Check Microsoft Graph API permissions."""
        self.stdout.write('\n' + self.style.MIGRATE_LABEL('Checking API Permissions...'))
        
        try:
            import requests
            
            token = provider._get_access_token()
            
            # Check current permissions
            headers = {'Authorization': f'Bearer {token}'}
            
            # Test Mail.Send permission
            test_message = {
                "message": {
                    "subject": "Permission Test - Delete This",
                    "body": {
                        "contentType": "Text",
                        "content": "This is a permission test email."
                    },
                    "toRecipients": [
                        {
                            "emailAddress": {
                                "address": provider.sender_email
                            }
                        }
                    ]
                },
                "saveToSentItems": "false"
            }
            
            response = requests.post(
                provider.send_mail_url,
                json=test_message,
                headers=headers
            )
            
            if response.status_code == 202:
                self.stdout.write(self.style.SUCCESS('Mail.Send permission verified'))
            elif response.status_code == 403:
                self.stdout.write(self.style.ERROR('✗ Mail.Send permission missing'))
                self.stdout.write(self.style.WARNING('  Please grant admin consent in Azure AD'))
            else:
                self.stdout.write(self.style.WARNING(f'⚠ Unexpected response: {response.status_code}'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Permission check error: {str(e)}'))
    
    def test_send_email(self, provider):
        """Test sending a simple email."""
        self.stdout.write('\n' + self.style.MIGRATE_LABEL('Testing Email Send...'))
        
        test_email = settings.MICROSOFT_TEST_EMAIL or provider.sender_email
        
        try:
            success = provider.send_email(
                to_email=test_email,
                subject=f"Pefoma Test Email - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                html_content="""
                <html>
                <body>
                    <h2>Test Email from Pefoma</h2>
                    <p>This is a test email to verify Microsoft Graph API integration.</p>
                    <p><strong>Configuration:</strong></p>
                    <ul>
                        <li>Provider: Microsoft Graph API</li>
                        <li>Timestamp: {timestamp}</li>
                        <li>Environment: {environment}</li>
                    </ul>
                </body>
                </html>
                """.format(
                    timestamp=datetime.now().isoformat(),
                    environment='DEBUG' if settings.DEBUG else 'PRODUCTION'
                )
            )
            
            if success:
                self.stdout.write(self.style.SUCCESS(f'Test email sent to {test_email}'))
            else:
                self.stdout.write(self.style.ERROR(f'Failed to send test email'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Email send error: {str(e)}'))
    
    def test_send_otp(self, provider, email):
        """Test sending an OTP email."""
        self.stdout.write('\n' + self.style.MIGRATE_LABEL(f'Sending OTP to {email}...'))
        
        try:
            # Test registration OTP
            success = provider.send_otp(
                email=email,
                otp_code='123456',
                otp_type='registration',
                metadata={'name': 'Test User'}
            )
            
            if success:
                self.stdout.write(self.style.SUCCESS(f'Registration OTP sent to {email}'))
            else:
                self.stdout.write(self.style.ERROR('Failed to send registration OTP'))
            
            # Test password reset OTP
            success = provider.send_otp(
                email=email,
                otp_code='654321',
                otp_type='password_reset',
                metadata={'name': 'Test User'}
            )
            
            if success:
                self.stdout.write(self.style.SUCCESS(f'Password reset OTP sent to {email}'))
            else:
                self.stdout.write(self.style.ERROR('Failed to send password reset OTP'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'OTP send error: {str(e)}'))
    
    def test_bulk_send(self, provider, emails):
        """Test bulk email sending."""
        self.stdout.write('\n' + self.style.MIGRATE_LABEL(f'Sending bulk emails to {len(emails)} recipients...'))
        
        recipients = [
            {'email': email.strip(), 'name': f'User {i+1}'}
            for i, email in enumerate(emails)
        ]
        
        try:
            results = provider.send_bulk_emails(recipients)
            
            self.stdout.write(f"\nBulk Send Results:")
            self.stdout.write(f"  Total: {results['total']}")
            self.stdout.write(self.style.SUCCESS(f"Success: {results['success']}"))
            
            if results['failed']:
                self.stdout.write(self.style.ERROR(f"  ✗ Failed: {len(results['failed'])}"))
                for failed in results['failed']:
                    self.stdout.write(f"    - {failed['email']}: {failed.get('error', 'Unknown error')}")
                    
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Bulk send error: {str(e)}'))
    
    def print_configuration_help(self):
        """Print configuration help."""
        self.stdout.write('\n' + self.style.WARNING('Configuration Help:'))
        self.stdout.write('\n1. Ensure these environment variables are set in .env:')
        self.stdout.write('   MICROSOFT_TENANT_ID=your-tenant-id')
        self.stdout.write('   MICROSOFT_CLIENT_ID=your-client-id')
        self.stdout.write('   MICROSOFT_CLIENT_SECRET=your-secret')
        self.stdout.write('   MICROSOFT_SENDER_EMAIL=noreply@yourdomain.com')
        
        self.stdout.write('\n2. In Azure AD, ensure:')
        self.stdout.write('   - App has Mail.Send permission')
        self.stdout.write('   - Admin consent is granted')
        self.stdout.write('   - Client secret is not expired')
        
        self.stdout.write('\n3. The sender email must be:')
        self.stdout.write('   - A valid mailbox in your tenant')
        self.stdout.write('   - Licensed for Exchange Online')
