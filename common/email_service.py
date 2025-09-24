# common/email_service.py
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from django.conf import settings
from django.template.loader import render_to_string
import logging

logger = logging.getLogger(__name__)


class BaseEmailProvider(ABC):
    """Abstract base class for email providers."""
    
    @abstractmethod
    def send_otp(self, email: str, otp_code: str, otp_type: str, metadata: Dict[str, Any] = None) -> bool:
        """Send OTP via email."""
        pass
    
    @abstractmethod
    def send_transactional(self, email: str, template_id: str, template_data: Dict[str, Any]) -> bool:
        """Send transactional email."""
        pass


class SupabaseEmailProvider(BaseEmailProvider):
    """Supabase built-in email service provider."""
    
    def __init__(self, supabase_client):
        self.client = supabase_client
    
    def send_otp(self, email: str, otp_code: str, otp_type: str, metadata: Dict[str, Any] = None) -> bool:
        """
        Send OTP using Supabase's email service.
        Note: This sends the OTP code, not a magic link.
        """
        try:
            # Map OTP types to email templates
            template_mapping = {
                'registration': 'confirmation',
                'password_reset': 'recovery',
                'email_verification': 'email_change',
                'login': 'magic_link'  # Can be used for OTP login
            }
            
            template_type = template_mapping.get(otp_type, 'confirmation')
            
            # Prepare email data with OTP code
            email_data = {
                'email': email,
                'type': template_type,
                'token': otp_code,  # Pass OTP as token
                'data': {
                    'otp_code': otp_code,
                    'expires_in': '10 minutes',
                    'app_name': 'Pefoma',
                    **(metadata or {})
                }
            }
            
            # Use Supabase admin API to trigger email
            # This assumes you have a custom email template in Supabase that displays the OTP
            response = self.client.auth.admin.send_email(email_data)
            
            logger.info(f"Supabase OTP email sent to {email} - Type: {otp_type}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Supabase OTP email: {str(e)}")
            return False
    
    def send_transactional(self, email: str, template_id: str, template_data: Dict[str, Any]) -> bool:
        """Send transactional email via Supabase."""
        try:
            response = self.client.auth.admin.send_email({
                'email': email,
                'template_id': template_id,
                'data': template_data
            })
            return True
        except Exception as e:
            logger.error(f"Failed to send Supabase transactional email: {str(e)}")
            return False


class SendGridEmailProvider(BaseEmailProvider):
    """SendGrid email service provider (future implementation)."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        # Initialize SendGrid client when needed
        # from sendgrid import SendGridAPIClient
        # self.client = SendGridAPIClient(api_key)
    
    def send_otp(self, email: str, otp_code: str, otp_type: str, metadata: Dict[str, Any] = None) -> bool:
        """Send OTP via SendGrid."""
        try:
            # Future implementation
            from sendgrid import SendGridAPIClient
            from sendgrid.helpers.mail import Mail
            
            sg = SendGridAPIClient(self.api_key)
            
            # Get template based on type
            templates = {
                'registration': 'd-xxxxx',  # Your SendGrid template IDs
                'password_reset': 'd-yyyyy',
                'email_verification': 'd-zzzzz',
            }
            
            message = Mail(
                from_email=settings.DEFAULT_FROM_EMAIL,
                to_emails=email,
                subject=f'Your Pefoma {otp_type.replace("_", " ").title()} Code'
            )
            
            message.template_id = templates.get(otp_type)
            message.dynamic_template_data = {
                'otp_code': otp_code,
                'expires_in': '10 minutes',
                **(metadata or {})
            }
            
            response = sg.send(message)
            logger.info(f"SendGrid OTP email sent to {email}")
            return response.status_code == 202
            
        except Exception as e:
            logger.error(f"Failed to send SendGrid OTP email: {str(e)}")
            return False
    
    def send_transactional(self, email: str, template_id: str, template_data: Dict[str, Any]) -> bool:
        """Send transactional email via SendGrid."""
        # Implementation similar to send_otp
        pass


class AWSEmailProvider(BaseEmailProvider):
    """AWS SES email service provider (future implementation)."""
    
    def __init__(self, aws_access_key: str, aws_secret_key: str, region: str = 'us-east-1'):
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.region = region
        # Initialize boto3 client when needed
    
    def send_otp(self, email: str, otp_code: str, otp_type: str, metadata: Dict[str, Any] = None) -> bool:
        """Send OTP via AWS SES."""
        try:
            import boto3
            
            ses = boto3.client(
                'ses',
                region_name=self.region,
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_secret_key
            )
            
            # Render HTML template
            html_body = self._render_otp_template(otp_type, otp_code, metadata)
            
            response = ses.send_email(
                Source=settings.DEFAULT_FROM_EMAIL,
                Destination={'ToAddresses': [email]},
                Message={
                    'Subject': {'Data': f'Your Pefoma Verification Code'},
                    'Body': {
                        'Html': {'Data': html_body},
                        'Text': {'Data': f'Your verification code is: {otp_code}'}
                    }
                }
            )
            
            logger.info(f"AWS SES OTP email sent to {email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send AWS SES OTP email: {str(e)}")
            return False
    
    def send_transactional(self, email: str, template_id: str, template_data: Dict[str, Any]) -> bool:
        """Send transactional email via AWS SES."""
        # Implementation here
        pass
    
    def _render_otp_template(self, otp_type: str, otp_code: str, metadata: Dict[str, Any] = None) -> str:
        """Render OTP email template."""
        templates = {
            'registration': '''
                <html>
                <body style="font-family: Arial, sans-serif;">
                    <h2>Welcome to Pefoma!</h2>
                    <p>Your verification code is:</p>
                    <h1 style="color: #2563eb; letter-spacing: 8px;">{otp_code}</h1>
                    <p>This code expires in {expires_in}.</p>
                </body>
                </html>
            ''',
            'password_reset': '''
                <html>
                <body style="font-family: Arial, sans-serif;">
                    <h2>Password Reset Request</h2>
                    <p>Your password reset code is:</p>
                    <h1 style="color: #dc2626; letter-spacing: 8px;">{otp_code}</h1>
                    <p>This code expires in {expires_in}.</p>
                </body>
                </html>
            '''
        }
        
        template = templates.get(otp_type, templates['registration'])
        return template.format(
            otp_code=otp_code,
            expires_in=metadata.get('expires_in', '10 minutes')
        )


class EmailService:
    """
    Main email service that switches between providers.
    This is the facade that the rest of the application uses.
    """
    
    def __init__(self):
        self.provider = self._get_provider()
    
    def _get_provider(self) -> BaseEmailProvider:
        """
        Get email provider based on settings.
        This allows runtime switching between providers.
        """
        provider_type = getattr(settings, 'EMAIL_PROVIDER', 'supabase')
        
        if provider_type == 'supabase':
            from auth_integration.supabase_client import SupabaseClient
            return SupabaseEmailProvider(SupabaseClient())
        
        elif provider_type == 'sendgrid':
            api_key = getattr(settings, 'SENDGRID_API_KEY', '')
            if not api_key:
                raise ValueError("SendGrid API key not configured")
            return SendGridEmailProvider(api_key)
        
        elif provider_type == 'aws':
            return AWSEmailProvider(
                aws_access_key=settings.AWS_ACCESS_KEY_ID,
                aws_secret_key=settings.AWS_SECRET_ACCESS_KEY,
                region=getattr(settings, 'AWS_SES_REGION', 'us-east-1')
            )
        
        else:
            raise ValueError(f"Unknown email provider: {provider_type}")
    
    def send_otp(self, email: str, otp_code: str, otp_type: str, metadata: Dict[str, Any] = None) -> bool:
        """
        Send OTP email using configured provider.
        
        Args:
            email: Recipient email
            otp_code: The 6-digit OTP code
            otp_type: Type of OTP (registration, password_reset, etc.)
            metadata: Additional data for the email template
        """
        return self.provider.send_otp(email, otp_code, otp_type, metadata)
    
    def send_transactional(self, email: str, template_id: str, template_data: Dict[str, Any]) -> bool:
        """Send transactional email using configured provider."""
        return self.provider.send_transactional(email, template_id, template_data)
    
    def switch_provider(self, provider_type: str):
        """
        Switch email provider at runtime (useful for testing or fallback).
        
        Args:
            provider_type: 'supabase', 'sendgrid', or 'aws'
        """
        settings.EMAIL_PROVIDER = provider_type
        self.provider = self._get_provider()
        logger.info(f"Switched email provider to: {provider_type}")


# Singleton instance
email_service = EmailService()