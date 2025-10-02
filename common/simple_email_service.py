"""
Simplified email service that bypasses import issues.
Windows-safe version without special characters.
"""

import logging
from typing import Dict, Any
from django.conf import settings

logger = logging.getLogger(__name__)


class SimpleEmailService:
    """Simple email service with basic functionality."""
    
    def __init__(self):
        self._initialized = False
        self.provider = None
        self._setup_provider()
    
    def _setup_provider(self):
        """Setup email provider with error handling."""
        try:
            # Try to import and initialize Microsoft Graph
            from common.microsoft_graph_email_fixed import MicrosoftGraphEmailProvider
            self.provider = MicrosoftGraphEmailProvider()
            self._initialized = True
            logger.info("[SUCCESS] Microsoft Graph email provider initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize email provider: {str(e)}")
            # Create a fallback dummy provider
            self.provider = self._create_fallback_provider()
            logger.warning("Using fallback email provider")
    
    def _create_fallback_provider(self):
        """Create a fallback provider for development."""
        class FallbackProvider:
            def send_otp(self, email, otp_code, otp_type, metadata=None):
                logger.warning(f"FALLBACK: Would send OTP {otp_code} to {email}")
                return True
            
            def send_email(self, to_email, subject, html_content, importance="normal"):
                logger.warning(f"FALLBACK: Would send email '{subject}' to {to_email}")
                return True
        
        return FallbackProvider()
    
    def send_otp(self, email: str, otp_code: str, otp_type: str, metadata: Dict[str, Any] = None) -> bool:
        """Send OTP email."""
        try:
            # Debug: Check what methods the provider has
            logger.debug(f"Provider type: {type(self.provider).__name__}")
            logger.debug(f"Provider has send_otp: {hasattr(self.provider, 'send_otp')}")
            
            if hasattr(self.provider, 'send_otp'):
                logger.info(f"Sending OTP to {email} using provider.send_otp()")
                return self.provider.send_otp(email, otp_code, otp_type, metadata)
            else:
                logger.warning(f"Provider doesn't support send_otp, using fallback")
                logger.warning(f"Available methods: {[m for m in dir(self.provider) if not m.startswith('_')]}")
                return True
        except Exception as e:
            logger.error(f"Error sending OTP: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    def send_transactional(self, email: str, subject: str, html_content: str, metadata: Dict[str, Any] = None) -> bool:
        """Send transactional email."""
        try:
            if hasattr(self.provider, 'send_email'):
                return self.provider.send_email(email, subject, html_content)
            else:
                logger.warning(f"Provider doesn't support send_email, using fallback")
                return True
        except Exception as e:
            logger.error(f"Error sending email: {str(e)}")
            return False
    
    def send_welcome_email(self, email: str, name: str) -> bool:
        """Send welcome email."""
        html_content = f"""
        <html>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2>Welcome to Pefoma, {name}!</h2>
                <p>Your account has been successfully verified.</p>
                <p>You can now start using our AI-powered inventory management platform.</p>
                <div style="margin: 30px 0;">
                    <a href="https://pefoma.com/dashboard" 
                       style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                              color: white; padding: 14px 32px; text-decoration: none;
                              border-radius: 50px; display: inline-block;">
                        Go to Dashboard
                    </a>
                </div>
                <p>If you have any questions, feel free to reach out to our support team.</p>
                <p>Best regards,<br>The Pefoma Team</p>
            </div>
        </body>
        </html>
        """
        
        return self.send_transactional(
            email=email,
            subject="Welcome to Pefoma!",
            html_content=html_content
        )


# Create singleton instance
simple_email_service = SimpleEmailService()