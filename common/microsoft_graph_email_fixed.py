"""
Complete Microsoft Graph email provider with proper permission handling.
Windows-safe version without special Unicode characters.
Save this as: common/microsoft_graph_email_fixed.py
"""

import logging
import requests
from typing import Dict, Any, Optional
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)


class MicrosoftGraphEmailProvider:
    """Complete Microsoft Graph API email provider."""
    
    def __init__(self, tenant_id: str = None, client_id: str = None, 
                 client_secret: str = None, sender_email: str = None):
        self.tenant_id = tenant_id or settings.MICROSOFT_TENANT_ID
        self.client_id = client_id or settings.MICROSOFT_CLIENT_ID
        self.client_secret = client_secret or settings.MICROSOFT_CLIENT_SECRET
        self.sender_email = sender_email or settings.MICROSOFT_SENDER_EMAIL
        
        # Validate configuration
        self._validate_config()
        
        # Setup session
        self.session = requests.Session()
        
        # Graph API endpoints
        self.token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        self.send_mail_url = f"https://graph.microsoft.com/v1.0/users/{self.sender_email}/sendMail"
    
    def _validate_config(self):
        """Validate required configuration."""
        if not all([self.tenant_id, self.client_id, self.client_secret, self.sender_email]):
            missing = []
            if not self.tenant_id:
                missing.append("MICROSOFT_TENANT_ID")
            if not self.client_id:
                missing.append("MICROSOFT_CLIENT_ID")
            if not self.client_secret:
                missing.append("MICROSOFT_CLIENT_SECRET")
            if not self.sender_email:
                missing.append("MICROSOFT_SENDER_EMAIL")
            
            raise ValueError(f"Missing required configuration: {', '.join(missing)}")
    
    def _get_access_token(self) -> str:
        """Get or refresh Microsoft Graph access token."""
        # Check cache first
        cache_key = f"msgraph_token_{self.tenant_id}_{self.client_id}"
        cached_token = cache.get(cache_key)
        
        if cached_token:
            logger.debug("Using cached Microsoft Graph token")
            return cached_token
        
        logger.info("Acquiring new Microsoft Graph token")
        
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://graph.microsoft.com/.default',
            'grant_type': 'client_credentials'
        }
        
        try:
            response = self.session.post(self.token_url, data=data, timeout=10)
            response.raise_for_status()
            
            token_data = response.json()
            access_token = token_data['access_token']
            expires_in = token_data.get('expires_in', 3600)
            
            # Cache token
            cache_timeout = max(expires_in - 300, 60)
            cache.set(cache_key, access_token, cache_timeout)
            
            logger.info("Microsoft Graph token acquired successfully")
            return access_token
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to acquire Microsoft Graph token: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response: {e.response.text}")
            raise Exception(f"Token acquisition failed: {str(e)}")
    
    def send_email(self, to_email: str, subject: str, html_content: str, 
                   importance: str = "normal", headers: Dict[str, str] = None) -> bool:
        """
        Send email using Microsoft Graph API.
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML body content
            importance: Email importance (low, normal, high)
            headers: Additional email headers
            
        Returns:
            True if email sent successfully
        """
        try:
            token = self._get_access_token()
            
            # Build message
            message = {
                "message": {
                    "subject": subject,
                    "body": {
                        "contentType": "HTML",
                        "content": html_content
                    },
                    "toRecipients": [
                        {
                            "emailAddress": {
                                "address": to_email
                            }
                        }
                    ],
                    "importance": importance
                },
                "saveToSentItems": "false"
            }
            
            # Add custom headers
            if headers:
                message["message"]["internetMessageHeaders"] = [
                    {"name": key, "value": value}
                    for key, value in headers.items()
                ]
            
            # Send email
            request_headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            response = self.session.post(
                self.send_mail_url,
                json=message,
                headers=request_headers,
                timeout=30
            )
            
            if response.status_code == 202:
                logger.info(f"Email sent successfully to {to_email}")
                return True
            else:
                logger.error(f"Failed to send email. Status: {response.status_code}")
                logger.error(f"Response: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending email to {to_email}: {str(e)}")
            return False
    
    def send_otp(self, email: str, otp_code: str, otp_type: str, 
                 metadata: Dict[str, Any] = None) -> bool:
        """
        Send OTP email with beautiful templates.
        
        Args:
            email: Recipient email
            otp_code: 6-digit OTP code
            otp_type: Type of OTP (registration, password_reset, login, email_verification)
            metadata: Additional template variables (e.g., user name)
            
        Returns:
            True if sent successfully
        """
        try:
            # Get user name from metadata
            user_name = metadata.get('name', 'User') if metadata else 'User'
            
            # Build email content based on OTP type
            otp_messages = {
                'registration': {
                    'subject': 'Verify Your Pefoma Account',
                    'title': 'Welcome to Pefoma!',
                    'message': 'Thank you for signing up. Please use the code below to verify your email address.'
                },
                'password_reset': {
                    'subject': 'Reset Your Pefoma Password',
                    'title': 'Password Reset Request',
                    'message': 'You requested to reset your password. Use the code below to proceed.'
                },
                'login': {
                    'subject': 'Your Pefoma Login Code',
                    'title': 'Login Verification',
                    'message': 'Use this code to complete your login.'
                },
                'email_verification': {
                    'subject': 'Verify Your Email Address',
                    'title': 'Email Verification',
                    'message': 'Please verify your email address using the code below.'
                }
            }
            
            otp_config = otp_messages.get(otp_type, otp_messages['registration'])
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body {{
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        margin: 0;
                        padding: 0;
                        background-color: #f5f5f5;
                    }}
                    .container {{
                        max-width: 600px;
                        margin: 20px auto;
                        background: white;
                        border-radius: 10px;
                        overflow: hidden;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    }}
                    .header {{
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        color: white;
                        padding: 40px 30px;
                        text-align: center;
                    }}
                    .header h1 {{
                        margin: 0;
                        font-size: 28px;
                        font-weight: 600;
                    }}
                    .content {{
                        padding: 40px 30px;
                    }}
                    .greeting {{
                        font-size: 18px;
                        color: #333;
                        margin-bottom: 20px;
                    }}
                    .message {{
                        color: #666;
                        margin-bottom: 30px;
                        font-size: 16px;
                        line-height: 1.8;
                    }}
                    .otp-container {{
                        background: linear-gradient(135deg, rgba(102, 126, 234, 0.08) 0%, rgba(118, 75, 162, 0.08) 100%);
                        border: 2px solid rgba(102, 126, 234, 0.3);
                        border-radius: 12px;
                        padding: 30px;
                        text-align: center;
                        margin: 30px 0;
                    }}
                    .otp-label {{
                        color: #666;
                        font-size: 12px;
                        text-transform: uppercase;
                        letter-spacing: 1.5px;
                        margin-bottom: 15px;
                        font-weight: 600;
                    }}
                    .otp-code {{
                        font-size: 42px;
                        font-weight: bold;
                        letter-spacing: 8px;
                        color: #667eea;
                        font-family: 'Courier New', Monaco, monospace;
                        margin: 10px 0;
                    }}
                    .otp-expiry {{
                        color: #999;
                        font-size: 14px;
                        margin-top: 15px;
                    }}
                    .security-note {{
                        background: #fff3cd;
                        border: 1px solid #ffc107;
                        border-radius: 8px;
                        padding: 15px;
                        margin: 20px 0;
                        font-size: 14px;
                        color: #856404;
                    }}
                    .footer {{
                        text-align: center;
                        color: #999;
                        font-size: 12px;
                        padding: 30px;
                        background: #f8f9fa;
                    }}
                    .footer p {{
                        margin: 5px 0;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>{otp_config['title']}</h1>
                    </div>
                    <div class="content">
                        <p class="greeting">Hi {user_name},</p>
                        <p class="message">{otp_config['message']}</p>
                        
                        <div class="otp-container">
                            <div class="otp-label">YOUR VERIFICATION CODE</div>
                            <div class="otp-code">{otp_code}</div>
                            <p class="otp-expiry">This code expires in 10 minutes</p>
                        </div>
                        
                        <div class="security-note">
                            <strong>Security Notice:</strong> Never share this code with anyone. 
                            Pefoma staff will never ask for your verification code.
                        </div>
                        
                        <p style="color: #666; font-size: 14px;">
                            If you didn't request this code, you can safely ignore this email. 
                            Your account security is not at risk.
                        </p>
                    </div>
                    <div class="footer">
                        <p>&copy; 2025 Pefoma. All rights reserved.</p>
                        <p>AI-Powered Inventory Management Platform</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Add tracking headers
            email_headers = {
                "X-Pefoma-Email-Type": otp_type,
                "X-Pefoma-OTP": "true"
            }
            
            return self.send_email(
                to_email=email,
                subject=otp_config['subject'],
                html_content=html_content,
                importance="high",
                headers=email_headers
            )
            
        except Exception as e:
            logger.error(f"Error sending OTP email: {str(e)}")
            return False
    
    def test_connection(self) -> bool:
        """Test Microsoft Graph API connection."""
        try:
            token = self._get_access_token()
            
            if not token:
                logger.error("No token obtained")
                return False
            
            logger.info("Token obtained successfully, testing API access...")
            
            test_message = {
                "message": {
                    "subject": "Connection Test",
                    "body": {
                        "contentType": "Text",
                        "content": "Testing Microsoft Graph API connection"
                    },
                    "toRecipients": [
                        {
                            "emailAddress": {
                                "address": self.sender_email
                            }
                        }
                    ]
                },
                "saveToSentItems": "false"
            }
            
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            response = self.session.post(
                self.send_mail_url,
                json=test_message,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 202:
                logger.info("[SUCCESS] Microsoft Graph API connection test successful")
                return True
            elif response.status_code == 403:
                logger.error("Permission denied. Please ensure Mail.Send permission is granted.")
                logger.error(f"Response: {response.text}")
                return False
            else:
                logger.error(f"Unexpected response: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Connection test error: {str(e)}")
            return False
    
    def diagnose_permissions(self) -> Dict[str, Any]:
        """Diagnose permission issues with detailed feedback."""
        results = {
            'token_acquisition': False,
            'mail_send': False,
            'errors': [],
            'recommendations': []
        }
        
        # Test 1: Token Acquisition
        try:
            token = self._get_access_token()
            if token:
                results['token_acquisition'] = True
                logger.info("[SUCCESS] Token acquisition successful")
            else:
                results['errors'].append("Failed to acquire token")
                results['recommendations'].append("Check client ID and secret")
        except Exception as e:
            results['errors'].append(f"Token error: {str(e)}")
            results['recommendations'].append("Verify tenant ID, client ID, and client secret")
            return results
        
        # Test 2: Mail.Send Permission
        try:
            test_message = {
                "message": {
                    "subject": "Permission Test",
                    "body": {
                        "contentType": "Text",
                        "content": "Testing permissions"
                    },
                    "toRecipients": [
                        {
                            "emailAddress": {
                                "address": self.sender_email
                            }
                        }
                    ]
                },
                "saveToSentItems": "false"
            }
            
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            response = self.session.post(
                self.send_mail_url,
                json=test_message,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 202:
                results['mail_send'] = True
                logger.info("[SUCCESS] Mail.Send permission verified")
            elif response.status_code == 403:
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('message', 'Unknown error')
                results['errors'].append(f"Mail.Send permission denied: {error_msg}")
                results['recommendations'].append(
                    "1. Go to Azure Portal -> Your App -> API permissions\n"
                    "2. Ensure 'Mail.Send' (Application) is listed\n"
                    "3. Click 'Grant admin consent'\n"
                    "4. Wait 5-10 minutes for permissions to propagate"
                )
            else:
                results['errors'].append(f"Unexpected response: {response.status_code}")
                
        except Exception as e:
            results['errors'].append(f"Mail.Send test error: {str(e)}")
        
        return results