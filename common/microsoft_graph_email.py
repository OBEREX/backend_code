"""
Production-ready Microsoft Graph API email provider for Pefoma.
Handles OTP emails, transactional emails, and bulk sending with proper error handling.
"""

import logging
import json
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from django.conf import settings
from django.core.cache import cache
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

logger = logging.getLogger(__name__)


class MicrosoftGraphEmailProvider:
    """
    Microsoft Graph API email provider with advanced features:
    - Token caching and automatic refresh
    - Retry logic for transient failures
    - Batch sending support
    - Rich HTML templates
    - Delivery tracking
    """
    
    def __init__(self, tenant_id: str = None, client_id: str = None, 
                 client_secret: str = None, sender_email: str = None):
        """
        Initialize Microsoft Graph email provider.
        
        Args:
            tenant_id: Azure AD tenant ID
            client_id: Application (client) ID
            client_secret: Client secret
            sender_email: Sender email address
        """
        self.tenant_id = tenant_id or settings.MICROSOFT_TENANT_ID
        self.client_id = client_id or settings.MICROSOFT_CLIENT_ID
        self.client_secret = client_secret or settings.MICROSOFT_CLIENT_SECRET
        self.sender_email = sender_email or settings.MICROSOFT_SENDER_EMAIL
        
        # Validate configuration
        self._validate_config()
        
        # Setup session with retry logic
        self.session = self._create_session()
        
        # Graph API endpoints
        self.token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        self.send_mail_url = f"https://graph.microsoft.com/v1.0/users/{self.sender_email}/sendMail"
        self.batch_url = "https://graph.microsoft.com/v1.0/$batch"
    
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
            
            raise ValueError(f"Missing required Microsoft Graph configuration: {', '.join(missing)}")
    
    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry logic."""
        session = requests.Session()
        
        # Configure retries for transient failures
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        
        return session
    
    def _get_access_token(self) -> str:
        """
        Get or refresh Microsoft Graph access token with caching.
        
        Returns:
            Access token string
            
        Raises:
            Exception: If token acquisition fails
        """
        # Check cache first
        cache_key = f"msgraph_token_{self.tenant_id}_{self.client_id}"
        cached_token = cache.get(cache_key)
        
        if cached_token:
            logger.debug("Using cached Microsoft Graph token")
            return cached_token
        
        # Request new token
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
            
            # Cache token with safety margin (expire 5 minutes early)
            cache_timeout = max(expires_in - 300, 60)
            cache.set(cache_key, access_token, cache_timeout)
            
            logger.info(f"Microsoft Graph token acquired, cached for {cache_timeout} seconds")
            return access_token
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to acquire Microsoft Graph token: {str(e)}")
            raise Exception(f"Token acquisition failed: {str(e)}")
    
    def send_email(self, to_email: str, subject: str, html_content: str, 
                   text_content: str = None, importance: str = "normal",
                   attachments: List[Dict] = None, headers: Dict = None) -> bool:
        """
        Send an email via Microsoft Graph API.
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML body content
            text_content: Plain text content (optional)
            importance: Email importance (low, normal, high)
            attachments: List of attachment dictionaries
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
                }
            }
            
            # Add plain text alternative if provided
            if text_content:
                message["message"]["body"] = {
                    "contentType": "HTML",
                    "content": html_content
                }
                # Note: Graph API doesn't support multipart directly
                # HTML content takes precedence
            
            # Add attachments if provided
            if attachments:
                message["message"]["attachments"] = attachments
            
            # Add custom headers
            if headers:
                message["message"]["internetMessageHeaders"] = [
                    {"name": key, "value": value}
                    for key, value in headers.items()
                ]
            
            # Send email
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            response = self.session.post(
                self.send_mail_url,
                json=message,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 202:  # Accepted
                logger.info(f"Email sent successfully to {to_email}")
                return True
            else:
                logger.error(f"Failed to send email. Status: {response.status_code}, Response: {response.text}")
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
            metadata: Additional template variables
            
        Returns:
            True if sent successfully
        """
        # Get template
        subject, html_content, importance = self._get_otp_template(
            otp_type, otp_code, metadata
        )
        
        # Add tracking headers
        headers = {
            "X-Pefoma-Email-Type": otp_type,
            "X-Pefoma-OTP": "true",
            "X-Pefoma-User-Email": email
        }
        
        # Send email
        return self.send_email(
            to_email=email,
            subject=subject,
            html_content=html_content,
            importance=importance,
            headers=headers
        )
    
    def send_bulk_emails(self, recipients: List[Dict[str, Any]], 
                        template_type: str = "notification") -> Dict[str, Any]:
        """
        Send bulk emails using Graph API batch requests.
        
        Args:
            recipients: List of recipient dictionaries with email, name, and custom data
            template_type: Type of template to use
            
        Returns:
            Dictionary with success count and failed emails
        """
        try:
            token = self._get_access_token()
            
            # Create batch requests (Graph API limits to 20 per batch)
            batch_size = 20
            results = {"success": 0, "failed": [], "total": len(recipients)}
            
            for i in range(0, len(recipients), batch_size):
                batch = recipients[i:i + batch_size]
                batch_requests = []
                
                for idx, recipient in enumerate(batch):
                    # Create individual request
                    subject, html_content, _ = self._get_bulk_template(
                        template_type, recipient
                    )
                    
                    request = {
                        "id": str(idx + 1),
                        "method": "POST",
                        "url": f"/users/{self.sender_email}/sendMail",
                        "body": {
                            "message": {
                                "subject": subject,
                                "body": {
                                    "contentType": "HTML",
                                    "content": html_content
                                },
                                "toRecipients": [
                                    {
                                        "emailAddress": {
                                            "address": recipient['email']
                                        }
                                    }
                                ]
                            }
                        },
                        "headers": {
                            "Content-Type": "application/json"
                        }
                    }
                    batch_requests.append(request)
                
                # Send batch request
                headers = {
                    'Authorization': f'Bearer {token}',
                    'Content-Type': 'application/json'
                }
                
                batch_response = self.session.post(
                    self.batch_url,
                    json={"requests": batch_requests},
                    headers=headers,
                    timeout=60
                )
                
                if batch_response.status_code == 200:
                    batch_results = batch_response.json()
                    
                    for response in batch_results.get("responses", []):
                        idx = int(response["id"]) - 1
                        recipient_email = batch[idx]['email']
                        
                        if response["status"] == 202:
                            results["success"] += 1
                        else:
                            results["failed"].append({
                                "email": recipient_email,
                                "error": response.get("body", {}).get("error", "Unknown error")
                            })
            
            logger.info(f"Bulk email results: {results}")
            return results
            
        except Exception as e:
            logger.error(f"Bulk email sending failed: {str(e)}")
            return {"success": 0, "failed": recipients, "error": str(e)}
    
    def _get_otp_template(self, otp_type: str, otp_code: str, 
                         metadata: Dict[str, Any] = None) -> tuple:
        """
        Get OTP email template with modern design.
        
        Returns:
            Tuple of (subject, html_content, importance)
        """
        templates = {
            'registration': {
                'subject': '🎉 Welcome to Pefoma - Verify Your Account',
                'importance': 'normal',
                'html': '''
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <style>
                        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                        body {{ 
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                            line-height: 1.6;
                            color: #333;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        }}
                        .container {{ 
                            max-width: 600px; 
                            margin: 40px auto; 
                            background: white;
                            border-radius: 16px;
                            overflow: hidden;
                            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                        }}
                        .header {{ 
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            padding: 40px;
                            text-align: center;
                        }}
                        .header h1 {{ 
                            color: white;
                            font-size: 28px;
                            font-weight: 600;
                            margin: 0;
                        }}
                        .header p {{
                            color: rgba(255,255,255,0.9);
                            margin-top: 10px;
                            font-size: 16px;
                        }}
                        .content {{ 
                            padding: 40px;
                        }}
                        .greeting {{
                            font-size: 20px;
                            color: #333;
                            margin-bottom: 20px;
                        }}
                        .message {{
                            color: #666;
                            margin-bottom: 30px;
                            font-size: 16px;
                        }}
                        .otp-container {{
                            background: linear-gradient(135deg, #667eea15 0%, #764ba215 100%);
                            border: 2px solid #667eea30;
                            border-radius: 12px;
                            padding: 30px;
                            text-align: center;
                            margin: 30px 0;
                        }}
                        .otp-label {{
                            color: #666;
                            font-size: 14px;
                            text-transform: uppercase;
                            letter-spacing: 1px;
                            margin-bottom: 15px;
                        }}
                        .otp-code {{
                            font-size: 40px;
                            font-weight: bold;
                            letter-spacing: 12px;
                            color: #667eea;
                            font-family: 'Courier New', monospace;
                        }}
                        .otp-expiry {{
                            color: #999;
                            font-size: 14px;
                            margin-top: 15px;
                        }}
                        .instructions {{
                            background: #f8f9fa;
                            border-left: 4px solid #667eea;
                            padding: 20px;
                            margin: 30px 0;
                            border-radius: 4px;
                        }}
                        .instructions h3 {{
                            color: #333;
                            margin-bottom: 10px;
                            font-size: 16px;
                        }}
                        .instructions ol {{
                            margin-left: 20px;
                            color: #666;
                        }}
                        .instructions li {{
                            margin: 8px 0;
                        }}
                        .button {{
                            display: inline-block;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            color: white;
                            padding: 14px 32px;
                            text-decoration: none;
                            border-radius: 50px;
                            font-weight: 600;
                            margin: 20px 0;
                            font-size: 16px;
                        }}
                        .security-note {{
                            background: #fff3cd;
                            border: 1px solid #ffc107;
                            padding: 15px;
                            border-radius: 8px;
                            margin: 20px 0;
                            font-size: 14px;
                            color: #856404;
                        }}
                        .footer {{
                            background: #f8f9fa;
                            padding: 30px;
                            text-align: center;
                            color: #666;
                            font-size: 14px;
                        }}
                        .footer a {{
                            color: #667eea;
                            text-decoration: none;
                        }}
                        .social-links {{
                            margin: 20px 0;
                        }}
                        .social-links a {{
                            display: inline-block;
                            margin: 0 10px;
                        }}
                        @media (max-width: 600px) {{
                            .container {{ margin: 0; border-radius: 0; }}
                            .content {{ padding: 20px; }}
                            .otp-code {{ font-size: 32px; letter-spacing: 8px; }}
                        }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>Welcome to Pefoma!</h1>
                            <p>Your AI-Powered Inventory Management Solution</p>
                        </div>
                        <div class="content">
                            <div class="greeting">
                                Hello{name}! 👋
                            </div>
                            <div class="message">
                                Thank you for joining Pefoma. We're excited to help you streamline your inventory management 
                                with our AI-powered platform. To get started, please verify your email address.
                            </div>
                            
                            <div class="otp-container">
                                <div class="otp-label">Your Verification Code</div>
                                <div class="otp-code">{otp_code}</div>
                                <div class="otp-expiry">⏱️ Expires in 10 minutes</div>
                            </div>
                            
                            <div class="instructions">
                                <h3>How to verify your account:</h3>
                                <ol>
                                    <li>Return to the Pefoma signup page</li>
                                    <li>Enter the 6-digit code above</li>
                                    <li>Click "Verify" to complete your registration</li>
                                </ol>
                            </div>
                            
                            <div class="security-note">
                                🔒 <strong>Security Notice:</strong> Never share this code with anyone. 
                                Pefoma staff will never ask for your verification code.
                            </div>
                            
                            <p style="color: #999; margin-top: 30px;">
                                If you didn't create an account with Pefoma, please ignore this email or 
                                contact our support team if you have concerns.
                            </p>
                        </div>
                        <div class="footer">
                            <p><strong>Pefoma</strong> - Smart Inventory, Simplified</p>
                            <p style="margin-top: 10px;">
                                <a href="https://pefoma.com/help">Help Center</a> • 
                                <a href="https://pefoma.com/privacy">Privacy Policy</a> • 
                                <a href="https://pefoma.com/terms">Terms of Service</a>
                            </p>
                            <p style="margin-top: 20px; color: #999;">
                                © 2024 Pefoma. All rights reserved.<br>
                                Lagos, Nigeria
                            </p>
                        </div>
                    </div>
                </body>
                </html>
                '''
            },
            'password_reset': {
                'subject': '🔐 Pefoma - Password Reset Code',
                'importance': 'high',
                'html': '''
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <style>
                        /* Similar styles as above but with red/orange theme for urgency */
                        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                        body {{ 
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                        }}
                        .container {{ 
                            max-width: 600px; 
                            margin: 40px auto; 
                            background: white;
                            border-radius: 16px;
                            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                        }}
                        .header {{ 
                            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                            padding: 40px;
                            text-align: center;
                        }}
                        .header h1 {{ 
                            color: white;
                            font-size: 28px;
                        }}
                        .content {{ padding: 40px; }}
                        .otp-container {{
                            background: #fff3cd;
                            border: 2px solid #ffc107;
                            border-radius: 12px;
                            padding: 30px;
                            text-align: center;
                            margin: 30px 0;
                        }}
                        .otp-code {{
                            font-size: 40px;
                            font-weight: bold;
                            letter-spacing: 12px;
                            color: #f5576c;
                            font-family: 'Courier New', monospace;
                        }}
                        .warning {{
                            background: #f8d7da;
                            border: 1px solid #f5c6cb;
                            color: #721c24;
                            padding: 15px;
                            border-radius: 8px;
                            margin: 20px 0;
                        }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>Password Reset Request</h1>
                        </div>
                        <div class="content">
                            <p style="font-size: 18px; margin-bottom: 20px;">
                                Hello{name},
                            </p>
                            <p style="color: #666; margin-bottom: 30px;">
                                We received a request to reset your Pefoma account password. 
                                Use the code below to complete the process:
                            </p>
                            
                            <div class="otp-container">
                                <div style="color: #856404; margin-bottom: 15px;">Password Reset Code</div>
                                <div class="otp-code">{otp_code}</div>
                                <div style="color: #856404; margin-top: 15px;">⏱️ Expires in 10 minutes</div>
                            </div>
                            
                            <div class="warning">
                                ⚠️ <strong>Important:</strong> If you didn't request this password reset, 
                                please ignore this email and ensure your account is secure. Consider changing 
                                your password if you suspect unauthorized access.
                            </div>
                            
                            <p style="color: #999; margin-top: 30px;">
                                For security reasons, this code will expire in 10 minutes. 
                                If you need a new code, please request another password reset.
                            </p>
                        </div>
                    </div>
                </body>
                </html>
                '''
            }
        }
        
        template = templates.get(otp_type, templates['registration'])
        
        # Format template with variables
        name = f", {metadata.get('name')}" if metadata and metadata.get('name') else ""
        html = template['html'].format(
            otp_code=otp_code,
            name=name,
            **metadata if metadata else {}
        )
        
        return template['subject'], html, template['importance']
    
    def _get_bulk_template(self, template_type: str, recipient: Dict[str, Any]) -> tuple:
        """Get template for bulk emails."""
        # Implement bulk email templates here
        subject = f"Pefoma Update for {recipient.get('name', 'User')}"
        html = f"<p>Hello {recipient.get('name', 'User')},</p><p>This is a bulk email.</p>"
        importance = "normal"
        
        return subject, html, importance
    
    def test_connection(self) -> bool:
        """
        Test Microsoft Graph API connection and permissions.
        
        Returns:
            True if connection successful and permissions are valid
        """
        try:
            token = self._get_access_token()
            
            # Test by getting user profile
            test_url = f"https://graph.microsoft.com/v1.0/users/{self.sender_email}"
            headers = {'Authorization': f'Bearer {token}'}
            
            response = self.session.get(test_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                logger.info("Microsoft Graph API connection test successful")
                return True
            else:
                logger.error(f"Connection test failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Connection test error: {str(e)}")
            return False


# Integration with existing email service
class MicrosoftGraphEmailAdapter:
    """Adapter to integrate with existing email service interface."""
    
    def __init__(self):
        try:
            from common.microsoft_graph_email_fixed import MicrosoftGraphEmailProvider
            self.provider = MicrosoftGraphEmailProvider()
            logger.info("Initialized Microsoft Graph email provider (fixed version)")
        except ImportError:
            logger.error("Could not import any Microsoft Graph email provider")
            raise ImportError("Microsoft Graph email provider not available")

    
    def send_otp(self, email: str, otp_code: str, otp_type: str, 
                 metadata: Dict[str, Any] = None) -> bool:
        """Send OTP email."""
        return self.provider.send_otp(email, otp_code, otp_type, metadata)
    
    def send_transactional(self, email: str, template_id: str, 
                          template_data: Dict[str, Any]) -> bool:
        """Send transactional email."""
        # Map template IDs to actual templates
        subject = template_data.get('subject', 'Pefoma Notification')
        html_content = template_data.get('html_content', '')
        
        return self.provider.send_email(
            to_email=email,
            subject=subject,
            html_content=html_content
        )