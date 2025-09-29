"""
Fixed Microsoft Graph email provider with proper permission handling.
"""

import logging
import requests
from typing import Dict, Any, Optional
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)


class MicrosoftGraphEmailProvider:
    """Fixed Microsoft Graph API email provider."""
    
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
            
            logger.info(f"Microsoft Graph token acquired successfully")
            return access_token
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to acquire Microsoft Graph token: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response: {e.response.text}")
            raise Exception(f"Token acquisition failed: {str(e)}")
    
    def test_connection(self) -> bool:
        """
        Test Microsoft Graph API connection using a minimal API call.
        This only requires the token to be valid, not specific permissions.
        """
        try:
            # Get token first
            token = self._get_access_token()
            
            if not token:
                logger.error("No token obtained")
                return False
            
            logger.info("Token obtained successfully, testing API access...")
            
            # Test with a simple API call that doesn't require special permissions
            # Using /me endpoint won't work for application permissions
            # Instead, we'll validate the token format and try a minimal operation
            
            # Option 1: Try to send an email to self (requires Mail.Send only)
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
                logger.info("Microsoft Graph API connection test successful - Mail.Send permission verified")
                return True
            elif response.status_code == 403:
                logger.error(f"Permission denied. Please ensure Mail.Send permission is granted with admin consent.")
                logger.error(f"Response: {response.text}")
                return False
            else:
                logger.error(f"Unexpected response: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Connection test error: {str(e)}")
            return False
    
    def diagnose_permissions(self) -> Dict[str, Any]:
        """
        Diagnose permission issues with detailed feedback.
        """
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
                logger.info("Token acquisition successful")
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
                logger.info("Mail.Send permission verified")
            elif response.status_code == 403:
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('message', 'Unknown error')
                results['errors'].append(f"Mail.Send permission denied: {error_msg}")
                results['recommendations'].append(
                    "1. Go to Azure Portal → Your App → API permissions\n"
                    "2. Ensure 'Mail.Send' (Application) is listed\n"
                    "3. Click 'Grant admin consent'\n"
                    "4. Wait 5-10 minutes for permissions to propagate"
                )
            else:
                results['errors'].append(f"Unexpected response: {response.status_code}")
                
        except Exception as e:
            results['errors'].append(f"Mail.Send test error: {str(e)}")
        
        return results


# Quick diagnostic script
def diagnose_microsoft_graph_setup():
    """
    Run a complete diagnostic of your Microsoft Graph setup.
    """
    print("\n" + "="*60)
    print("MICROSOFT GRAPH API DIAGNOSTIC")
    print("="*60 + "\n")
    
    # Check environment variables
    print("1. Checking Configuration...")
    print("-" * 40)
    
    from django.conf import settings
    
    config_items = [
        ('MICROSOFT_TENANT_ID', settings.MICROSOFT_TENANT_ID if hasattr(settings, 'MICROSOFT_TENANT_ID') else None),
        ('MICROSOFT_CLIENT_ID', settings.MICROSOFT_CLIENT_ID if hasattr(settings, 'MICROSOFT_CLIENT_ID') else None),
        ('MICROSOFT_CLIENT_SECRET', 'SET' if hasattr(settings, 'MICROSOFT_CLIENT_SECRET') and settings.MICROSOFT_CLIENT_SECRET else 'NOT SET'),
        ('MICROSOFT_SENDER_EMAIL', settings.MICROSOFT_SENDER_EMAIL if hasattr(settings, 'MICROSOFT_SENDER_EMAIL') else None),
    ]
    
    all_configured = True
    for name, value in config_items:
        if value:
            print(f" {name}: {value}")
        else:
            print(f" {name}: NOT CONFIGURED")
            all_configured = False
    
    if not all_configured:
        print("\n❌ Configuration incomplete. Please set all required environment variables.")
        return
    
    print("\n2. Testing API Connection...")
    print("-" * 40)
    
    try:
        provider = MicrosoftGraphEmailProvider()
        results = provider.diagnose_permissions()
        
        if results['token_acquisition']:
            print("Token acquisition: SUCCESS")
        else:
            print("Token acquisition: FAILED")
        
        if results['mail_send']:
            print("Mail.Send permission: VERIFIED")
        else:
            print("Mail.Send permission: NOT WORKING")
        
        if results['errors']:
            print("\n⚠️ Errors found:")
            for error in results['errors']:
                print(f"  - {error}")
        
        if results['recommendations']:
            print("\n💡 Recommendations:")
            for rec in results['recommendations']:
                print(f"  {rec}")
        
        if results['token_acquisition'] and results['mail_send']:
            print("\n✅ Microsoft Graph API is properly configured and ready to use!")
        else:
            print("\n❌ Please fix the issues above before proceeding.")
            
    except Exception as e:
        print(f"\n❌ Diagnostic failed: {str(e)}")


# Run this in Django shell
"""
from common.microsoft_graph_email_fixed import diagnose_microsoft_graph_setup
diagnose_microsoft_graph_setup()
"""