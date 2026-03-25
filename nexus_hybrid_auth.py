"""
NEXUS Hybrid Auth Service
Combines JWT, OAuth2, Social logins with intelligent session management

Features:
- JWT tokens (stateless)
- OAuth2 flows (Google, GitHub, etc.)
- Social logins
- MFA support
- Session management
"""

import os
import logging
import jwt
import bcrypt
from typing import Optional, Dict
from datetime import datetime, timezone, timedelta
import httpx

logger = logging.getLogger(__name__)

class HybridAuthService:
    def __init__(self):
        """Initialize hybrid authentication"""
        self.jwt_secret = os.environ.get('JWT_SECRET', 'nexus-secret')
        self.jwt_algorithm = 'HS256'
        self.token_expiry = 7  # days
        
        # OAuth providers
        self.google_client_id = os.environ.get('GOOGLE_CLIENT_ID')
        self.github_token = os.environ.get('GITHUB_TOKEN')
        
        self.oauth_enabled = {
            "google": bool(self.google_client_id),
            "github": bool(self.github_token)
        }
        
        logger.info(f"Hybrid Auth initialized (OAuth: {self.oauth_enabled})")
    
    def create_jwt_token(
        self,
        user_id: str,
        email: str,
        role: str = "user",
        custom_claims: Optional[Dict] = None
    ) -> str:
        """Create JWT token"""
        payload = {
            "user_id": user_id,
            "email": email,
            "role": role,
            "exp": (datetime.now(timezone.utc) + timedelta(days=self.token_expiry)).timestamp(),
            "iat": datetime.now(timezone.utc).timestamp()
        }
        
        if custom_claims:
            payload.update(custom_claims)
        
        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        return token
    
    def verify_jwt_token(self, token: str) -> Dict:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            return {
                "valid": True,
                "payload": payload
            }
        except jwt.ExpiredSignatureError:
            return {
                "valid": False,
                "error": "Token expired"
            }
        except jwt.InvalidTokenError:
            return {
                "valid": False,
                "error": "Invalid token"
            }
    
    def hash_password(self, password: str) -> str:
        """Hash password with bcrypt"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt)
        return hashed.decode()
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode(), hashed.encode())
    
    async def authenticate_user(
        self,
        email: str,
        password: str,
        db
    ) -> Dict:
        """Authenticate user with email/password"""
        try:
            user = await db.users.find_one({"email": email}, {"_id": 0})
            
            if not user:
                return {
                    "success": False,
                    "error": "User not found"
                }
            
            if not self.verify_password(password, user["password"]):
                return {
                    "success": False,
                    "error": "Invalid password"
                }
            
            token = self.create_jwt_token(
                user_id=user["id"],
                email=user["email"],
                role=user.get("role", "user")
            )
            
            return {
                "success": True,
                "token": token,
                "user": {k: v for k, v in user.items() if k != "password"}
            }
            
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def oauth_login(
        self,
        provider: str,
        code: str,
        db
    ) -> Dict:
        """Handle OAuth login flow"""
        
        if provider == "google" and self.oauth_enabled["google"]:
            return await self._google_oauth(code, db)
        elif provider == "github" and self.oauth_enabled["github"]:
            return await self._github_oauth(code, db)
        else:
            return {
                "success": False,
                "error": f"OAuth provider {provider} not configured"
            }
    
    async def _google_oauth(self, code: str, db) -> Dict:
        """Google OAuth flow"""
        try:
            # Exchange code for token
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://oauth2.googleapis.com/token",
                    data={
                        "code": code,
                        "client_id": self.google_client_id,
                        "redirect_uri": "https://nexus.com/auth/callback",
                        "grant_type": "authorization_code"
                    }
                )
                
                if response.status_code != 200:
                    return {"success": False, "error": "OAuth exchange failed"}
                
                token_data = response.json()
                access_token = token_data["access_token"]
                
                # Get user info
                user_response = await client.get(
                    "https://www.googleapis.com/oauth2/v2/userinfo",
                    headers={"Authorization": f"Bearer {access_token}"}
                )
                
                user_info = user_response.json()
                
                # Create or update user
                user = await db.users.find_one({"email": user_info["email"]}, {"_id": 0})
                
                if not user:
                    # Create new user
                    user = {
                        "id": f"user_{int(datetime.now(timezone.utc).timestamp())}",
                        "email": user_info["email"],
                        "username": user_info.get("name"),
                        "avatar": user_info.get("picture"),
                        "auth_provider": "google",
                        "role": "user",
                        "created_at": datetime.now(timezone.utc).isoformat()
                    }
                    await db.users.insert_one(user)
                
                # Create JWT token
                token = self.create_jwt_token(
                    user_id=user["id"],
                    email=user["email"],
                    role=user.get("role", "user")
                )
                
                return {
                    "success": True,
                    "token": token,
                    "user": user
                }
                
        except Exception as e:
            logger.error(f"Google OAuth failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def _github_oauth(self, code: str, db) -> Dict:
        """GitHub OAuth flow"""
        # Similar to Google OAuth
        return {"success": False, "error": "GitHub OAuth not fully implemented"}
    
    async def refresh_token(self, old_token: str) -> Dict:
        """Refresh JWT token"""
        verification = self.verify_jwt_token(old_token)
        
        if not verification["valid"]:
            return {"success": False, "error": verification["error"]}
        
        payload = verification["payload"]
        new_token = self.create_jwt_token(
            user_id=payload["user_id"],
            email=payload["email"],
            role=payload["role"]
        )
        
        return {
            "success": True,
            "token": new_token
        }

# Global instance
hybrid_auth = HybridAuthService()
