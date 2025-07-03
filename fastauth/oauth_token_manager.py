import base64
import hashlib
import secrets
import ssl
import time
from dataclasses import dataclass
from typing import Optional, Dict, Any

import aiohttp
import certifi
from loguru import logger as log


@dataclass
class AccessToken:
    """OAuth access token with metadata"""
    access_token: str
    token_type: str
    expires_in: int
    scope: str
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    issued_at: float = None

    def __post_init__(self):
        if self.issued_at is None:
            self.issued_at = time.time()

    @property
    def expires_at(self) -> float:
        return self.issued_at + self.expires_in

    @property
    def is_expired(self) -> bool:
        return time.time() >= (self.expires_at - 300)  # 5 min buffer

    @property
    def authorization_header(self) -> str:
        return f"{self.token_type} {self.access_token}"


@dataclass
class PKCEChallenge:
    """PKCE challenge for secure OAuth flow"""
    code_verifier: str
    code_challenge: str
    code_challenge_method: str = "S256"

    @classmethod
    def generate(cls) -> "PKCEChallenge":
        """Generate new PKCE challenge"""
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        challenge_bytes = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')

        return cls(
            code_verifier=code_verifier,
            code_challenge=code_challenge
        )


# noinspection PyUnusedLocal
class MultiTenantTokenManager:
    """Manages OAuth tokens for multi-tenant scenarios"""

    def __init__(self, client_id: str, redirect_uri: str = "http://localhost:8080/callback"):
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.token_endpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        self._pkce_challenges: Dict[str, PKCEChallenge] = {}

    def create_pkce_challenge(self, state: str) -> PKCEChallenge:
        """Create and store PKCE challenge"""
        challenge = PKCEChallenge.generate()
        self._pkce_challenges[state] = challenge
        return challenge

    def consume_pkce_challenge(self, state: str) -> Optional[PKCEChallenge]:
        """Get and remove PKCE challenge (one-time use)"""
        return self._pkce_challenges.pop(state, None)

    async def exchange_code_for_token(self, auth_code: str, scopes: str, pkce_verifier: str) -> AccessToken:
        """Exchange authorization code for access token"""
        data = {
            'client_id': self.client_id,
            'scope': scopes,
            'code': auth_code,
            'redirect_uri': self.redirect_uri,
            'grant_type': 'authorization_code',
            'code_verifier': pkce_verifier
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                    self.token_endpoint,
                    data=data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    log.error(f"Token exchange failed: {response.status} - {error_text}")
                    raise RuntimeError(f"Token exchange failed: {response.status}")

                token_data = await response.json()
                return AccessToken(
                    access_token=token_data['access_token'],
                    token_type=token_data.get('token_type', 'Bearer'),
                    expires_in=token_data['expires_in'],
                    scope=token_data.get('scope', scopes),
                    refresh_token=token_data.get('refresh_token'),
                    id_token=token_data.get('id_token')
                )

    async def refresh_token(self, refresh_token: str, scopes: str) -> AccessToken:
        """Refresh access token"""
        data = {
            'client_id': self.client_id,
            'scope': scopes,
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token'
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                    self.token_endpoint,
                    data=data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    log.error(f"Token refresh failed: {response.status}")
                    raise RuntimeError(f"Token refresh failed: {response.status}")

                token_data = await response.json()
                return AccessToken(
                    access_token=token_data['access_token'],
                    token_type=token_data.get('token_type', 'Bearer'),
                    expires_in=token_data['expires_in'],
                    scope=token_data.get('scope', scopes),
                    refresh_token=token_data.get('refresh_token', refresh_token),
                    id_token=token_data.get('id_token')
                )


class TokenStorage:
    """In-memory token storage"""

    def __init__(self):
        self._tokens: Dict[str, AccessToken] = {}

    async def store_token(self, key: str, token: AccessToken):
        self._tokens[key] = token
        log.info(f"Stored token for: {key}")

    async def get_token(self, key: str) -> Optional[AccessToken]:
        return self._tokens.get(key)

    async def remove_token(self, key: str):
        if key in self._tokens:
            del self._tokens[key]
            log.info(f"Removed token for: {key}")


class GraphAPI:
    """Microsoft Graph API via HTTP only, pure async"""

    BASE_URL = "https://graph.microsoft.com/v1.0"

    def __init__(self):
        # build a context using certifi CA bundle
        self.ssl_ctx = ssl.create_default_context(cafile=certifi.where())

    async def call(self, token: str, endpoint: str, method: str = "GET", data=None, params=None) -> dict:
        url = f"{self.BASE_URL}{endpoint}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        }
        async with aiohttp.ClientSession() as session:
            async with session.request(
                    method, url, headers=headers, json=data, params=params, ssl=self.ssl_ctx
            ) as resp:
                try:
                    return await resp.json()
                except Exception as e:
                    text = await resp.text()
                    return {"error": str(e), "body": text}

    async def get_user_profile(self, token: str) -> dict:
        return await self.call(token, "/me")

    async def get_user_emails(self, token: str, count: int = 10) -> dict:
        return await self.call(token, "/me/messages", params={"$top": count})

    async def get_user_files(self, token: str, count: int = 10) -> dict:
        return await self.call(token, "/me/drive/root/children", params={"$top": count})


class ManagedOAuthClient:
    """High-level OAuth client with automatic token management"""

    def __init__(self, token_manager: MultiTenantTokenManager, token_storage: TokenStorage, graph_api: GraphAPI):
        self.token_manager = token_manager
        self.token_storage = token_storage
        self.graph_api = graph_api
        self._current_token: Optional[AccessToken] = None

    async def authenticate_with_code(self, auth_code: str, scopes: str, pkce_verifier: str) -> AccessToken:
        """Complete OAuth flow"""
        token = await self.token_manager.exchange_code_for_token(auth_code, scopes, pkce_verifier)

        await self.token_storage.store_token("current", token)
        self._current_token = token

        log.success(f"Authentication successful! Token expires in {token.expires_in}s")
        return token

    async def get_valid_token(self) -> Optional[AccessToken]:
        """Get valid token, refresh if needed"""
        if not self._current_token:
            self._current_token = await self.token_storage.get_token("current")

        if not self._current_token:
            return None

        if self._current_token.is_expired and self._current_token.refresh_token:
            try:
                refreshed = await self.token_manager.refresh_token(
                    self._current_token.refresh_token,
                    self._current_token.scope
                )
                await self.token_storage.store_token("current", refreshed)
                self._current_token = refreshed
                log.info("Token refreshed successfully")
            except Exception as e:
                log.error(f"Token refresh failed: {e}")
                return None

        return self._current_token if not self._current_token.is_expired else None

    async def get_user_data(self, data_type: str = "profile") -> Dict[str, Any]:
        """Get user data via Azure CLI Graph API"""
        token = await self.get_valid_token()
        if not token:
            return {"error": "No valid token available"}

        try:
            if data_type == "profile":
                return await self.graph_api.get_user_profile(token.access_token)
            elif data_type == "emails":
                return await self.graph_api.get_user_emails(token.access_token)
            elif data_type == "files":
                return await self.graph_api.get_user_files(token.access_token)
            else:
                return await self.graph_api.call(token.access_token, f"/{data_type}")
        except Exception as e:
            log.error(f"Graph API call failed: {e}")
            return {"error": str(e)}

    async def logout(self):
        """Clear stored tokens"""
        await self.token_storage.remove_token("current")
        self._current_token = None
        log.info("Logged out successfully")
