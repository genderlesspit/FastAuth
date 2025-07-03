import asyncio
import time
from pathlib import Path
from typing import Optional

from async_property import AwaitLoader, async_cached_property
from loguru import logger as log
from pyzurecli import AzureCLI, AzureCLIAppRegistration

from fastauth.server import AuthCallbackServer, ServerManager, AuthUrlBuilder, user_cache
from oauth_token_manager import (
    MultiTenantTokenManager,
    TokenStorage,
    ManagedOAuthClient,
    AccessToken,
    GraphAPI
)


class AuthServer(AwaitLoader):
    """Multi-tenant OAuth authentication server"""

    _instance = None
    _oauth_client = None

    def __init__(self, path: Path):
        self.path = path

    def __repr__(self):
        return f"[{self.path.name.title()}.AuthServer]"

    @classmethod
    async def __async_init__(cls, path: Path):
        if not cls._instance:
            cls._instance = cls(path)
        return cls._instance

    @async_cached_property
    async def azure_cli(self) -> AzureCLI:
        return await AzureCLI.__async_init__(self.path)

    @async_cached_property
    async def app_registration(self) -> AzureCLIAppRegistration:
        azure_cli = await self.azure_cli
        return await azure_cli.app_registration

    @async_cached_property
    async def client_id(self) -> str:
        app_registration = await self.app_registration
        return await app_registration.client_id

    @async_cached_property
    async def oauth_client(self) -> ManagedOAuthClient:
        """Create multi-tenant OAuth client - shared instance"""
        if not AuthServer._oauth_client:
            client_id = await self.client_id
            azure_cli = await self.azure_cli

            token_manager = MultiTenantTokenManager(client_id)
            token_storage = TokenStorage()
            graph_api = GraphAPI()

            AuthServer._oauth_client = ManagedOAuthClient(token_manager, token_storage, graph_api)
            log.debug(f"[{self}]: ✅ Created OAuth client instance")

        return AuthServer._oauth_client

    @async_cached_property
    async def auth_url_builder(self) -> AuthUrlBuilder:
        client_id = await self.client_id
        return AuthUrlBuilder(client_id)

    @async_cached_property
    async def server_manager(self) -> ServerManager:
        """Create server manager"""
        callback_app = AuthCallbackServer(self)
        return ServerManager(callback_app)

    async def start(self):
        """Start the multi-tenant authentication server"""
        server_manager = await self.server_manager
        client_id = await self.client_id

        server_manager.start()
        log.debug(f"[{self}]: 🔐 Multi-tenant OAuth server started")
        log.debug(f"[{self}]: 🆔 Client ID: {client_id}")
        log.debug(f"[{self}]: 🎯 Scopes: User.Read, Mail.Read, Files.Read")
        log.debug(f"[{self}]: 🛡️ Security: PKCE + Multi-Tenant")
        log.debug(f"[{self}]: 🌐 Admin Consent: http://localhost:8080/admin-consent")
        log.debug(f"[{self}]: 🔧 Debug: http://localhost:8080/debug")

    async def stop(self):
        """Stop the authentication server"""
        server_manager = await self.server_manager
        server_manager.stop()

    async def get_current_token(self) -> Optional[AccessToken]:
        """Get current valid access token"""
        oauth_client = await self.oauth_client
        return await oauth_client.get_valid_token()

    async def get_user_data_via_cli(self, data_type: str = "profile"):
        """Get user data via Azure CLI Graph API"""
        oauth_client = await self.oauth_client
        return await oauth_client.get_user_data(data_type)

    async def generate_admin_consent_url(self) -> str:
        """Generate admin consent URL for cross-tenant permissions"""
        app_registration = await self.app_registration
        return await app_registration.generate_admin_consent_url()

    # Legacy compatibility
    async def launch_as_thread(self):
        await self.start()

    async def stop_server(self):
        await self.stop()


async def debug():
    server = await AuthServer.__async_init__(Path.cwd())
    await server.start()
    result = await user_cache.get_user("my_debug_token")

if __name__ == "__main__":
    asyncio.run(debug())
    time.sleep(500)
