# test_app.py - Complete OAuth test setup
import asyncio
import threading
import time
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
import uvicorn
import httpx

from fastauth.core import AuthServer
from fastauth.server import add_oauth

# Test Application (your actual app)
test_app = FastAPI()
add_oauth(test_app)  # 🎉 ONE LINE!

@test_app.get("/")
async def home():
    return HTMLResponse("""
    <html>
    <body style="font-family: Arial; margin: 40px;">
        <h1>🚀 Test Application</h1>
        <p>This app uses OAuth middleware!</p>
        <ul>
            <li><a href="/dashboard">Dashboard (requires auth)</a></li>
            <li><a href="/profile">Profile (requires auth)</a></li>
            <li><a href="/public">Public page</a></li>
        </ul>
    </body>
    </html>
    """)

@test_app.get("/dashboard")
async def dashboard(request: Request):
    """Protected dashboard - requires OAuth"""
    user = getattr(request.state, 'user', None)
    if not user:
        raise HTTPException(302, headers={"Location": "http://localhost:8080/"})

    return HTMLResponse(f"""
    <html>
    <body style="font-family: Arial; margin: 40px;">
        <h1>📊 Dashboard</h1>
        <p>Welcome, {user['name']}!</p>
        <ul>
            <li><strong>Email:</strong> {user['email']}</li>
        </ul>
        <p><a href="/profile">View Profile</a> | <a href="/logout">Logout</a></p>
    </body>
    </html>
    """)

@test_app.get("/profile")
async def profile(request: Request):
    """Protected profile - requires OAuth"""
    user = getattr(request.state, 'user', None)
    if not user:
        raise HTTPException(302, headers={"Location": "http://localhost:8080/"})

    return {"user": user}

@test_app.get("/public")
async def public_page(request: Request):
    """Public page - shows user if authenticated"""
    user = getattr(request.state, 'user', None)

    if user:
        message = f"Hello {user['name']}, you're logged in!"
    else:
        message = "Hello anonymous user! <a href='/dashboard'>Login</a>"

    return HTMLResponse(f"""
    <html>
    <body style="font-family: Arial; margin: 40px;">
        <h1>🌍 Public Page</h1>
        <p>{message}</p>
        <p><a href="/">Home</a></p>
    </body>
    </html>
    """)

@test_app.get("/logout")
async def logout():
    """Logout - clear session"""
    response = HTMLResponse("""
    <html>
    <body style="font-family: Arial; margin: 40px;">
        <h1>👋 Logged Out</h1>
        <p>You have been logged out successfully.</p>
        <p><a href="/">Home</a></p>
    </body>
    </html>
    """)
    response.delete_cookie("session")
    return response

# Server management
class ThreadedServer:
    def __init__(self, app, host="localhost", port=8080):
        self.app = app
        self.host = host
        self.port = port
        self.server_thread = None

    def start(self):
        """Start server in background thread"""
        def run_server():
            uvicorn.run(self.app, host=self.host, port=self.port, log_level="warning")

        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        time.sleep(2)  # Give server time to start
        print(f"🚀 Server started: http://{self.host}:{self.port}")

async def main():
    """Run both OAuth server and test app"""
    print("🔧 Starting OAuth Test Environment...")

    # Start OAuth server on port 8080
    oauth_server = await AuthServer.__async_init__(Path.cwd())
    await oauth_server.start()

    # Start test app on port 8081
    test_server = ThreadedServer(test_app, port=8081)
    test_server.start()

    print("\n" + "="*50)
    print("🎉 OAuth Test Environment Ready!")
    print("="*50)
    print("OAuth Server: http://localhost:8080")
    print("Test App:     http://localhost:8081")
    print("\n🧪 Test Flow:")
    print("1. Visit: http://localhost:8081")
    print("2. Click 'Dashboard' -> redirects to OAuth")
    print("3. Click 'Login as John Doe' -> sets session")
    print("4. Gets redirected back -> shows user data")
    print("5. Visit other protected routes!")
    print("\nPress Ctrl+C to stop servers")
    print("="*50)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n👋 Shutting down servers...")

if __name__ == "__main__":
    asyncio.run(main())

# Alternative: Run just the test app if OAuth server is already running
def run_test_app_only():
    """Run just the test app (OAuth server must be running on 8080)"""
    print("🚀 Starting test app on http://localhost:8081")
    print("Make sure OAuth server is running on http://localhost:8080")
    uvicorn.run(test_app, host="localhost", port=8081)

# Uncomment to run test app only:
# if __name__ == "__main__":
#     run_test_app_only()