"""
NordStellar MCP auth proxy.

Performs cookie-based browser login, extracts the JWT from the AccessToken
cookie, then proxies all MCP calls to the remote Go server over StreamableHTTP
using that JWT as a Bearer token.  Re-authenticates transparently when the
token expires.

Usage:
  nordstellar-remote-mcp-proxy <remote_mcp_url>
  nordstellar-remote-mcp-proxy --logout

  Or set NORDSTELLAR_REMOTE_MCP_URL (e.g. MCPB / Claude Desktop extensions).

  uvx --from git+https://github.com/NordStellar/nordstellar-mcp \\
      nordstellar-remote-mcp-proxy https://platform-mcp.nordstellar.com/mcp

Cursor mcp.json:
  "nordstellar-graphql": {
    "command": "uvx",
    "args": [
      "--from", "git+https://github.com/NordStellar/nordstellar-mcp",
      "nordstellar-remote-mcp-proxy",
      "https://platform-mcp.nordstellar.com/mcp"
    ]
  }
"""

import argparse
import asyncio
import base64
import ipaddress
import os
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
import json
import logging
from pathlib import Path
import secrets
import signal
import sys
import threading
import time
from typing import Any, TypeVar
import urllib.parse
import webbrowser

import anyio
import httpx
from jinja2 import Environment, FileSystemLoader
import keyring
import keyring.errors
from mcp import server, types
from mcp.client.session import ClientSession
from mcp.client.streamable_http import (
    StreamableHTTPTransport,
)
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import McpError

T = TypeVar("T")

BACKEND_BASE = "https://platform-api.nordstellar.com"
_LOOPBACK_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}
_ALLOWED_SCHEMES = {"http", "https"}

_KEYRING_SERVICE = "NordStellar MCP"
_KEYRING_ACCOUNT = "session-cookies"

_PARENT_WATCHDOG_INTERVAL = 5.0
_SHUTDOWN_TIMEOUT = 10

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
_JINJA_ENV = Environment(
    loader=FileSystemLoader(_TEMPLATES_DIR),
    autoescape=True,
)

logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="[%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("nordstellar-proxy")


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nordstellar-remote-mcp-proxy",
        description=(
            "Authenticate to NordStellar and proxy a local stdio MCP session "
            "to a remote StreamableHTTP MCP server."
        ),
    )
    parser.add_argument(
        "remote_mcp_url",
        nargs="?",
        help=(
            "Remote MCP server URL. If omitted, NORDSTELLAR_REMOTE_MCP_URL is used."
        ),
    )
    parser.add_argument(
        "--logout",
        action="store_true",
        help="Clear stored NordStellar session cookies from the OS keyring and exit.",
    )
    return parser


def _count_stored_cookies(value: str) -> int | None:
    try:
        cookies = json.loads(value)
    except Exception:
        return None
    if isinstance(cookies, dict):
        return len(cookies)
    return None


def _logout() -> int:
    backend_name = type(keyring.get_keyring()).__name__
    if backend_name == "NullKeyring":
        print(
            "NordStellar: No secure keyring backend is available; nothing to clear.",
            file=sys.stderr,
        )
        return 0

    try:
        value = keyring.get_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT)
    except Exception as exc:
        print(f"NordStellar: Failed to access keyring: {exc}", file=sys.stderr)
        return 1

    if not value:
        print(
            f"NordStellar: No stored cookies found in {backend_name}.",
            file=sys.stderr,
        )
        return 0

    try:
        keyring.delete_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT)
    except keyring.errors.PasswordDeleteError as exc:
        print(f"NordStellar: Failed to clear stored cookies: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"NordStellar: Failed to clear stored cookies: {exc}", file=sys.stderr)
        return 1

    cookie_count = _count_stored_cookies(value)
    if cookie_count is None:
        print(
            f"NordStellar: Cleared stored cookies from {backend_name}.",
            file=sys.stderr,
        )
    else:
        print(
            f"NordStellar: Cleared {cookie_count} stored cookie(s) from {backend_name}.",
            file=sys.stderr,
        )
    return 0


def _validate_mcp_url(url: str) -> None:
    """
    Validate the remote MCP server URL.

    Only http and https schemes are permitted. Plain HTTP is allowed only for
    localhost and loopback IP literals (for example 127.0.0.1 or ::1)
    because sending Bearer tokens over unencrypted connections on non-loopback
    networks exposes credentials in cleartext.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as exc:
        raise SystemExit(f"Invalid MCP URL: {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise SystemExit(
            f"Invalid MCP URL scheme '{parsed.scheme}'. "
            "Only 'https' and 'http' (loopback only) are allowed."
        )

    hostname = (parsed.hostname or "").lower()
    is_loopback = hostname in _LOOPBACK_HOSTNAMES
    if not is_loopback:
        try:
            is_loopback = ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            is_loopback = False
    if scheme == "http" and not is_loopback:
        raise SystemExit(
            f"Plain HTTP is not allowed for non-loopback host '{hostname}'. "
            "Use HTTPS to protect Bearer token transmission."
        )


def _callback_uri(port: int) -> str:
    return f"http://127.0.0.1:{port}/callback"


def _oauth_state_from_auth_url(auth_url: str) -> str:
    params = urllib.parse.parse_qs(urllib.parse.urlparse(auth_url).query)
    states = params.get("state", [])
    return states[0] if states else ""


def _jwt_exp(jwt: str) -> float | None:
    """Return the exp claim of a JWT as a Unix timestamp, or None on any error."""
    try:
        payload_b64 = jwt.split(".")[1]
        # urlsafe_b64decode requires padding to be a multiple of 4
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        data = json.loads(base64.urlsafe_b64decode(payload_b64))
        return float(data["exp"])
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Persistent cookie storage (keyring with in-memory fallback)
# ---------------------------------------------------------------------------


class _CookieBackend:
    """No-op backend — in-memory only, no persistence across restarts."""

    name = "in-memory"

    def save(self, cookies: dict[str, Any]) -> None:
        pass

    def load(self) -> dict[str, Any] | None:
        return None

    def clear(self) -> None:
        pass


class _KeyringBackend(_CookieBackend):
    """
    Persists cookies via the ``keyring`` library.

    Uses the platform's native credential store:
      - macOS: Keychain (backward-compatible with previous /usr/bin/security entries)
      - Windows: Credential Locker
      - Linux: Freedesktop Secret Service (GNOME Keyring / KWallet)
    """

    def __init__(self, backend_name: str) -> None:
        self.name = backend_name

    def save(self, cookies: dict[str, Any]) -> None:
        try:
            keyring.delete_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT)
        except keyring.errors.PasswordDeleteError:
            pass
        keyring.set_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT, json.dumps(cookies))

    def load(self) -> dict[str, Any] | None:
        value = keyring.get_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT)
        if not value:
            return None
        return json.loads(value)

    def clear(self) -> None:
        try:
            keyring.delete_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT)
        except keyring.errors.PasswordDeleteError:
            pass


def _create_cookie_backend() -> _CookieBackend:
    try:
        kr = keyring.get_keyring()
        backend_name = type(kr).__name__

        # Null backend means no usable secure store is available.
        if backend_name == "NullKeyring":
            raise RuntimeError("keyring resolved to NullKeyring")

        # Smoke-test: attempt a read to verify the backend works.
        keyring.get_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT)

        return _KeyringBackend(backend_name)
    except Exception as exc:
        log.info("keyring unavailable (%s), using in-memory cookie store", exc)
        return _CookieBackend()


class CookieStore:
    """
    Safe wrapper around a platform-specific credential backend.

    Every public method catches all exceptions so that a Keychain failure
    never prevents the proxy from working — it just falls back to the
    current in-memory-only behaviour.
    """

    def __init__(self) -> None:
        self._backend = _create_cookie_backend()
        log.info("Cookie store backend: %s", self._backend.name)

    def save(self, client: httpx.AsyncClient) -> None:
        cookies: dict[str, Any] = {}
        for cookie in client.cookies.jar:
            key = f"{cookie.domain}:{cookie.path}:{cookie.name}"
            cookies[key] = {
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain,
                "path": cookie.path,
            }
        try:
            self._backend.save(cookies)
            log.info("Saved %d cookie(s) to %s", len(cookies), self._backend.name)
        except Exception as exc:
            log.warning("Cookie store save failed, falling back to in-memory: %s", exc)

    def load(self, client: httpx.AsyncClient) -> bool:
        try:
            cookies = self._backend.load()
            if not cookies:
                return False
            for data in cookies.values():
                client.cookies.set(
                    data["name"],
                    data["value"],
                    domain=data["domain"],
                    path=data["path"],
                )
            log.info("Loaded %d cookie(s) from %s", len(cookies), self._backend.name)
            return True
        except Exception as exc:
            log.warning("Cookie store load failed, falling back to in-memory: %s", exc)
            return False

    def clear(self) -> None:
        try:
            self._backend.clear()
        except Exception as exc:
            log.debug("Cookie store clear failed: %s", exc)


# ---------------------------------------------------------------------------
# Auth state
# ---------------------------------------------------------------------------


class AuthState:
    """
    Cookie-based NordStellar authentication.

    Replicates the Go auth flow from cmd/local/pkg/auth/:
      - refresh_session  → POST /auth/refresh-token
      - login_flow       → GET  /auth/initiate-login/{redirect} → browser
                           → callback → POST /auth/login
      - ensure_authenticated → refresh then login if needed
      - extract_jwt      → URL-decode AccessToken cookie, parse JSON, return Token
    """

    def __init__(self) -> None:
        # follow_redirects=True for all calls except initiate-login (overridden per-request)
        self._client = httpx.AsyncClient(follow_redirects=True, timeout=30.0)
        self._cookie_store = CookieStore()
        if self._cookie_store.load(self._client):
            log.info("Restored session from secure storage")

    def is_authenticated(self) -> bool:
        return bool(self._client.cookies.get("AccessToken"))

    async def _refresh_session(self) -> bool:
        """POST /auth/refresh-token; return True if a new AccessToken cookie was set."""
        try:
            resp = await self._client.post(
                f"{BACKEND_BASE}/auth/refresh-token",
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200 and self.is_authenticated():
                self._cookie_store.save(self._client)
                return True
            return False
        except Exception as exc:
            log.debug("Refresh request failed: %s", exc)
            return False

    async def _login_flow(self) -> None:
        """
        Full browser OAuth flow, mirroring login.go:
          1. Bind local callback server on 127.0.0.1 (random port)
          2. GET /auth/initiate-login/{encoded_redirect} (no redirects)
          3. Open Keycloak URL in the browser
          4. Receive OAuth callback (code + state)
          5. POST /auth/login to exchange the code
        """
        result_queue: asyncio.Queue[dict[str, str]] = asyncio.Queue(maxsize=1)

        async def _handle_connection(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                raw_line = await asyncio.wait_for(reader.readline(), timeout=10)
                first_line = raw_line.decode(errors="replace").rstrip("\r\n")
                # "GET /callback?code=xxx&state=yyy HTTP/1.1"
                parts = first_line.split(" ")
                params: dict[str, str] = {}
                if (
                    len(parts) >= 3
                    and parts[0] == "GET"
                    and urllib.parse.urlparse(parts[1]).path == "/callback"
                ):
                    qs = urllib.parse.urlparse(parts[1]).query
                    params = dict(urllib.parse.parse_qsl(qs))
                else:
                    writer.write(
                        b"HTTP/1.1 400 Bad Request\r\n"
                        b"Content-Type: text/plain; charset=utf-8\r\n"
                        b"Connection: close\r\n\r\n"
                        b"Bad Request"
                    )
                    await writer.drain()
                    return

                if "error" in params:
                    desc = params.get("error_description", "")
                    body = (
                        _JINJA_ENV.get_template("login-error.html")
                        .render(message=f"{params['error']}: {desc}")
                        .encode()
                    )
                    await result_queue.put({"error": params["error"]})
                else:
                    body = (
                        _JINJA_ENV.get_template("login-success.html").render().encode()
                    )
                    await result_queue.put(
                        {
                            "code": params.get("code", ""),
                            "state": params.get("state", ""),
                        }
                    )

                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/html; charset=utf-8\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        cb_server = await asyncio.start_server(
            _handle_connection, "127.0.0.1", 0
        )
        try:
            callback_port = cb_server.sockets[0].getsockname()[1]
            callback_uri = _callback_uri(callback_port)

            encoded = urllib.parse.quote(callback_uri, safe="")
            init_resp = await self._client.get(
                f"{BACKEND_BASE}/auth/initiate-login/{encoded}",
                headers={"Accept": "application/json"},
                follow_redirects=False,
            )

            if init_resp.status_code == 200:
                try:
                    auth_url = init_resp.json()["auth_url"]
                except Exception:
                    raise RuntimeError(
                        f"Unexpected initiate-login response body: {init_resp.text}"
                    )
            elif init_resp.status_code in (301, 302, 303, 307, 308):
                auth_url = init_resp.headers.get("Location", "")
                if not auth_url:
                    raise RuntimeError("initiate-login redirect had no Location header")
            else:
                raise RuntimeError(
                    f"initiate-login failed (HTTP {init_resp.status_code}): {init_resp.text}"
                )

            expected_state = _oauth_state_from_auth_url(auth_url)
            if not expected_state:
                raise RuntimeError(
                    "initiate-login response did not include OAuth state"
                )

            print("NordStellar: Opening browser for login...", file=sys.stderr)
            webbrowser.open(auth_url)

            result = await asyncio.wait_for(result_queue.get(), timeout=300)
        finally:
            cb_server.close()
            await cb_server.wait_closed()

        if "error" in result:
            raise RuntimeError(f"OAuth callback error: {result['error']}")
        if not result.get("code"):
            raise RuntimeError("OAuth callback missing authorization code")
        if not result.get("state"):
            raise RuntimeError("OAuth callback missing state")
        if not secrets.compare_digest(result["state"], expected_state):
            raise RuntimeError("OAuth callback state mismatch")

        login_resp = await self._client.post(
            f"{BACKEND_BASE}/auth/login",
            json={
                "authorization_code": result["code"],
                "state": result["state"],
                "redirect_uri": callback_uri,
            },
        )
        if login_resp.status_code != 200:
            raise RuntimeError(
                f"Code exchange failed (HTTP {login_resp.status_code}): {login_resp.text}"
            )
        self._cookie_store.save(self._client)
        print("NordStellar: Login successful.", file=sys.stderr)

    def invalidate(self) -> None:
        """Remove the AccessToken cookie so the next ensure_authenticated call is forced to refresh."""
        self._client.cookies.delete("AccessToken")

    async def ensure_authenticated(self, *, force_refresh: bool = False) -> None:
        """Refresh or run browser login, mirroring ensureAuthenticated in refresh.go."""
        if self.is_authenticated() and not force_refresh:
            try:
                jwt = self.extract_jwt()
                exp = _jwt_exp(jwt)
                if exp is not None and exp - time.time() > 0:
                    return
            except Exception:
                log.info("Could not validate stored token.")
        log.info("Attempting token refresh...")
        if await self._refresh_session():
            log.info("Token refreshed successfully.")
            return
        self.invalidate()
        log.info("Starting browser login flow...")
        await self._login_flow()

    def extract_jwt(self) -> str:
        """
        Decode the AccessToken cookie and return the raw JWT.

        The platform API sets the cookie as:
          URL-encode({"token":"<jwt>","expires_in":<n>})

        Note: graphql.go's comment describes the *reverse* direction (Go remote server
        synthesising a cookie from a Bearer token for the GraphQL backend), which uses
        PascalCase keys. The backend itself uses lowercase keys.
        """
        raw = self._client.cookies.get("AccessToken")
        if not raw:
            raise RuntimeError("AccessToken cookie not found after authentication")
        decoded = urllib.parse.unquote(raw)
        data = json.loads(decoded)
        # Backend sets lowercase "token"; accept PascalCase "Token" as fallback
        jwt = data.get("token") or data.get("Token")
        if not jwt:
            raise RuntimeError(
                f"JWT not found in AccessToken cookie. Got keys: {list(data.keys())}"
            )
        return jwt

    async def aclose(self) -> None:
        await self._client.aclose()


# ---------------------------------------------------------------------------
# Connection manager — reconnectable StreamableHTTP ↔ ClientSession
# ---------------------------------------------------------------------------


class ConnectionManager:
    """
    Manages the StreamableHTTP connection to the remote Go MCP server.

    Holds a live ClientSession and an AsyncExitStack so the connection
    can be torn down and re-established on re-authentication without
    restarting the stdio server that Cursor is connected to.
    """

    def __init__(self) -> None:
        self._session: ClientSession | None = None
        self.server_name: str = "nordstellar-graphql"
        self.capabilities: types.ServerCapabilities | None = None
        self._commands: asyncio.Queue[_ConnectionCommand] = asyncio.Queue()
        self._owner_task: asyncio.Task[None] | None = None

    @staticmethod
    def _build_http_client(jwt: str) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={"Authorization": f"Bearer {jwt}"},
            timeout=httpx.Timeout(30, read=60 * 5),
        )

    @staticmethod
    @asynccontextmanager
    async def _post_only_streamablehttp_client(
        url: str,
        jwt: str,
    ):
        """
        StreamableHTTP client variant that never opens standalone GET SSE.
        """
        read_stream_writer, read_stream = anyio.create_memory_object_stream(0)
        write_stream, write_stream_reader = anyio.create_memory_object_stream(0)
        transport = StreamableHTTPTransport(url)

        async with anyio.create_task_group() as tg:
            try:
                async with ConnectionManager._build_http_client(jwt) as client:
                    def start_get_stream() -> None:
                        # Intentionally no-op for stateless remote servers.
                        return

                    async def _guarded_post_writer() -> None:
                        try:
                            await transport.post_writer(
                                client,
                                write_stream_reader,
                                read_stream_writer,
                                write_stream,
                                start_get_stream,
                                tg,
                            )
                        finally:
                            # Eagerly close the writer so any pending
                            # read_stream.receive() unblocks with EndOfStream
                            # instead of hanging until the generator is re-entered.
                            await read_stream_writer.aclose()

                    tg.start_soon(_guarded_post_writer)

                    try:
                        yield (
                            read_stream,
                            write_stream,
                            transport.get_session_id,
                        )
                    finally:
                        # Remote server is stateless — no session to terminate.
                        # Skip the DELETE to avoid a pointless round-trip that
                        # would also fail with 401 when the JWT has expired.
                        tg.cancel_scope.cancel()
            finally:
                await read_stream_writer.aclose()
                await write_stream.aclose()

    def _open_transport(
        self,
        url: str,
        jwt: str,
    ):
        # Remote server is intentionally stateless; standalone GET SSE is unsupported.
        return self._post_only_streamablehttp_client(url, jwt)

    async def _open_connection(
        self, url: str, jwt: str
    ) -> tuple[AsyncExitStack, ClientSession, Any]:
        stack = AsyncExitStack()
        try:
            read, write, _ = await stack.enter_async_context(
                self._open_transport(url, jwt)
            )
            session = await stack.enter_async_context(ClientSession(read, write))
            init_result = await session.initialize()
        except BaseException:
            await stack.aclose()
            raise
        return stack, session, init_result

    @staticmethod
    async def _close_stack(stack: AsyncExitStack, context: str) -> None:
        try:
            await stack.aclose()
        except Exception as exc:
            raise RuntimeError(f"{context}: {exc}") from exc

    @staticmethod
    def _finish_command(
        command: "_ConnectionCommand", exc: Exception | None = None
    ) -> None:
        if command.future.done():
            return
        if exc is None:
            command.future.set_result(None)
            return
        command.future.set_exception(exc)

    async def _connection_owner(self) -> None:
        current_stack: AsyncExitStack | None = None
        try:
            while True:
                try:
                    command = await self._commands.get()
                except asyncio.CancelledError:
                    # The streamablehttp_client's internal anyio TaskGroup may
                    # cancel us when its SSE listener exits.  Exit cleanly so
                    # _ensure_owner_task can create a fresh owner on the next
                    # connect() call without logging a scary warning.
                    log.debug(
                        "Connection owner interrupted by cancel scope while idle"
                    )
                    break

                if isinstance(command, _ConnectCommand):
                    try:
                        new_stack, session, init_result = await self._open_connection(
                            command.url, command.jwt
                        )
                    except asyncio.CancelledError:
                        self._finish_command(
                            command,
                            RuntimeError(
                                "Connection cancelled by transport cancel scope"
                            ),
                        )
                        break
                    except Exception as exc:
                        self._finish_command(command, exc)
                        continue

                    old_stack = current_stack
                    current_stack = new_stack
                    self._session = session
                    self.server_name = init_result.serverInfo.name
                    self.capabilities = init_result.capabilities

                    if old_stack is not None:
                        try:
                            await self._close_stack(
                                old_stack, "close previous connection stack"
                            )
                        except Exception as exc:
                            log.warning(
                                "Connected to replacement session but cleanup failed: %s",
                                exc,
                            )

                    self._finish_command(command)
                    log.info("Connected to remote MCP server: %s", self.server_name)
                    continue

                stack_to_close = current_stack
                current_stack = None
                self._session = None
                self.capabilities = None

                if stack_to_close is not None:
                    try:
                        await self._close_stack(
                            stack_to_close, "close active connection stack"
                        )
                    except Exception as exc:
                        self._finish_command(command, exc)
                        break

                self._finish_command(command)
                break
        finally:
            if current_stack is not None:
                try:
                    await self._close_stack(
                        current_stack, "close connection stack during owner shutdown"
                    )
                except Exception as exc:
                    log.warning("Connection owner shutdown cleanup failed: %s", exc)
            self._session = None
            self.capabilities = None

    def _ensure_owner_task(self) -> None:
        if self._owner_task is not None and self._owner_task.done():
            # Discard any stored exception — the owner exited due to a transport
            # failure (e.g. TaskGroup from streamablehttp_client) and a fresh task
            # must be created so connect() can succeed.  Re-raising here would
            # prevent reconnection after a 401.
            try:
                self._owner_task.result()
            except (Exception, asyncio.CancelledError) as exc:
                log.warning("Connection owner task exited: %s", exc)
            self._owner_task = None
        if self._owner_task is None:
            self._owner_task = asyncio.create_task(
                self._connection_owner(),
                name="nordstellar-proxy-connection-owner",
            )

    async def connect(self, url: str, jwt: str) -> None:
        self._ensure_owner_task()
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        await self._commands.put(_ConnectCommand(url=url, jwt=jwt, future=future))
        await future

    async def close(self) -> None:
        if self._owner_task is None:
            return

        if self._owner_task.done():
            try:
                self._owner_task.result()
            except (Exception, asyncio.CancelledError) as exc:
                log.warning("Connection owner task already exited: %s", exc)
            self._owner_task = None
            self._session = None
            self.capabilities = None
            return

        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        await self._commands.put(_CloseCommand(future=future))
        await future
        await self._owner_task
        self._owner_task = None

    async def force_close(self) -> None:
        """Cancel the connection owner task and clean up immediately.

        Unlike close(), this does not send a command through the queue —
        it directly cancels the owner task.  Safe to call when the owner
        may be stuck in cleanup and no longer processing commands.
        """
        if self._owner_task is None:
            return
        if not self._owner_task.done():
            self._owner_task.cancel()
        try:
            await self._owner_task
        except (asyncio.CancelledError, Exception):
            pass
        self._owner_task = None
        self._session = None
        self.capabilities = None

    async def execute(self, coro: Awaitable[T]) -> T:
        """Await *coro*, but cancel it if the connection owner task dies.

        The MCP SDK's ClientSession does not cancel pending request futures
        when the underlying transport crashes (e.g. HTTP 401 kills the
        StreamableHTTP post_writer).  This leaves call_tool() and similar
        calls hanging forever.

        By racing the coroutine against the owner task we guarantee a
        prompt RuntimeError("Not connected to remote MCP server") instead
        of an indefinite hang.
        """
        task = asyncio.ensure_future(coro)
        owner = self._owner_task

        if owner is None:
            return await task

        if owner.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
            raise RuntimeError("Not connected to remote MCP server")

        done, _ = await asyncio.wait(
            {task, owner},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if task in done:
            return task.result()

        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        raise RuntimeError("Not connected to remote MCP server")

    @property
    def session(self) -> ClientSession:
        if self._session is None:
            raise RuntimeError("Not connected to remote MCP server")
        return self._session


@dataclass(slots=True)
class _ConnectCommand:
    url: str
    jwt: str
    future: asyncio.Future[None]


@dataclass(slots=True)
class _CloseCommand:
    future: asyncio.Future[None]


_ConnectionCommand = _ConnectCommand | _CloseCommand


# ---------------------------------------------------------------------------
# Auth error detection
# ---------------------------------------------------------------------------


def _is_auth_error(result: types.CallToolResult) -> bool:
    """
    Detect the AUTH_NOT_AUTHENTICATED sentinel that the remote Go server
    returns when the Bearer token has expired (see graphql.go remote mode branch).
    """
    for content in result.content:
        if isinstance(content, types.TextContent):
            try:
                data = json.loads(content.text)
                if (
                    isinstance(data, dict)
                    and data.get("error") == "AUTH_NOT_AUTHENTICATED"
                ):
                    return True
            except (json.JSONDecodeError, ValueError):
                pass
    return False


# ---------------------------------------------------------------------------
# Proxy server factory
# ---------------------------------------------------------------------------


def _is_auth_exception(exc: BaseException) -> bool:
    """
    Return True if exc indicates the remote MCP server rejected the Bearer token.

    Recognised cases:

    1. httpx.HTTPStatusError with status 401 — the streamablehttp_client raises
       this when the remote Go server returns HTTP 401 (missing/invalid/expired JWT).

    2. MCPError("Session terminated") — the streamablehttp_client converts a 404
       into this error when the remote server's session has expired or restarted.

    3. RuntimeError("AUTH_NOT_AUTHENTICATED") — raised by _call_tool's _do()
       when the Go tool returns an AUTH_NOT_AUTHENTICATED sentinel in its content
       (HTTP 200, within the tokenauth cache window).

    ExceptionGroup recursion is required because anyio / asyncio.TaskGroup wraps
    transport failures in a group whose top-level message contains no auth signal.
    """
    if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 401:
        return True
    if isinstance(exc, McpError) and exc.message == "Session terminated":
        return True
    if isinstance(exc, RuntimeError) and exc.args == ("AUTH_NOT_AUTHENTICATED",):
        return True
    subs = getattr(exc, "exceptions", None)
    if subs is not None:
        return any(_is_auth_exception(sub) for sub in subs)
    return False


def _is_transport_exception(exc: BaseException) -> bool:
    """
    Return True if exc indicates a transport-level connection loss (not an auth rejection).

    Recognised cases:

    1. RuntimeError("Not connected to remote MCP server") — raised by
       ConnectionManager.session when _session is None after the connection owner
       task exits (e.g. the streamablehttp_client TaskGroup crashed).

    2. anyio.ClosedResourceError / BrokenResourceError / EndOfStream — the
       underlying transport stream was closed by a network timeout, server restart,
       load balancer drop, or keep-alive expiration.

    These errors are recoverable via reconnection without re-authentication when
    the JWT is still valid.
    """
    if isinstance(exc, RuntimeError) and exc.args == (
        "Not connected to remote MCP server",
    ):
        return True
    if isinstance(
        exc, (anyio.ClosedResourceError, anyio.BrokenResourceError, anyio.EndOfStream)
    ):
        return True
    subs = getattr(exc, "exceptions", None)
    if subs is not None:
        return any(_is_transport_exception(sub) for sub in subs)
    return False


def _is_recoverable_exception(exc: BaseException) -> bool:
    """Return True if the error can be recovered via reconnection (with or without re-auth)."""
    return _is_auth_exception(exc) or _is_transport_exception(exc)


async def _create_proxy_server(
    conn: ConnectionManager,
    auth: AuthState,
    url: str,
    reauth_lock: asyncio.Lock,
) -> server.Server:
    """
    Build a local MCP server whose handlers forward every call through conn.

    All handlers include a re-authentication retry: if the remote server returns
    AUTH_NOT_AUTHENTICATED or the connection raises an auth-related error, the
    proxy refreshes/re-logs in, reconnects with the new JWT, and retries once.
    This prevents Cursor from caching an empty capabilities set after a 401.
    """
    caps = conn.capabilities
    app: server.Server = server.Server(name=conn.server_name)
    _reauth_lock = reauth_lock

    async def _reauth_and_reconnect() -> None:
        async with _reauth_lock:
            await conn.force_close()

            need_reauth = True
            if auth.is_authenticated():
                try:
                    jwt = auth.extract_jwt()
                    exp = _jwt_exp(jwt)
                    if exp is not None and exp - time.time() > 0:
                        need_reauth = False
                except Exception:
                    pass

            if need_reauth:
                log.info("Auth error detected — re-authenticating and reconnecting...")
                await auth.ensure_authenticated(force_refresh=True)
            else:
                log.info("Token still valid — reconnecting without re-authentication...")

            jwt = auth.extract_jwt()
            await conn.connect(url, jwt)
            log.info("Reconnected%s.", " with refreshed token" if need_reauth else "")

    async def _with_reauth(coro_factory: "Callable[[], Awaitable[T]]") -> T:
        """
        Call coro_factory(). On a recoverable exception (auth or transport),
        re-authenticate/reconnect and retry once. Re-raises on the second failure.
        """
        for attempt in range(2):
            try:
                return await conn.execute(coro_factory())
            except Exception as exc:  # noqa: BLE001
                if attempt == 0 and _is_auth_exception(exc):
                    log.warning(
                        "Auth error on attempt %d (%s: %s) — re-authenticating...",
                        attempt,
                        type(exc).__name__,
                        exc,
                    )
                elif attempt == 0 and _is_transport_exception(exc):
                    log.warning(
                        "Transport error on attempt %d (%s: %s) — reconnecting...",
                        attempt,
                        type(exc).__name__,
                        exc,
                    )
                else:
                    raise
                try:
                    await _reauth_and_reconnect()
                except Exception as reauth_exc:
                    log.error("Recovery failed: %s", reauth_exc)
                    raise exc from reauth_exc
                continue
        raise RuntimeError("unreachable")  # pragma: no cover

    # --- Tools ---
    if caps and caps.tools:

        async def _list_tools(_: Any) -> types.ServerResult:
            return types.ServerResult(
                await _with_reauth(lambda: conn.session.list_tools())
            )

        async def _call_tool(req: types.CallToolRequest) -> types.ServerResult:
            async def _do() -> types.CallToolResult:
                result = await conn.session.call_tool(
                    req.params.name, req.params.arguments or {}
                )
                if _is_auth_error(result):
                    raise RuntimeError("AUTH_NOT_AUTHENTICATED")
                return result

            try:
                return types.ServerResult(await _with_reauth(_do))
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "call_tool(%s) failed: %s: %s",
                    req.params.name,
                    type(exc).__name__,
                    exc,
                )
                # Forward the remote server's error message (e.g. blocked delete operations)
                # instead of a generic message so the client sees the actual reason.
                error_text = str(exc).strip()
                if not error_text:
                    error_text = (
                        "Tool call failed. Please try again or restart the MCP server."
                    )
                return types.ServerResult(
                    types.CallToolResult(
                        content=[
                            types.TextContent(
                                type="text",
                                text=error_text,
                            )
                        ],
                        isError=True,
                    )
                )

        app.request_handlers[types.ListToolsRequest] = _list_tools
        app.request_handlers[types.CallToolRequest] = _call_tool

    # --- Resources ---
    if caps and caps.resources:

        async def _list_resources(_: Any) -> types.ServerResult:
            return types.ServerResult(
                await _with_reauth(lambda: conn.session.list_resources())
            )

        async def _list_resource_templates(_: Any) -> types.ServerResult:
            return types.ServerResult(
                await _with_reauth(lambda: conn.session.list_resource_templates())
            )

        async def _read_resource(req: types.ReadResourceRequest) -> types.ServerResult:
            return types.ServerResult(
                await _with_reauth(lambda: conn.session.read_resource(req.params.uri))
            )

        app.request_handlers[types.ListResourcesRequest] = _list_resources
        app.request_handlers[types.ListResourceTemplatesRequest] = (
            _list_resource_templates
        )
        app.request_handlers[types.ReadResourceRequest] = _read_resource

    # --- Prompts ---
    if caps and caps.prompts:

        async def _list_prompts(_: Any) -> types.ServerResult:
            return types.ServerResult(
                await _with_reauth(lambda: conn.session.list_prompts())
            )

        async def _get_prompt(req: types.GetPromptRequest) -> types.ServerResult:
            return types.ServerResult(
                await _with_reauth(
                    lambda: conn.session.get_prompt(
                        req.params.name, req.params.arguments
                    )
                )
            )

        app.request_handlers[types.ListPromptsRequest] = _list_prompts
        app.request_handlers[types.GetPromptRequest] = _get_prompt

    return app


# ---------------------------------------------------------------------------
# Parent process watchdog
# ---------------------------------------------------------------------------


def _is_pid_alive(pid: int) -> bool:
    """Check whether a process with the given PID is still running."""
    if sys.platform == "win32":
        # On Windows os.kill with signal 0 is not reliable; use ctypes.
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        SYNCHRONIZE = 0x00100000
        handle = kernel32.OpenProcess(SYNCHRONIZE, False, pid)
        if handle:
            kernel32.CloseHandle(handle)
            return True
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


async def _parent_watchdog(initial_ppid: int) -> None:
    """
    Exit immediately when the parent process is gone.

    On macOS/Linux, a child whose parent exits is reparented to PID 1
    (launchd / init), so os.getppid() changes.  On Windows the original
    ppid is retained but the process handle becomes invalid, so we fall
    back to probing whether the PID is still alive.

    Uses os._exit() because the event loop itself may be the source of
    the CPU spin (e.g. kqueue busy-wake on a dead pipe fd).
    """
    while True:
        await asyncio.sleep(_PARENT_WATCHDOG_INTERVAL)
        ppid_changed = os.getppid() != initial_ppid
        parent_dead = not _is_pid_alive(initial_ppid)
        if ppid_changed or parent_dead:
            log.warning(
                "Parent process gone (was pid %d). Exiting.",
                initial_ppid,
            )
            os._exit(0)


# ---------------------------------------------------------------------------
# Shutdown helpers
# ---------------------------------------------------------------------------


def _schedule_hard_exit() -> None:
    """
    Start a daemon thread that calls os._exit after _SHUTDOWN_TIMEOUT seconds.

    Guarantees the process dies even if the async cleanup is deadlocked or
    the event loop is stuck in a busy-wake state.
    """

    def _force() -> None:
        time.sleep(_SHUTDOWN_TIMEOUT)
        log.warning("Graceful shutdown timed out after %ds, forcing exit.", _SHUTDOWN_TIMEOUT)
        os._exit(1)

    threading.Thread(target=_force, daemon=True).start()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def _run(url: str) -> None:
    initial_ppid = os.getppid()
    auth = AuthState()
    conn = ConnectionManager()
    reauth_lock = asyncio.Lock()
    background_tasks: list[asyncio.Task[None]] = []

    # -- Signal handling -------------------------------------------------------
    # loop.add_signal_handler() is only available on Unix (ProactorEventLoop
    # on Windows raises NotImplementedError).  Gracefully skip if unsupported.
    shutdown_event = asyncio.Event()
    if sys.platform != "win32":
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGHUP):
            loop.add_signal_handler(
                sig,
                lambda s=sig: (
                    log.warning("Received %s, shutting down.", signal.Signals(s).name),
                    shutdown_event.set(),
                ),
            )

    try:
        for attempt in range(2):
            await auth.ensure_authenticated()
            jwt = auth.extract_jwt()
            try:
                await conn.connect(url, jwt)
                break
            except Exception as exc:
                if attempt == 0 and _is_recoverable_exception(exc):
                    log.warning(
                        "Initial connection failed with auth error, re-authenticating..."
                    )
                    continue
                raise

        background_tasks.append(
            asyncio.create_task(
                _parent_watchdog(initial_ppid),
                name="nordstellar-proxy-parent-watchdog",
            )
        )

        app = await _create_proxy_server(conn, auth, url, reauth_lock)

        async with stdio_server() as (read_stream, write_stream):
            run_task = asyncio.create_task(
                app.run(
                    read_stream,
                    write_stream,
                    app.create_initialization_options(),
                )
            )
            shutdown_waiter = asyncio.create_task(shutdown_event.wait())
            done, _ = await asyncio.wait(
                [run_task, shutdown_waiter],
                return_when=asyncio.FIRST_COMPLETED,
            )
            if shutdown_waiter in done:
                run_task.cancel()
            shutdown_waiter.cancel()
            for t in done:
                if t is not shutdown_waiter:
                    exc = t.exception()
                    if exc is not None:
                        raise exc
    finally:
        _schedule_hard_exit()
        for task in background_tasks:
            if not task.done():
                task.cancel()
        for task in background_tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        await conn.close()
        await auth.aclose()


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)

    if args.logout:
        return _logout()

    url = os.environ.get("NORDSTELLAR_REMOTE_MCP_URL", "").strip() or (
        args.remote_mcp_url or ""
    )
    if not url:
        _build_arg_parser().print_usage(sys.stderr)
        print(
            "Set NORDSTELLAR_REMOTE_MCP_URL or pass <remote_mcp_url>.\n"
            "Use --logout to clear stored NordStellar session cookies.",
            file=sys.stderr,
        )
        return 1

    _validate_mcp_url(url)
    log.info("Starting NordStellar MCP proxy → %s", url)
    asyncio.run(_run(url))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
