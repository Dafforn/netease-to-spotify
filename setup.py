#!/usr/bin/env python3
"""Interactive helper for creating a Spotify refresh token locally (PKCE flow).

Uses a public client_id from an established open-source Spotify client
(ncspot / spotify-player, etc.) so that no client secret is required and
the app-level Web API restrictions on newly-registered apps do not apply.
"""

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlencode, urlparse

import requests


# Public client_id of an established open-source Spotify client.
# Find one in e.g. https://github.com/hrkfdn/ncspot or
# https://github.com/aome510/spotify-player (search "client_id").
SPOTIFY_CLIENT_ID = "65b708073fc0480ea92a077233ca87bd"

SPOTIFY_AUTHORIZE_URL = "https://accounts.spotify.com/authorize"
SPOTIFY_TOKEN_URL = "https://accounts.spotify.com/api/token"
SPOTIFY_SCOPE = "playlist-modify-private"
REDIRECT_URI = "http://127.0.0.1:8989/login"


def playlist_id_from_input(value: str) -> str:
    value = value.strip()
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) == 2 and parts[0] == "playlist":
            value = parts[1]
        else:
            raise ValueError("Enter a Spotify playlist URL or playlist ID.")
    if not value or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" for character in value):
        raise ValueError("Enter a valid Spotify playlist URL or playlist ID.")
    return value


def build_authorization_url(state: str, code_challenge: str) -> str:
    params = {
        "client_id": SPOTIFY_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": SPOTIFY_SCOPE,
        "state": state,
        "code_challenge_method": "S256",
        "code_challenge": code_challenge,
    }
    return f"{SPOTIFY_AUTHORIZE_URL}?{urlencode(params)}"


def extract_callback_code(callback: str, expected_state: str) -> str:
    parsed = urlparse(callback.strip())
    values = parse_qs(parsed.query)
    if values.get("state", [None])[0] != expected_state:
        raise ValueError("OAuth state mismatch.")
    if values.get("error", [None])[0]:
        raise ValueError(f"Spotify authorization failed: {values['error'][0]}")
    code = values.get("code", [None])[0]
    if not code:
        raise ValueError("Callback URL does not contain an authorization code.")
    return code


def exchange_code(code: str, code_verifier: str) -> str:
    response = requests.post(
        SPOTIFY_TOKEN_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": SPOTIFY_CLIENT_ID,
            "code_verifier": code_verifier,
        },
        timeout=30,
    )
    response.raise_for_status()
    token = response.json().get("refresh_token")
    if not token:
        raise RuntimeError("Spotify did not return a refresh token.")
    return token


def main() -> None:
    if "PASTE_" in SPOTIFY_CLIENT_ID:
        raise SystemExit(
            "Edit this file first: set SPOTIFY_CLIENT_ID to a public "
            "client_id (e.g. from ncspot or spotify-player)."
        )

    playlist_input = input("Spotify playlist URL or ID: ")
    playlist_id = playlist_id_from_input(playlist_input)

    state = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()

    print("\nOpen this URL in your browser:")
    print(build_authorization_url(state, challenge))
    callback = input("\nPaste the full callback URL: ")
    refresh_token = exchange_code(
        extract_callback_code(callback, state), verifier
    )

    print("\nSetup complete.")
    print("Add these values to GitHub Repository Secrets:")
    print(f"SPOTIFY_CLIENT_ID={SPOTIFY_CLIENT_ID}")
    print(f"SPOTIFY_REFRESH_TOKEN={refresh_token}")
    print(f"SPOTIFY_PLAYLIST_ID={playlist_id}")
    print("NETEASE_COOKIE=<add manually from your logged-in NetEase session>")
    print("(SPOTIFY_CLIENT_SECRET is no longer needed; delete that secret.)")


if __name__ == "__main__":
    main()
