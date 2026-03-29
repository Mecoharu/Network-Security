import os
import json
import base64
import secrets
import requests

from flask import (
    Flask, session, redirect,
    url_for, request, render_template
)
from dotenv import load_dotenv

load_dotenv(override=True)

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'fallback-secret')
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True


# OIDC Helper Functions 
def get_discovery():
    """Fetch OIDC Discovery Document dan cache di app context."""
    if not hasattr(app, '_oidc_discovery'):
        url = os.getenv('OIDC_DISCOVERY_URL')
        resp = requests.get(url)
        resp.raise_for_status()
        app._oidc_discovery = resp.json()
    return app._oidc_discovery


def parse_jwt(token: str) -> dict:
    """Decode JWT payload tanpa verifikasi signature (untuk display)."""
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('Invalid JWT format')


    payload = parts[1]
    payload += '=' * (4 - len(payload) % 4)
    decoded = base64.urlsafe_b64decode(payload)
    return json.loads(decoded)


#Routes 
@app.route('/')
def home():
    user = session.get('user')
    return render_template(
        'home.html',
        user=user,
        provider=os.getenv('OIDC_PROVIDER', 'unknown')
    )


@app.route('/auth/login')
def login():
    discovery = get_discovery()

    # Generate state & nonce untuk safety
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    session['oidc_state'] = state
    session['oidc_nonce'] = nonce

    # Build authorization URL
    params = {
        'response_type': 'code',
        'client_id':     os.getenv('OIDC_CLIENT_ID'),
        'redirect_uri':  os.getenv('OIDC_REDIRECT_URI'),
        'scope': os.getenv('OIDC_SCOPE', 'openid profile email'),
        'state':         state,
        'nonce':         nonce,
    }

    auth_url = discovery['authorization_endpoint']
    query = '&'.join(f'{k}={v}' for k, v in params.items())
    return redirect(f'{auth_url}?{query}')

@app.route('/auth/callback')
def callback():
    
    print("=== CALLBACK ===")
    print("Args:", request.args)
    print("Session state:", session.get('oidc_state'))
    print("Received state:", request.args.get('state'))

    received_state = request.args.get('state')
    expected_state = session.get('oidc_state')

    if not expected_state:
        return 'Session expired. <a href="/auth/login">Login again</a>', 403

    if received_state != expected_state:
        return 'Invalid state parameter. <a href="/auth/login">Login again</a>', 403

    if 'error' in request.args:
        return f"OAuth error: {request.args.get('error_description')}", 400

    code = request.args.get('code')
    discovery = get_discovery()

    token_response = requests.post(
        discovery['token_endpoint'],
        data={
            'grant_type':    'authorization_code',
            # 'client_id':     os.getenv('OIDC_CLIENT_ID'),
            # 'client_secret': os.getenv('OIDC_CLIENT_SECRET'),
            'redirect_uri':  os.getenv('OIDC_REDIRECT_URI'),
            'code':          code,
        },
        auth=(os.getenv('OIDC_CLIENT_ID'), os.getenv('OIDC_CLIENT_SECRET'))
        
    )

    if not token_response.ok:
        return f'Token exchange failed: {token_response.text}', 500

    tokens = token_response.json()

    if 'id_token' not in tokens:
        return 'No ID token received from provider', 500

    claims = parse_jwt(tokens['id_token'])

    session['user']         = claims
    session['id_token']     = tokens['id_token']
    session['access_token'] = tokens.get('access_token')

    return redirect(url_for('profile'))

@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('home'))

    return render_template(
        'profile.html',
        user=session['user'],
        id_token=session['id_token'],
        provider=os.getenv('OIDC_PROVIDER', 'unknown')
    )


@app.route('/auth/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


# Run Flask App

if __name__ == '__main__':
    port = int(os.getenv('FLASK_PORT', 8000))
    app.run(debug=True, port=port)
