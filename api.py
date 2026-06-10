import os
import requests
from functools import wraps
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import jwt

load_dotenv()

app = Flask(__name__)

AUTH0_DOMAIN = os.getenv('AUTH0_DOMAIN')
AUDIENCE = os.getenv('AUTH0_AUDIENCE')
ISSUER = f'https://{AUTH0_DOMAIN}/'
JWKS_URI = f'https://{AUTH0_DOMAIN}/.well-known/jwks.json'

PAYMENT_AUDIENCE = os.getenv('AUTH0_PAYMENT_AUDIENCE')
PAYMENT_TOKEN_URL = f'https://{AUTH0_DOMAIN}/oauth/token'
M2M_CLIENT_ID = os.getenv('AUTH0_M2M_CLIENT_ID')
M2M_CLIENT_SECRET = os.getenv('AUTH0_M2M_CLIENT_SECRET')


def validate_token(token, audience, issuer, jwks_uri):
    public_keys = jwt.PyJWKClient(jwks_uri)
    signing_key = public_keys.get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=['RS256'],
        audience=audience,
        issuer=issuer,
    )
    return claims


def require_scope(required_scope):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Missing or invalid Authorization header'}), 401
            token = auth_header.split(' ')[1]
            try:
                claims = validate_token(token, AUDIENCE, ISSUER, JWKS_URI)
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token has expired'}), 401
            except jwt.InvalidTokenError as e:
                return jsonify({'error': f'Invalid token: {str(e)}'}), 401
            # Auth0 returns scope as a space-separated string, not a list
            scopes = claims.get('scope', '').split()
            if required_scope not in scopes:
                return jsonify({
                    'error': 'Insufficient scope',
                    'required': required_scope,
                    'present': scopes
                }), 403
            return f(claims, *args, **kwargs)
        return decorated
    return decorator


def exchange_token(subject_token):
    # RFC 8693 OBO token exchange using Auth0 M2M client credentials.
    # The subject_token (Jane's Orders API token) is passed as a custom
    # parameter to the Auth0 Action, which extracts her sub and injects
    # it into the Payment API token along with an act claim.
    # Unlike Okta, Auth0 does not support RFC 8693 grant type natively —
    # the exchange is handled via a Client Credentials flow intercepted
    # by an Auth0 Action on the Client Credentials trigger.
    response = requests.post(
        PAYMENT_TOKEN_URL,
        json={
            'grant_type': 'client_credentials',
            'client_id': M2M_CLIENT_ID,
            'client_secret': M2M_CLIENT_SECRET,
            'audience': PAYMENT_AUDIENCE,
            'subject_token': subject_token,
        }
    )
    print(f'Token exchange status: {response.status_code}')
    print(f'Token exchange response: {response.json()}')
    if response.status_code != 200:
        return None, response.json()
    return response.json().get('access_token'), None


@app.route('/orders', methods=['GET'])
@require_scope('read:orders')
def get_orders(claims):
    return jsonify({
        'user': claims.get('sub'),
        'orders': [
            {'id': 1, 'item': 'Widget A', 'status': 'shipped'},
            {'id': 2, 'item': 'Widget B', 'status': 'pending'},
        ]
    })


@app.route('/orders', methods=['POST'])
@require_scope('write:orders')
def create_order(claims):
    return jsonify({
        'user': claims.get('sub'),
        'message': 'Order created',
        'order': {'id': 3, 'item': 'Widget C', 'status': 'created'}
    }), 201


@app.route('/orders/<int:order_id>', methods=['DELETE'])
@require_scope('delete:orders')
def delete_order(claims, order_id):
    return jsonify({
        'user': claims.get('sub'),
        'message': f'Order {order_id} deleted'
    })


@app.route('/orders/payment', methods=['POST'])
@require_scope('read:orders')
def request_payment(claims):
    subject_token = request.headers.get('Authorization', '').split(' ')[1]

    payment_token, error = exchange_token(subject_token)
    if error:
        return jsonify({
            'error': 'Token exchange failed',
            'detail': error
        }), 500

    payment_response = requests.post(
        'http://127.0.0.1:5002/payments',
        headers={'Authorization': f'Bearer {payment_token}'}
    )

    if payment_response.status_code == 201:
        return jsonify({
            'message': 'Payment request successful',
            'original_user': claims.get('sub'),
            'payment': payment_response.json()
        }), 201
    else:
        return jsonify({
            'error': 'Payment API call failed',
            'detail': payment_response.json()
        }), payment_response.status_code


if __name__ == '__main__':
    app.run(debug=True, port=5001)