import os
from functools import wraps
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import jwt

load_dotenv()

app = Flask(__name__)

AUTH0_DOMAIN = os.getenv('AUTH0_DOMAIN')
PAYMENT_AUDIENCE = os.getenv('AUTH0_PAYMENT_AUDIENCE')
ISSUER = f'https://{AUTH0_DOMAIN}/'
JWKS_URI = f'https://{AUTH0_DOMAIN}/.well-known/jwks.json'


def validate_token(token):
    # Auth0 uses a single JWKS endpoint for all APIs on the tenant
    # unlike Okta which has a separate JWKS endpoint per Authorization Server
    public_keys = jwt.PyJWKClient(JWKS_URI)
    signing_key = public_keys.get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=['RS256'],
        audience=PAYMENT_AUDIENCE,
        issuer=ISSUER,
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
                claims = validate_token(token)
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token has expired'}), 401
            except jwt.InvalidTokenError as e:
                return jsonify({'error': f'Invalid token: {str(e)}'}), 401
            # Auth0 scope is a space-separated string
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


@app.route('/payments', methods=['POST'])
@require_scope('process:payments')
def process_payment(claims):
    print(f'Payment API token claims: {claims}')
    return jsonify({
        'acting_service': claims.get('sub'),
        'original_user': claims.get('original_sub'),
        'act': claims.get('https://auth0-payments-api/act'),
        'audience': claims.get('aud'),
        'scopes': claims.get('scope'),
        'message': 'Payment processed successfully',
        'payment': {
            'id': 'PAY-001',
            'amount': 99.99,
            'currency': 'USD',
            'status': 'approved'
        }
    }), 201


if __name__ == '__main__':
    app.run(debug=True, port=5002)