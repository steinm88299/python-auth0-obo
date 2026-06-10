import os
import json
from flask import Flask, redirect, url_for, session, request, jsonify, render_template
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import requests as http_requests
import jwt

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET_KEY')

oauth = OAuth(app)

AUTH0_DOMAIN = os.getenv('AUTH0_DOMAIN')
AUDIENCE = os.getenv('AUTH0_AUDIENCE')

auth0 = oauth.register(
    'auth0',
    client_id=os.getenv('AUTH0_CLIENT_ID'),
    client_secret=os.getenv('AUTH0_CLIENT_SECRET'),
    client_kwargs={
        'scope': 'openid profile email read:orders write:orders delete:orders',
        'code_challenge_method': 'S256',
    },
    server_metadata_url=f'https://{AUTH0_DOMAIN}/.well-known/openid-configuration',
)


@app.route('/')
def home():
    user = session.get('user')
    if user:
        userinfo = user.get('userinfo', {})
        email = userinfo.get('email', 'unknown')
        return render_template('index.html', user=email)
    return render_template('index.html', user=None)


@app.route('/login')
def login():
    redirect_uri = url_for('callback', _external=True)
    return auth0.authorize_redirect(
        redirect_uri,
        audience=AUDIENCE
    )


@app.route('/callback')
def callback():
    token = auth0.authorize_access_token()
    session['user'] = token
    return redirect('/')


@app.route('/token')
def token():
    user = session.get('user')
    if not user:
        return redirect('/login')
    access_token = user.get('access_token')
    claims = jwt.decode(access_token, options={"verify_signature": False})
    return jsonify(claims)


@app.route('/logout')
def logout():
    id_token = session.get('user', {}).get('id_token', '')
    session.clear()
    logout_url = (
        f'https://{AUTH0_DOMAIN}/v2/logout'
        f'?returnTo=http://127.0.0.1:5000'
        f'&client_id={os.getenv("AUTH0_CLIENT_ID")}'
    )
    return redirect(logout_url)


def get_access_token():
    user = session.get('user')
    if not user:
        return None
    return user.get('access_token')


@app.route('/orders/get', methods=['POST'])
def orders_get():
    token = get_access_token()
    if not token:
        return redirect('/login')
    response = http_requests.get(
        'http://127.0.0.1:5001/orders',
        headers={'Authorization': f'Bearer {token}'}
    )
    user = session.get('user', {}).get('userinfo', {}).get('email', 'unknown')
    if response.status_code == 200:
        result = json.dumps(response.json(), indent=2)
        return render_template('index.html', user=user, result=result)
    else:
        return render_template('index.html', user=user, error=f'{response.status_code} - {response.text}')


@app.route('/orders/create', methods=['POST'])
def orders_create():
    token = get_access_token()
    if not token:
        return redirect('/login')
    response = http_requests.post(
        'http://127.0.0.1:5001/orders',
        headers={'Authorization': f'Bearer {token}'}
    )
    user = session.get('user', {}).get('userinfo', {}).get('email', 'unknown')
    if response.status_code == 201:
        result = json.dumps(response.json(), indent=2)
        return render_template('index.html', user=user, result=result)
    else:
        return render_template('index.html', user=user, error=f'{response.status_code} - {response.text}')


@app.route('/orders/delete/<int:order_id>', methods=['POST'])
def orders_delete(order_id):
    token = get_access_token()
    if not token:
        return redirect('/login')
    response = http_requests.delete(
        f'http://127.0.0.1:5001/orders/{order_id}',
        headers={'Authorization': f'Bearer {token}'}
    )
    user = session.get('user', {}).get('userinfo', {}).get('email', 'unknown')
    if response.status_code == 200:
        result = json.dumps(response.json(), indent=2)
        return render_template('index.html', user=user, result=result)
    else:
        return render_template('index.html', user=user, error=f'{response.status_code} - {response.text}')


@app.route('/orders/payment', methods=['POST'])
def orders_payment():
    token = get_access_token()
    if not token:
        return redirect('/login')
    response = http_requests.post(
        'http://127.0.0.1:5001/orders/payment',
        headers={'Authorization': f'Bearer {token}'}
    )
    user = session.get('user', {}).get('userinfo', {}).get('email', 'unknown')
    if response.status_code == 201:
        result = json.dumps(response.json(), indent=2)
        return render_template('index.html', user=user, result=result)
    else:
        return render_template('index.html', user=user, error=f'{response.status_code} - {response.text}')


if __name__ == '__main__':
    app.run(debug=True, port=5000)