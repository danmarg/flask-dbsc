import sys
import os
import logging
# Add the parent directory to sys.path so we can import flask_dbsc
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, session, request, redirect, url_for, make_response, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_dbsc import DBSC, SQLAlchemyStore, DBSCSessionMixin, DBSCChallengeMixin
from werkzeug.middleware.proxy_fix import ProxyFix

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super-secret-key-for-session')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:////data/dbsc.db')
app.logger.setLevel(logging.DEBUG)

# For production behind a proxy (like Fly.io)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

db = SQLAlchemy(app)

# Define concrete models using the DBSC mixins.
# In an existing app these live alongside your other models and are included
# in your normal Flask-Migrate / Alembic migrations.
class DBSCSession(db.Model, DBSCSessionMixin):
    __tablename__ = 'dbsc_sessions'

class DBSCChallenge(db.Model, DBSCChallengeMixin):
    __tablename__ = 'dbsc_challenges'

dbsc = DBSC(app, storage=SQLAlchemyStore(db, DBSCSession, DBSCChallenge))

with app.app_context():
    db.create_all()  # replace with Flask-Migrate in a real app

DBSC_HEADERS = [
    'Secure-Session-Response',
    'Sec-Secure-Session-Id',
    'Sec-Session-Id',
    'Secure-Session-Registration',
    'Secure-Session-Challenge',
    'Secure-Session-Skipped',
]

@app.before_request
def log_dbsc_headers():
    dbsc_hdrs = {h: request.headers.get(h) for h in DBSC_HEADERS if request.headers.get(h)}
    if dbsc_hdrs:
        app.logger.debug('DBSC request headers on %s %s: %s', request.method, request.path, dbsc_hdrs)
    else:
        app.logger.debug('%s %s (no DBSC headers)', request.method, request.path)

@app.after_request
def log_dbsc_response_headers(response):
    dbsc_hdrs = {h: response.headers.get(h) for h in DBSC_HEADERS if response.headers.get(h)}
    if dbsc_hdrs:
        app.logger.debug('DBSC response headers on %s %s: %s', request.method, request.path, dbsc_hdrs)
    return response

INDEX_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>DBSC Flask Demo</title>
</head>
<body>
    <h1>DBSC Flask Demo</h1>
    {% if session.get('user') %}
        <p>Logged in as: {{ session['user'] }}</p>
        <p>DBSC Protected: <strong>{{ 'YES' if dbsc_authenticated else 'NO' }}</strong></p>
        <p><a href="{{ url_for('logout') }}">Logout</a></p>
        <p><a href="{{ url_for('protected') }}">Access Protected API</a></p>
    {% else %}
        <form action="{{ url_for('login') }}" method="post">
            <input type="text" name="username" placeholder="Username" required>
            <button type="submit">Login</button>
        </form>
    {% endif %}

    <hr>
    <h3>DBSC Status</h3>
    <p>DBSC Cookie ({{ dbsc_cookie_name }}): {{ dbsc_cookie_val or 'Not Set' }}</p>

    <hr>
    <p><a href="https://github.com/danmarg/flask-dbsc">View on GitHub</a></p>
</body>
</html>
"""

@app.route('/')
def index():
    dbsc_authenticated = dbsc.is_authenticated()
    dbsc_cookie_name = dbsc.config['cookie_name']
    dbsc_cookie_val = request.cookies.get(dbsc_cookie_name)
    return render_template_string(INDEX_TEMPLATE,
                                  dbsc_authenticated=dbsc_authenticated,
                                  dbsc_cookie_name=dbsc_cookie_name,
                                  dbsc_cookie_val=dbsc_cookie_val)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    session['user'] = username

    # DBSC: Secure-Session-Registration must be on a 2xx response — Chrome
    # ignores it on 3xx redirects (spec §8.8). Use a JS redirect with a short
    # delay so Chrome has time to complete the registration handshake (and set
    # the bound cookie) before the next navigation sends a request.
    resp = make_response(
        '<html><head><script>'
        'setTimeout(function(){ window.location.replace("/"); }, 1000);'
        '</script></head></html>',
        200
    )
    resp.content_type = 'text/html'
    return dbsc.initiate(resp)

@app.route('/logout')
def logout():
    session.pop('user', None)
    resp = make_response(redirect(url_for('index')))
    resp.set_cookie(dbsc.config['cookie_name'], '', expires=0)
    return resp

@app.route('/api/protected')
def protected():
    if not session.get('user'):
        return jsonify({"error": "Not logged in"}), 401

    if not dbsc.is_authenticated():
        return jsonify({
            "error": "DBSC session missing or invalid",
            "message": "Your session is not device-bound. Re-login to enable DBSC."
        }), 403

    return jsonify({
        "data": "This is sensitive data bound to your device!",
        "user": session['user']
    })

if __name__ == '__main__':
    # DBSC MUST run over HTTPS.
    # For local testing, we use an adhoc SSL context.
    print("Starting DBSC Demo App on https://127.0.0.1:5000")
    app.run(port=5000, ssl_context='adhoc', debug=True)
