import sys
import os
# Add the parent directory to sys.path so we can import flask_dbsc
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, session, request, redirect, url_for, make_response, jsonify, render_template_string
from flask_dbsc import DBSC
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super-secret-key-for-session')

# For production behind a proxy (like Fly.io)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Initialize DBSC
dbsc = DBSC(app)

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
    
    # Create response and initiate DBSC
    resp = make_response(redirect(url_for('index')))
    return dbsc.initiate(resp)

@app.route('/logout')
def logout():
    session.pop('user', None)
    resp = make_response(redirect(url_for('index')))
    # Clear DBSC cookie if needed
    resp.set_cookie(dbsc.config['cookie_name'], '', expires=0)
    return resp

@app.route('/api/protected')
def protected():
    if not session.get('user'):
        return jsonify({"error": "Not logged in"}), 401
        
    if not dbsc.is_authenticated():
        # In a real app, you might want to force DBSC or just warn
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
