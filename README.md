# Flask-DBSC Reference Implementation

This project provides a reference implementation of **Device Bound Session Credentials (DBSC)** for Flask. DBSC is a W3C specification that helps mitigate session hijacking by binding session cookies to hardware-backed keys on the user's device.

**Spec**: [https://w3c.github.io/webappsec-dbsc/](https://w3c.github.io/webappsec-dbsc/)

## Features
- **DBSCExtension**: Easy integration with existing Flask applications.
- **Hardware Binding**: Leverages DBSC to bind session cookies to the user's device.
- **Automatic Refresh**: Handles the DBSC refresh flow to maintain secure, short-lived cookies.
- **Pluggable Storage**: Interface for storing public keys (MemoryStore included).
- **Security-First**: Uses `authlib` for robust JWT and JWK verification.

## Project Structure
- `flask_dbsc/`: Core package containing the extension, storage, and utilities.
- `examples/`: A demo application showing how to integrate DBSC with standard Flask sessions.
- `tests/`: Unit tests for the cryptographic verification logic.

## Live Demo

A live demo is running at **https://flask-dbsc-demo.fly.dev**. Log in with any username using Chrome 130+ to see DBSC session registration in action.

## Getting Started

### Prerequisites
- Python 3.12+
- Flask
- Authlib
- cryptography
- pyOpenSSL (for ad-hoc SSL in development)

### Installation
1.  **Set up the environment**:
    ```bash
    # Install venv if needed (Ubuntu/Debian)
    sudo apt install -y python3.12-venv
    
    # Create and activate virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Install dependencies
    pip install Flask authlib cryptography pyOpenSSL
    ```

### Running the Demo
1.  **Start the application**:
    ```bash
    PYTHONPATH=. python examples/app.py
    ```
2.  **Access the app**: Visit `https://127.0.0.1:5000`.
    *Note: DBSC MUST run over HTTPS. Accept the self-signed certificate warning for local testing.*
3.  **Test the flow**: 
    - Log in with any username.
    - Check the network tab for the `Sec-Session-Registration` header in the login response.
    - In a DBSC-supported browser (Chrome 130+), you'll see background requests to `/dbsc/register`.
    - Protected API calls (`/api/protected`) will verify the bound cookie.

## How it Works
1.  **Initiation**: When a user logs in, the server sends a `Sec-Session-Registration` header.
2.  **Registration**: The browser generates a hardware-backed key pair and registers the public key at `/dbsc/register`.
3.  **Binding**: The server issues a short-lived cookie (e.g., `dbsc_session`) bound to that key.
4.  **Refresh**: Before the cookie expires, the browser automatically refreshes it by providing a Proof of Possession (PoP) signature at `/dbsc/refresh`.

## Security Benefits
Even if an attacker steals the `dbsc_session` cookie, they cannot use it on another device because they lack the hardware-bound private key required to sign the refresh request.

## Testing
Run the unit tests to verify the cryptographic logic:
```bash
PYTHONPATH=. ./venv/bin/python3 tests/test_utils.py
```
