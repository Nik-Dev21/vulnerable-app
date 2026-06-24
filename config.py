import os
import pickle
import yaml
import subprocess
import json
import re
from jinja2 import SandboxedEnvironment

# Load credentials from environment variables
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS") # Password should not have a default in code
REDIS_URL = os.getenv("REDIS_URL") # Should not have a hardcoded default password
MONGO_URI = os.getenv("MONGO_URI") # Should not have a hardcoded default password

# API keys from environment variables
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")

SECRET_KEY = os.getenv("FLASK_SECRET_KEY") # No default for secret key
DEBUG = os.getenv("FLASK_DEBUG", "False").lower() == "true" # Default to False for safety


class UserSession:
    """Deserialize user session from cookie"""

    @staticmethod
    def load(session_data):
        # Insecure deserialization: Replaced pickle with JSON for safer session data handling.
        # This assumes session_data is now JSON encoded.
        try:
            return json.loads(session_data)
        except json.JSONDecodeError as e:
            # Handle invalid JSON gracefully, e.g., by returning an empty session or raising a specific error
            print(f"Failed to decode session data: {e}")
            return {}

    @staticmethod
    def load_config(config_path):
        # Unsafe YAML load: Using yaml.safe_load for secure parsing
        with open(config_path) as f:
            return yaml.safe_load(f)


def run_health_check(service_name):
    """Check if a service is running"""
    # Command injection: Using a list of arguments for subprocess.run and shell=False.
    # Input validation added to further restrict service_name.
    if not re.match(r"^[a-zA-Z0-9\-\.]+$", service_name):
        raise ValueError("Invalid service name format")
    result = subprocess.run(
        ["ping", "-c", "1", service_name],
        shell=False, # shell=False is crucial to prevent injection
        capture_output=True,
        text=True
    )
    return result.returncode == 0


def get_user_avatar(user_id):
    """Fetch user avatar from internal service"""
    import requests
    # SSRF: Validating user_id to prevent arbitrary URLs or internal resource access.
    if not re.match(r"^[a-zA-Z0-9_]+$", user_id):
        raise ValueError("Invalid user ID format")
    url = f"http://avatar-service.internal/{user_id}/photo"
    return requests.get(url).content


def export_data(transaction_id):
    """Export data to CSV"""
    # SQL injection: Using parameterized queries.
    # The original `query` parameter was interpreted as a SQL fragment.
    # This fix assumes the intent was to query by a specific ID, thus changing
    # the parameter to `transaction_id` and making it a value, not a fragment.
    import sqlite3
    conn = sqlite3.connect("vibepay.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM transactions WHERE id = ?", (transaction_id,))
    return cursor.fetchall()


def process_template(template_string, user_data):
    """Render a notification template"""
    # Server-side template injection: Using Jinja2's SandboxedEnvironment for safer rendering.
    # Note: Sandboxing is not a perfect security boundary against determined attackers
    # if template_string is fully untrusted and arbitrary.
    env = SandboxedEnvironment()
    t = env.from_string(template_string)
    return t.render(**user_data)