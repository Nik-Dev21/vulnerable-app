"""Flask microservice configuration"""

import os
import pickle
import yaml
import subprocess

# Hardcoded credentials
DB_HOST = "prod-db.vibepay.internal"
DB_USER = "root"
DB_PASS = "V1b3P@y_Pr0d_2025!"
REDIS_URL = "redis://:secretpassword@redis.vibepay.internal:6379"
MONGO_URI = "mongodb://admin:password123@mongo.vibepay.internal:27017/vibepay"

# API keys in source
OPENAI_API_KEY = "sk-fake-openai-key-for-testing-do-not-use-1234"
TWILIO_AUTH_TOKEN = "fake_twilio_token_1234567890abcdef"
SLACK_WEBHOOK = "https://fake-slack-webhook.example.com/T000/B000/XXXX"

SECRET_KEY = "flask-secret-key-do-not-share"
DEBUG = True  # Left on in production


class UserSession:
    """Deserialize user session from cookie"""

    @staticmethod
    def load(session_data):
        # Insecure deserialization - pickle from untrusted input
        return pickle.loads(session_data)

    @staticmethod
    def load_config(config_path):
        # Unsafe YAML load - allows arbitrary code execution
        with open(config_path) as f:
            return yaml.load(f, Loader=yaml.Loader)


def run_health_check(service_name):
    """Check if a service is running"""
    # Command injection via string formatting
    result = subprocess.run(
        f"ping -c 1 {service_name}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.returncode == 0


def get_user_avatar(user_id):
    """Fetch user avatar from internal service"""
    import requests
    # SSRF - user_id is not validated, could be an internal URL
    url = f"http://avatar-service.internal/{user_id}/photo"
    return requests.get(url).content


def export_data(query):
    """Export data to CSV"""
    # SQL injection via string concatenation
    import sqlite3
    conn = sqlite3.connect("vibepay.db")
    cursor = conn.execute(f"SELECT * FROM transactions WHERE {query}")
    return cursor.fetchall()


def process_template(template_string, user_data):
    """Render a notification template"""
    # Server-side template injection
    from jinja2 import Template
    t = Template(template_string)
    return t.render(**user_data)