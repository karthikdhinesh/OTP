"""
server.py — OTP backend with real email delivery via Gmail SMTP.

Setup:
1. pip install flask flask-cors
2. Turn on 2-Step Verification on your Google account:
   https://myaccount.google.com/security
3. Create an "App Password":
   https://myaccount.google.com/apppasswords
   (Choose app: "Mail", device: "Other" -> name it "OTP demo")
   Google gives you a 16-character password — use that below, NOT your
   normal Gmail password.
4. Set the two environment variables before running:
     export GMAIL_ADDRESS="youraddress@gmail.com"
     export GMAIL_APP_PASSWORD="the16charapppassword"
   (On Windows CMD: set GMAIL_ADDRESS=... / set GMAIL_APP_PASSWORD=...)
5. Run: python server.py
6. The API listens on http://localhost:5000

Endpoints:
  POST /send-otp    body: {"email": "someone@example.com"}
  POST /verify-otp  body: {"email": "someone@example.com", "code": "123456"}
"""

import os
import secrets
import smtplib
import string
import time
from dataclasses import dataclass
from email.mime.text import MIMEText

from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # allows the HTML page (opened as a local file) to call this API

GMAIL_ADDRESS = os.environ.get("GMAIL_ADDRESS")
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD")

OTP_LENGTH = 6
TTL_SECONDS = 300      # 5 minutes
MAX_ATTEMPTS = 3


@dataclass
class OTPRecord:
    code: str
    expires_at: float
    attempts_left: int


_store: dict[str, OTPRecord] = {}


def generate_otp(length: int = OTP_LENGTH) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(length))


def send_email(to_address: str, code: str) -> None:
    if not GMAIL_ADDRESS or not GMAIL_APP_PASSWORD:
        raise RuntimeError(
            "GMAIL_ADDRESS / GMAIL_APP_PASSWORD environment variables are not set. "
            "See the setup instructions at the top of server.py."
        )

    subject = "Your verification code"
    body = (
        f"Your one-time code is: {code}\n\n"
        f"This code expires in {TTL_SECONDS // 60} minutes. "
        f"If you didn't request this, you can ignore this email."
    )
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = GMAIL_ADDRESS
    msg["To"] = to_address

    with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
        smtp.starttls()
        smtp.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
        smtp.sendmail(GMAIL_ADDRESS, [to_address], msg.as_string())


@app.route("/send-otp", methods=["POST"])
def send_otp():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()

    if "@" not in email or "." not in email:
        return jsonify({"success": False, "message": "Enter a valid email address."}), 400

    code = generate_otp()
    _store[email] = OTPRecord(
        code=code,
        expires_at=time.time() + TTL_SECONDS,
        attempts_left=MAX_ATTEMPTS,
    )

    try:
        send_email(email, code)
    except Exception as exc:  # noqa: BLE001 — surface a clean message to the frontend
        return jsonify({"success": False, "message": f"Could not send email: {exc}"}), 500

    return jsonify({"success": True, "message": "Code sent.", "expires_in": TTL_SECONDS})


@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()
    code = (data.get("code") or "").strip()

    record = _store.get(email)

    if record is None:
        return jsonify({"success": False, "message": "No code was requested for this email."}), 400

    if time.time() > record.expires_at:
        del _store[email]
        return jsonify({"success": False, "message": "Code expired. Request a new one."}), 400

    if record.attempts_left <= 0:
        del _store[email]
        return jsonify({"success": False, "message": "Too many attempts. Request a new code."}), 429

    if secrets.compare_digest(record.code, code):
        del _store[email]
        return jsonify({"success": True, "message": "Verified."})

    record.attempts_left -= 1
    return jsonify({
        "success": False,
        "message": f"Incorrect code. {record.attempts_left} attempt(s) left.",
        "attempts_left": record.attempts_left,
    }), 401


if __name__ == "__main__":
    if not GMAIL_ADDRESS or not GMAIL_APP_PASSWORD:
        print(
            "\n⚠️  GMAIL_ADDRESS / GMAIL_APP_PASSWORD are not set.\n"
            "   The server will run, but /send-otp will fail until you set them.\n"
            "   See the setup instructions at the top of this file.\n"
        )
    app.run(port=5000, debug=True)
