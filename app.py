import re
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

DATABASE = "scamsense.db"


# =========================================================
# DATABASE
# =========================================================

def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analyzed_at TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                message_preview TEXT NOT NULL
            )
        """)


init_db()


# =========================================================
# DETECTION RULES
# =========================================================

URGENT_PHRASES = [
    "act now",
    "immediately",
    "urgent",
    "within 24 hours",
    "account will be blocked",
    "account suspended",
    "final warning",
    "verify now",
    "respond immediately",
    "last chance",
]

SENSITIVE_REQUESTS = [
    "password",
    "one-time password",
    "otp",
    "pin number",
    "security code",
    "bank details",
    "card details",
    "credit card",
    "debit card",
    "login details",
]

MONEY_PRESSURE = [
    "send money",
    "wire transfer",
    "pay a fee",
    "claim your prize",
    "you have won",
    "gift card",
    "crypto payment",
    "payment required",
    "send payment",
    "processing fee",
]

IMPERSONATION_TERMS = [
    "bank support",
    "government refund",
    "tech support",
    "account verification",
    "customer support",
    "security department",
    "official support",
]

LINK_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
    "cutt.ly",
    "rebrand.ly",
}

# These brands are used only as heuristic signals.
# A matching name does NOT prove that a website is fraudulent.
PROTECTED_BRANDS = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "instagram",
    "facebook",
    "netflix",
    "linkedin",
]


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def find_phrases(message, phrases):
    """Return phrases found in a message, ignoring case."""
    lower_message = message.lower()

    return [
        phrase
        for phrase in phrases
        if phrase in lower_message
    ]


def find_urls(message):
    """Extract URL-like strings from a message."""

    pattern = r"(?:https?://|www\.)[^\s<>\"']+"

    return re.findall(
        pattern,
        message,
        flags=re.IGNORECASE
    )


def inspect_url(url):
    """
    Inspect a URL for transparent heuristic warning signals.
    These checks do not prove that a URL is malicious.
    """

    cleaned = url.rstrip(".,!?;:)]}")

    candidate = (
        cleaned
        if "://" in cleaned
        else "https://" + cleaned
    )

    try:
        parsed = urlparse(candidate)

        host = (
            parsed.hostname or ""
        ).lower()

    except ValueError:
        return [
            "A link could not be parsed reliably."
        ]

    signals = []

    if not host:
        return [
            "A link could not be parsed reliably."
        ]

    # HTTPS is useful but does NOT prove safety.
    if parsed.scheme != "https":
        signals.append(
            "The link does not use HTTPS."
        )

    # Some deceptive URLs use @ to confuse the reader.
    if "@" in parsed.netloc:
        signals.append(
            "The URL contains an @ symbol that may confuse readers."
        )

    # IP address instead of a normal domain.
    if re.fullmatch(
        r"(?:\d{1,3}\.){3}\d{1,3}",
        host
    ):
        signals.append(
            "The link uses an IP address instead of a domain name."
        )

    # URL shorteners hide the final destination.
    if host in LINK_SHORTENERS:
        signals.append(
            "The link uses a URL-shortening service."
        )

    # Punycode can represent internationalized domains.
    if (
        host.startswith("xn--")
        or ".xn--" in host
    ):
        signals.append(
            "The domain uses punycode encoding."
        )

    # Many hyphens can sometimes be suspicious.
    if host.count("-") >= 3:
        signals.append(
            "The domain contains several hyphens."
        )

    # Check for brand impersonation.
    for brand in PROTECTED_BRANDS:

        if brand in host:

            legitimate_domain = f"{brand}.com"

            if host != legitimate_domain:

                signals.append(
                    f"The domain contains the brand name "
                    f"'{brand}' but is not its basic .com domain."
                )

                break

    # Deep subdomains can sometimes be used deceptively.
    parts = host.split(".")

    if len(parts) >= 4:
        signals.append(
            "The domain has an unusually large number "
            "of subdomain levels."
        )

    return signals


# =========================================================
# MAIN ANALYSIS ENGINE
# =========================================================

def analyze_message(message):
    """
    Analyze a message using transparent heuristic rules.

    Returns:
        risk_score
        risk_level
        summary
        signals
        recommendations
        disclaimer
    """

    if not isinstance(message, str):
        raise ValueError(
            "Please enter a valid message."
        )

    message = message.strip()

    if not message:
        raise ValueError(
            "Please enter a message to analyze."
        )

    if len(message) > 10000:
        raise ValueError(
            "Please keep messages under 10,000 characters."
        )

    signals = []

    score = 0

    def add_signal(
        points,
        title,
        explanation
    ):
        nonlocal score

        score += points

        signals.append({
            "title": title,
            "points": points,
            "explanation": explanation
        })

    # -----------------------------------------------------
    # TEXT ANALYSIS
    # -----------------------------------------------------

    urgent = find_phrases(
        message,
        URGENT_PHRASES
    )

    sensitive = find_phrases(
        message,
        SENSITIVE_REQUESTS
    )

    money = find_phrases(
        message,
        MONEY_PRESSURE
    )

    impersonation = find_phrases(
        message,
        IMPERSONATION_TERMS
    )

    # -----------------------------------------------------
    # URGENCY
    # -----------------------------------------------------

    if urgent:

        add_signal(
            18,
            "Urgency or pressure",
            "Urgent wording found: "
            + ", ".join(urgent)
        )

    # -----------------------------------------------------
    # SENSITIVE INFORMATION
    # -----------------------------------------------------

    if sensitive:

        add_signal(
            25,
            "Sensitive information mentioned",
            "Sensitive terms found: "
            + ", ".join(sensitive)
        )

    # -----------------------------------------------------
    # MONEY
    # -----------------------------------------------------

    if money:

        add_signal(
            22,
            "Payment or prize pressure",
            "Money-related phrases found: "
            + ", ".join(money)
        )

    # -----------------------------------------------------
    # IMPERSONATION
    # -----------------------------------------------------

    if impersonation:

        add_signal(
            12,
            "Possible impersonation wording",
            "Terms found: "
            + ", ".join(impersonation)
        )

    # -----------------------------------------------------
    # URL ANALYSIS
    # -----------------------------------------------------

    urls = find_urls(message)

    if urls:

        add_signal(
            8,
            "Message contains a link",
            "Links should be checked carefully, "
            "especially when unexpected."
        )

        for url in urls:

            url_signals = inspect_url(url)

            for url_signal in url_signals:

                add_signal(
                    10,
                    "URL warning",
                    url_signal
                )

    # -----------------------------------------------------
    # SCORE
    # -----------------------------------------------------

    score = min(score, 100)

    # -----------------------------------------------------
    # RISK LEVEL
    # -----------------------------------------------------

    if score >= 50:

        risk = "High"

        summary = (
            "Several warning signs were detected. "
            "Verify independently before acting."
        )

    elif score >= 25:

        risk = "Moderate"

        summary = (
            "Some warning signs were detected. "
            "Check the message carefully."
        )

    else:

        risk = "Low signal"

        summary = (
            "Few warning signs were detected by "
            "these rules. This does not prove safety."
        )

    # -----------------------------------------------------
    # RECOMMENDATIONS
    # -----------------------------------------------------

    recommendations = [

        "Do not share passwords, PINs, or one-time "
        "codes in response to an unexpected message.",

        "Verify requests using the organization's "
        "official app, website, or phone number.",

        "Avoid clicking unexpected links or sending "
        "money under pressure."
    ]

    # -----------------------------------------------------
    # NO SIGNALS
    # -----------------------------------------------------

    if not signals:

        signals.append({

            "title": "No configured rule matched",

            "points": 0,

            "explanation": (
                "This detector did not find its "
                "configured warning patterns. "
                "New or subtle scams may not be detected."
            )
        })

    return {

        "risk_score": score,

        "risk_level": risk,

        "summary": summary,

        "signals": signals,

        "recommendations": recommendations,

        "disclaimer": (
            "This is a rule-based educational tool, "
            "not a definitive verdict. Messages can "
            "trigger false alarms or evade these rules."
        )
    }


# =========================================================
# FLASK ROUTES
# =========================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


@app.route(
    "/api/analyze",
    methods=["POST"]
)
def analyze_api():

    data = request.get_json(
        silent=True
    ) or {}

    message = data.get(
        "message",
        ""
    )

    try:

        result = analyze_message(
            message
        )

        # Save only a short preview.
        preview = " ".join(
            message.split()
        )[:160]

        with get_db_connection() as connection:

            connection.execute(
                """
                INSERT INTO analysis_history
                (
                    analyzed_at,
                    risk_score,
                    risk_level,
                    message_preview
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    datetime.now(
                        timezone.utc
                    ).isoformat(),

                    result["risk_score"],

                    result["risk_level"],

                    preview
                )
            )

        return jsonify(result)

    except ValueError as error:

        return jsonify({
            "error": str(error)
        }), 400


@app.route(
    "/api/history",
    methods=["GET"]
)
def history_api():

    with get_db_connection() as connection:

        rows = connection.execute(
            """
            SELECT
                id,
                analyzed_at,
                risk_score,
                risk_level,
                message_preview

            FROM analysis_history

            ORDER BY id DESC

            LIMIT 50
            """
        ).fetchall()

    return jsonify([
        dict(row)
        for row in rows
    ])


@app.route(
    "/api/history",
    methods=["DELETE"]
)
def clear_history_api():

    with get_db_connection() as connection:

        connection.execute(
            "DELETE FROM analysis_history"
        )

    return jsonify({
        "message":
        "Analysis history cleared."
    })


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )