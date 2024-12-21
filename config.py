from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import Flask,request
import logging
from flask_talisman import Talisman



app = Flask(__name__)
Talisman(app, content_security_policy=None) # Integrate this to transmit this for HTTPS request
limiter = Limiter(get_remote_address,app=app,default_limits=["100 per minute"]) # initiate the limiter

logging.basicConfig(
    filename="app.log",  # Log file
    level=logging.INFO,  # Log level: INFO, DEBUG, ERROR, etc.
    format="%(asctime)s - %(levelname)s - %(message)s"
)

@app.before_request
def log_request_info():
    """Log details of incoming requests."""
    logging.info(
        "Request: %s %s %s\nHeaders: %s\nBody: %s",
        request.remote_addr,
        request.method,
        request.url,
        request.headers,
        request.get_data(as_text=True),
    )

@app.after_request
def log_response_info(response):
    """Log details of outgoing responses."""
    logging.info(
        "Response: %s\nStatus: %s\nBody: %s",
        request.url,
        response.status,
        response.get_data(as_text=True),
    )
    return response