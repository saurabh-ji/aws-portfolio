# app.py
import os
import datetime
from functools import wraps

from flask import Flask, request, jsonify
import boto3
import jwt
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
AWS_PROFILE = os.getenv("AWS_PROFILE")  # optional
JWT_SECRET = os.getenv("JWT_SECRET", "change_this_secret")
JWT_ALGO = "HS256"
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", "60"))

# Optional: Use a specific AWS profile if provided (local dev)
if AWS_PROFILE:
    session = boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)
else:
    session = boto3.Session(region_name=AWS_REGION)

ec2 = session.client("ec2")

app = Flask(__name__)


# -------------------------
# Authentication utilities
# -------------------------
def generate_token(username: str):
    payload = {
        "sub": username,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=JWT_EXP_MINUTES),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
    # PyJWT >=2 returns str, older returns bytes
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Expect token in Authorization header: "Bearer <token>"
        auth_header = request.headers.get("Authorization", None)
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()

        if not token:
            return jsonify({"message": "Token is missing!"}), 401

        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
            request.user = payload.get("sub")
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expired"}), 401
        except Exception as e:
            return jsonify({"message": "Token is invalid", "error": str(e)}), 401

        return f(*args, **kwargs)

    return decorated


# -------------------------
# Simple user "login"
# -------------------------
# NOTE: This example uses a basic username/password for demo.
# Replace with real auth (DB/LDAP/OAuth) for production.
DUMMY_USER = os.getenv("DUMMY_USER", "saurabh")
DUMMY_PASS = os.getenv("DUMMY_PASS", "password123")


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "username & password required"}), 400

    if username == DUMMY_USER and password == DUMMY_PASS:
        token = generate_token(username)
        return jsonify({"token": token}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401


# -------------------------
# EC2 endpoints
# -------------------------
@app.route("/ec2/list", methods=["GET"])
@token_required
def list_ec2():
    """
    Returns a list of instances with basic info.
    Optional query param: state (running, stopped, etc.)
    """
    state = request.args.get("state")  # optional filter
    filters = []
    if state:
        filters.append({"Name": "instance-state-name", "Values": [state]})

    try:
        resp = ec2.describe_instances(Filters=filters) if filters else ec2.describe_instances()
        instances = []
        for reservation in resp.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                instances.append({
                    "InstanceId": inst.get("InstanceId"),
                    "State": inst.get("State", {}).get("Name"),
                    "InstanceType": inst.get("InstanceType"),
                    "LaunchTime": inst.get("LaunchTime").isoformat() if inst.get("LaunchTime") else None,
                    "PrivateIp": inst.get("PrivateIpAddress"),
                    "PublicIp": inst.get("PublicIpAddress"),
                    "Tags": inst.get("Tags", []),
                })
        return jsonify({"instances": instances}), 200
    except Exception as e:
        return jsonify({"message": "Failed to list instances", "error": str(e)}), 500


@app.route("/ec2/status/<instance_id>", methods=["GET"])
@token_required
def ec2_status(instance_id):
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        reservations = resp.get("Reservations", [])
        if not reservations:
            return jsonify({"message": "Instance not found"}), 404
        inst = reservations[0]["Instances"][0]
        return jsonify({
            "InstanceId": inst.get("InstanceId"),
            "State": inst.get("State", {}).get("Name"),
            "InstanceType": inst.get("InstanceType"),
            "LaunchTime": inst.get("LaunchTime").isoformat() if inst.get("LaunchTime") else None
        }), 200
    except ec2.exceptions.ClientError as e:
        return jsonify({"message": "Error fetching status", "error": str(e)}), 400
    except Exception as e:
        return jsonify({"message": "Unexpected error", "error": str(e)}), 500


@app.route("/ec2/start", methods=["POST"])
@token_required
def ec2_start():
    data = request.get_json() or {}
    instance_id = data.get("instance_id")
    if not instance_id:
        return jsonify({"message": "instance_id is required in JSON body"}), 400
    try:
        resp = ec2.start_instances(InstanceIds=[instance_id])
        return jsonify({"message": "Start initiated", "response": resp}), 200
    except ec2.exceptions.ClientError as e:
        return jsonify({"message": "Failed to start instance", "error": str(e)}), 400
    except Exception as e:
        return jsonify({"message": "Unexpected error", "error": str(e)}), 500


@app.route("/ec2/stop", methods=["POST"])
@token_required
def ec2_stop():
    data = request.get_json() or {}
    instance_id = data.get("instance_id")
    if not instance_id:
        return jsonify({"message": "instance_id is required in JSON body"}), 400
    try:
        resp = ec2.stop_instances(InstanceIds=[instance_id])
        return jsonify({"message": "Stop initiated", "response": resp}), 200
    except ec2.exceptions.ClientError as e:
        return jsonify({"message": "Failed to stop instance", "error": str(e)}), 400
    except Exception as e:
        return jsonify({"message": "Unexpected error", "error": str(e)}), 500


# Health check
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "aws_region": AWS_REGION}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=(os.getenv("FLASK_DEBUG","0") == "1"))
