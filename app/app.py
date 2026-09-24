"""Minimal demo service.

The application is deliberately small. The engineering in this repository is
the pipeline that builds, scans and gates it -- not the app itself.
"""
import os

from flask import Flask, jsonify, request

app = Flask(__name__)

MAX_NAME = 64


@app.get("/healthz")
def healthz():
    return jsonify(status="ok"), 200


@app.get("/greet")
def greet():
    name = request.args.get("name", "world")[:MAX_NAME]
    return jsonify(message=f"hello {name}"), 200


@app.get("/version")
def version():
    return jsonify(version=os.environ.get("APP_VERSION", "dev")), 200


if __name__ == "__main__":  # pragma: no cover
    app.run(host="127.0.0.1", port=8000)
