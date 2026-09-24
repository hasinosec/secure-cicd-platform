import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from app import app  # noqa: E402


def client():
    app.config["TESTING"] = True
    return app.test_client()


def test_healthz_ok():
    r = client().get("/healthz")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_greet_default():
    assert client().get("/greet").get_json()["message"] == "hello world"


def test_greet_truncates_long_input():
    long_name = "a" * 500
    msg = client().get(f"/greet?name={long_name}").get_json()["message"]
    assert len(msg) == len("hello ") + 64
