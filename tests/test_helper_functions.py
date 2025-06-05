import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))
import requests
from leanscan.utils import is_hash, request_with_retries


class DummyResponse:
    def __init__(self, status_code):
        self.status_code = status_code


def test_is_hash_valid_cases():
    assert is_hash("a" * 32)
    assert is_hash("A" * 40)
    assert is_hash("0123456789abcdef" * 4)


def test_is_hash_invalid_cases():
    assert not is_hash("g" * 32)
    assert not is_hash("a" * 31)
    assert not is_hash("z" * 64)


def test_request_success_no_retry(monkeypatch):
    def fake_get(url, headers=None, params=None, timeout=10, debug=False):
        return DummyResponse(200)

    monkeypatch.setattr(requests, "get", fake_get)
    resp = request_with_retries("http://example.com")
    assert isinstance(resp, DummyResponse)
    assert resp.status_code == 200


def test_request_timeout_then_success(monkeypatch):
    calls = {"count": 0}

    def fake_get(url, headers=None, params=None, timeout=10, debug=False):
        if calls["count"] == 0:
            calls["count"] += 1
            raise requests.exceptions.ReadTimeout
        return DummyResponse(200)

    monkeypatch.setattr(requests, "get", fake_get)
    resp = request_with_retries("http://example.com", max_retries=2)
    assert isinstance(resp, DummyResponse)
    assert calls["count"] == 1


def test_request_rate_limit(monkeypatch):
    def fake_get(url, headers=None, params=None, timeout=10, debug=False):
        return DummyResponse(429)

    monkeypatch.setattr(requests, "get", fake_get)
    resp = request_with_retries("http://example.com")
    assert resp is None


def test_request_exception(monkeypatch):
    def fake_get(url, headers=None, params=None, timeout=10, debug=False):
        raise requests.exceptions.RequestException("fail")

    monkeypatch.setattr(requests, "get", fake_get)
    assert request_with_retries("http://example.com") is None
