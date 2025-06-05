import os
import ast
import re
import ipaddress
import requests
import colorama


def load_functions(*names):
    path = os.path.join(os.path.dirname(__file__), os.pardir, "leanscan.py")
    with open(path, "r") as f:
        source = f.read()
    tree = ast.parse(source, filename=path)

    env = {
        "ipaddress": ipaddress,
        "re": re,
        "requests": requests,
        "Fore": colorama.Fore,
        "DEBUG": False,
    }
    loaded = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            compiled = compile(ast.Module([node], type_ignores=[]), path, "exec")
            exec(compiled, env)
            loaded[node.name] = env[node.name]
    return loaded

funcs = load_functions("is_hash", "request_with_retries")

is_hash = funcs["is_hash"]
request_with_retries = funcs["request_with_retries"]


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
    def fake_get(url, headers=None, params=None, timeout=10):
        return DummyResponse(200)

    monkeypatch.setattr(requests, "get", fake_get)
    resp = request_with_retries("http://example.com")
    assert isinstance(resp, DummyResponse)
    assert resp.status_code == 200


def test_request_timeout_then_success(monkeypatch):
    calls = {"count": 0}

    def fake_get(url, headers=None, params=None, timeout=10):
        if calls["count"] == 0:
            calls["count"] += 1
            raise requests.exceptions.ReadTimeout
        return DummyResponse(200)

    monkeypatch.setattr(requests, "get", fake_get)
    resp = request_with_retries("http://example.com", max_retries=2)
    assert isinstance(resp, DummyResponse)
    assert calls["count"] == 1


def test_request_rate_limit(monkeypatch):
    def fake_get(url, headers=None, params=None, timeout=10):
        return DummyResponse(429)

    monkeypatch.setattr(requests, "get", fake_get)
    resp = request_with_retries("http://example.com")
    assert resp is None


def test_request_exception(monkeypatch):
    def fake_get(url, headers=None, params=None, timeout=10):
        raise requests.exceptions.RequestException("fail")

    monkeypatch.setattr(requests, "get", fake_get)
    assert request_with_retries("http://example.com") is None
