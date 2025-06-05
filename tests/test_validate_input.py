import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))
from leanscan.utils import validate_input


def test_accepts_public_ip():
    assert validate_input("8.8.8.8") is True


def test_rejects_private_or_reserved_ip():
    assert validate_input("192.168.1.1") is False
    assert validate_input("127.0.0.1") is False


def test_accepts_hash():
    assert validate_input("a" * 32) is True


def test_accepts_public_ipv6():
    assert validate_input("2001:4860:4860::8888") is True


def test_rejects_reserved_ipv6():
    assert validate_input("fc00::1") is False
    assert validate_input("::") is False
