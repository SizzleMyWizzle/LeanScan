import os
import ast
import ipaddress
import re


def load_validate_input():
    path = os.path.join(os.path.dirname(__file__), os.pardir, "leanscan.py")
    with open(path, "r") as f:
        source = f.read()
    tree = ast.parse(source, filename=path)

    env = {"ipaddress": ipaddress, "re": re, "DEBUG": False}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in {"is_hash", "validate_input"}:
            compiled = compile(ast.Module([node], type_ignores=[]), path, "exec")
            exec(compiled, env)
    return env["validate_input"]


validate_input = load_validate_input()

def test_accepts_public_ip():
    assert validate_input("8.8.8.8") is True

def test_rejects_private_or_reserved_ip():
    assert validate_input("192.168.1.1") is False
    assert validate_input("127.0.0.1") is False

def test_accepts_hash():
    assert validate_input("a" * 32) is True
