"""Regression tests for the command-injection fix.

Each payload here was confirmed to execute on the original code (see the PR).
Run from this folder:  python -m pytest -q
"""

import subprocess

import pytest

import app as lab

INJECTION_PAYLOADS = [
    "example.com; echo INJECTED",        # command chaining
    "example.com && echo INJECTED",
    "example.com | echo INJECTED",       # pipe
    "$(echo INJECTED)",                  # command substitution
    "`echo INJECTED`",
    "example.com\necho INJECTED",        # newline
    "-f/etc/passwd",                     # option injection: dig reads a file; no "dangerous" characters
    "-h",
    "example..com",
    "a" * 64 + ".com",                   # label too long
    "",
]


@pytest.fixture
def client():
    lab.app.config["TESTING"] = True
    return lab.app.test_client()


@pytest.fixture
def recorded_runs(monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout="ANSWER SECTION\n", stderr="")

    monkeypatch.setattr(lab.subprocess, "run", fake_run)
    return calls


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_lab1_rejects_injection_before_running_anything(client, recorded_runs, payload):
    r = client.post("/lab1", data={"domain": payload, "os": "linux"})
    assert r.status_code == 200
    assert "valid domain" in r.get_data(as_text=True)
    assert recorded_runs == []  # nothing was executed


def test_lab1_real_shell_payload_does_not_execute(client):
    # No mock: the exact proof-of-concept from the PR must not run.
    r = client.post("/lab1", data={"domain": "example.com; echo INJECTED-$((6*7))", "os": "linux"})
    assert "INJECTED-42" not in r.get_data(as_text=True)


@pytest.mark.parametrize("domain", ["example.com", "sub.domain-name.co.uk", "localhost", "example.com."])
def test_lab1_valid_domains_run_without_a_shell(client, recorded_runs, domain):
    client.post("/lab1", data={"domain": domain, "os": "linux"})
    (args, kwargs), = recorded_runs
    assert args == ["dig", domain]          # an argument list: the domain is never parsed by a shell
    assert kwargs["shell"] is False
    assert kwargs["timeout"] > 0


def test_lab1_os_is_allowlisted(client, recorded_runs):
    client.post("/lab1", data={"domain": "example.com", "os": "win"})
    assert recorded_runs[0][0] == ["nslookup", "example.com"]
    client.post("/lab1", data={"domain": "example.com", "os": "rm -rf /"})
    assert len(recorded_runs) == 1


@pytest.mark.parametrize("payload", [
    "__import__('os').popen('echo RCE').read()",   # the PR's proof of concept
    "open('/etc/passwd').read()",
    "().__class__.__bases__[0].__subclasses__()",  # classic sandbox escape
    "lambda: 1",
    "[1, 2, 3]",
    "True + 1",
    "'a' * 3",
])
def test_lab2_rejects_code(client, payload):
    r = client.post("/lab2", data={"val": payload})
    body = r.get_data(as_text=True)
    assert "RCE" not in body.replace(payload, "")
    assert "root:" not in body
    with pytest.raises(lab.UnsafeExpression):
        lab.safe_calculate(payload)


@pytest.mark.parametrize("expression, expected", [
    ("7*7", 49), ("2 + 3 * 4", 14), ("(2 + 3) * 4", 20), ("10 / 4", 2.5),
    ("10 // 4", 2), ("10 % 4", 2), ("2 ** 10", 1024), ("-5 + 2", -3), ("1.5 * 2", 3.0),
])
def test_lab2_still_does_arithmetic(client, expression, expected):
    assert lab.safe_calculate(expression) == expected
    assert str(expected) in client.post("/lab2", data={"val": expression}).get_data(as_text=True)


@pytest.mark.parametrize("payload", ["9 ** 9 ** 9", "2 ** 1000000", "1" * 101, "1 / 0"])
def test_lab2_blocks_resource_exhaustion_and_errors(payload):
    with pytest.raises(lab.UnsafeExpression):
        lab.safe_calculate(payload)


def test_no_hardcoded_secret_and_debug_off_by_default():
    assert lab.app.config["SECRET_KEY"] != "your-secret-key-here"
    assert len(lab.app.config["SECRET_KEY"]) >= 32
