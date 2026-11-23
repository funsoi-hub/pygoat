# Fix: remote code execution in the command-injection lab

| | |
|---|---|
| **Severity** | Critical, CVSS 3.1 **9.8** (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) |
| **Weaknesses** | CWE-78 OS command injection · CWE-88 argument injection · CWE-95 eval injection · CWE-489 debug mode · CWE-798 hard-coded secret · CWE-1104 outdated components |
| **OWASP Top 10:2025** | A05 Injection · A02 Security Misconfiguration · A03 Software Supply Chain Failures |
| **Files** | `dockerized_labs/command_injection_lab/` |
| **Fixed in** | PR `fix/command-injection-lab` |

> PyGoat is intentionally vulnerable for teaching. This fork fixes one lab as a find-and-fix exercise; the lab's description pages are unchanged.

## How it was found

1. **SAST:** Bandit flagged `B602 subprocess with shell=True` (High), `B307 eval` (Medium) and `B201 Flask debug=True` (High) in `app.py`.
2. **AI-assisted review:** an AI code-review pass over the flagged code confirmed both paths were reachable from unauthenticated form fields. It also spotted a gap the scanners and the lab's own suggested fix both miss: **option injection** into `dig` (below).
3. **Manual verification:** each finding was confirmed with a harmless proof of concept before writing any fix.

## Proof of concept (original code)

Both payloads ran attacker-controlled code; `$((6*7))` is evaluated by the shell, proving execution rather than echo:

```
POST /lab1  domain=example.com; echo INJECTED-$((6*7))   os=linux
→ response contains "INJECTED-42"                       (shell command executed)

POST /lab2  val=__import__('os').popen('echo RCE-$((6*7))').read()
→ response contains "RCE-42"                            (Python code executed)
```

Either one gives an unauthenticated attacker full control of the container.

## Root cause

| Lab | Vulnerable code | Why it's exploitable |
|---|---|---|
| Lab 1 | `subprocess.Popen(f"dig {domain}", shell=True)` | User input is pasted into a string that a shell parses, so `;`, `|`, `$( )` and newlines start new commands. |
| Lab 2 | `eval(request.form["val"])` | `eval` runs any Python expression, not just arithmetic. |
| Both | `debug=True`, `SECRET_KEY = "your-secret-key-here"` | The Werkzeug debugger is itself a remote code-execution console; the session-signing key is public. |

## The fix

**Lab 1: no shell, and an allowlist instead of a blocklist.**

- `subprocess.run(["dig", domain], shell=False, timeout=10)`: the domain is a single argv entry, so no character in it is ever interpreted.
- The domain must match an RFC 1123 hostname pattern. Anything else is refused *before* a process starts.
- The OS choice is allowlisted (`linux` → `dig`, `win` → `nslookup`).

**Why not the lab's own suggested fix?** It blocks a list of "dangerous characters" (`| & ; $ \` ( )`). That stops shell metacharacters but not **argument injection**: `-f/etc/passwd` has none of them, yet `dig -f <file>` reads queries from a file and echoes its lines back, leaking the file. `shell=False` alone doesn't stop this either. An allowlist ("must look like a hostname", which can't start with `-`) closes both. There's a test for it.

**Lab 2: parse, don't execute.**

`eval` is replaced by `safe_calculate()`, which parses the input with `ast.parse` and walks the tree, allowing only number literals, `+ - * / // % **`, unary `+ -` and parentheses. Names, calls, attributes, strings, lists and lambdas are rejected before anything runs. Input is capped at 100 characters and exponents at 100, so `9**9**9` can't hang the server.

**Hardening:**

- Debug mode is off unless `FLASK_DEBUG=1` is set.
- `SECRET_KEY` comes from the environment, or a random key per process.
- The container now runs as a non-root user on `python:3.13-alpine` (3.9 is end-of-life), and only `app.py` and the templates are copied in.
- Flask 2.0.1, Werkzeug 2.0.1 and Jinja2 3.0.1 are upgraded to 3.1.3, 3.1.9 and 3.1.6. pip-audit found 7 known vulnerabilities in the old versions and finds 0 in the new ones.

## Verification

| Check | Before | After |
|---|---|---|
| Proof of concept, lab 1 | Executes | Rejected: "Enter a valid domain name" |
| Proof of concept, lab 2 | Executes | Rejected: "Only numbers and … are allowed" |
| Regression tests (`tests/`, 38 cases) | **38 failed** | **38 passed** |
| Bandit issues (High / Medium / Low) | 2 / 2 / 2 | 0 / 0 / 0 |
| pip-audit known vulnerabilities | 7 | 0 |

The Bandit result includes three `# nosec` markers, each with a written justification: importing `subprocess`, the fixed-argument `subprocess.run` call, and binding `0.0.0.0` inside a container.

The tests include the exact proof-of-concept payloads, shell metacharacters, newline and option injection, the classic `().__class__.__bases__[0].__subclasses__()` sandbox escape, resource-exhaustion inputs, and checks that ordinary lookups and arithmetic still work.

```bash
cd dockerized_labs/command_injection_lab
pip install -r requirements-dev.txt
python -m pytest -q
```

## Lessons

- **`shell=True` with user input is never safe.** Escaping is fragile. Pass an argument list instead.
- **Allowlists beat blocklists.** The blocklist fix still allowed option injection.
- **Never `eval` user input,** even "just for a calculator". Parse it and allow only what you need.
- **Debug mode is a backdoor** when it's reachable from the network.
