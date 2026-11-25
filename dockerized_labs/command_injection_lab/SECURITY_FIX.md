# Fixing a remote-code-execution flaw in PyGoat

[PyGoat](https://github.com/adeyosemanputra/pygoat) is an OWASP training app that's vulnerable on purpose, so people can practise finding flaws. In my fork, I took one of its labs and did what a security engineer would do with a real finding: **find it, prove it, fix it properly, and prove the fix.**

| | |
|---|---|
| **Severity** | Critical: CVSS 3.1 score **9.8** (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) |
| **What an attacker gets** | Full control of the server, without logging in |
| **Weaknesses** | CWE-78 OS command injection · CWE-88 argument injection · CWE-95 eval injection · CWE-489 debug mode · CWE-798 hard-coded secret · CWE-1104 outdated components |
| **OWASP Top 10 (2025)** | A05 Injection · A02 Security Misconfiguration · A03 Software Supply Chain Failures |
| **Where** | `dockerized_labs/command_injection_lab/` |

## The short version

- The lab passed user input to a **shell** (lab 1) and to Python's **`eval()`** (lab 2). Either one let anyone run their own commands on the server.
- I proved both with a harmless test, then rewrote the code so user input is **never treated as code**.
- I found a gap in the lab's own "secure fix" suggestion and closed it too.
- **38 tests** fail on the old code and pass on mine. Bandit goes from **6 findings to 0**, and outdated libraries go from **7 known vulnerabilities to 0**.

## How I found it

1. **Automated scanning.** Bandit flagged `subprocess` with `shell=True` (high), use of `eval` (medium) and Flask debug mode (high).
2. **Code review.** I traced each flagged line back to where its data came from. Both came straight from a web form, with no login needed. An AI-assisted review pass helped me check the reachability and pointed me at the `dig` option-injection angle covered below.
3. **Proof.** I confirmed each one actually worked before touching any code. A scanner warning isn't a vulnerability until you've shown it can be exploited.

## Proving it (on the original code)

I used harmless commands that just do some arithmetic. If `42` comes back, the server ran my code:

```
Lab 1  domain = example.com; echo INJECTED-$((6*7))
       → page shows "INJECTED-42"          the server ran my shell command

Lab 2  val = __import__('os').popen('echo RCE-$((6*7))').read()
       → page shows "RCE-42"               the server ran my Python code
```

## Why it happened

| Lab | The vulnerable line | The problem |
|---|---|---|
| Lab 1 (DNS lookup) | `subprocess.Popen(f"dig {domain}", shell=True)` | The input is glued into a command that a shell reads, so characters like `;`, `\|` and `$( )` start new commands |
| Lab 2 (calculator) | `eval(request.form["val"])` | `eval` runs *any* Python, not just maths |
| Both | `debug=True` and `SECRET_KEY = "your-secret-key-here"` | The Flask debugger is itself a remote code-execution console, and the key that signs sessions was public |

## How I fixed it

### Lab 1: no shell, and only accept things that look like a domain

- The command now runs **without a shell**, with the domain passed as a single separate value. Even if it contains `;`, it's just text.
- The domain must match the official hostname format (RFC 1123). Anything else is rejected **before** a command runs.
- The operating-system choice must be exactly `linux` or `win`, and lookups time out after 10 seconds.

#### The gap in the lab's own suggested fix

The lab's "secure fix" page suggests **blocking a list of dangerous characters** (`| & ; $ \` ( )`). That stops classic injection, but it misses **argument injection**:

```
domain = -f/etc/passwd
```

That contains none of the blocked characters. But `dig -f <file>` reads a file and prints its lines back, so it would leak `/etc/passwd`. Turning off the shell doesn't help either.

My fix uses an **allowlist** instead: the input must *look like a hostname*, and hostnames can't start with `-`. That closes both holes. There's a test for this exact payload.

> **Lesson:** blocklists try to list everything bad, and attackers only need the one thing you forgot. Allowlists describe what good input looks like and reject the rest.

### Lab 2: do the maths without running code

I replaced `eval` with a small calculator that **reads the expression's structure** (using Python's `ast` module) and only allows numbers, `+ - * / // % **` and brackets. Anything else, like function calls, names or text, is rejected before it runs.

I also limited input to 100 characters and exponents to 100, so something like `9**9**9` can't freeze the server.

### General hardening

- **Debug mode is off** unless a developer deliberately turns it on locally.
- **The secret key comes from the environment**, or a random one is generated, never a hard-coded value.
- **The container runs as a non-root user**, on Python 3.13 instead of the end-of-life 3.9.
- **Flask, Werkzeug and Jinja2 are updated.** The old versions had 7 known vulnerabilities; the new ones have none.

## Proving the fix

| Check | Before | After |
|---|---|---|
| Lab 1 proof of concept | Runs my command | Rejected: "Enter a valid domain name" |
| Lab 2 proof of concept | Runs my code | Rejected: "Only numbers and ... are allowed" |
| Regression tests (38) | **38 fail** | **38 pass** |
| Bandit findings (high / medium / low) | 2 / 2 / 2 | 0 / 0 / 0 |
| Known vulnerable dependencies | 7 | 0 |

The tests include my proof-of-concept payloads, every common shell trick, newline and option injection, a well-known Python sandbox escape, inputs designed to exhaust resources, and checks that normal lookups and sums still work.

Bandit's zero includes three `# nosec` markers, each with a written reason: importing `subprocess`, the safe fixed-argument call, and listening on all interfaces inside a container.

**Run the tests yourself:**

```bash
cd dockerized_labs/command_injection_lab
pip install -r requirements-dev.txt
python -m pytest -q
```

## What I took away

- **Never use `shell=True` with user input.** Pass commands as a list instead.
- **Allowlists beat blocklists.** The official suggested fix proved it.
- **Never `eval` user input**, even for something as harmless-looking as a calculator.
- **Prove it before and after.** A proof of concept shows the risk is real, and failing-then-passing tests show the fix actually works.

---

**Funso Isola** · [LinkedIn](https://linkedin.com/in/funisola) · [More projects](https://github.com/funsoi-hub)
