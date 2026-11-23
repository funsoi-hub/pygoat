import ast
import operator
import os
import re
import secrets
import subprocess  # nosec B404 - used only with fixed argument lists, never a shell

from flask import Flask, render_template, request

app = Flask(__name__)
# Secret from the environment; a random per-process key otherwise (never a hard-coded value).
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# --------------------------------------------------------------------------- Lab 1 helpers

# RFC 1123 hostname: dot-separated labels of letters, digits and inner hyphens, 253 chars max.
# An allowlist, not a blocklist: anything that isn't plainly a hostname is refused, including
# shell metacharacters (; | & $ ` newline) AND option injection such as "-f/etc/passwd",
# which a character blocklist misses because it contains no "dangerous" characters.
HOSTNAME_RE = re.compile(r"(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?")
LOOKUP_COMMANDS = {"linux": "dig", "win": "nslookup"}
LOOKUP_TIMEOUT_SECONDS = 10


def is_valid_hostname(value: str) -> bool:
    return bool(HOSTNAME_RE.fullmatch(value))


def dns_lookup(domain: str, os_type: str) -> str:
    """Run a DNS lookup without a shell: the domain is one argv entry, never parsed as code."""
    if os_type not in LOOKUP_COMMANDS:
        return "Choose Linux or Windows."
    if not is_valid_hostname(domain):
        return "Enter a valid domain name, for example example.com."
    try:
        result = subprocess.run(  # nosec B603 - fixed binary, validated single argument, no shell
            [LOOKUP_COMMANDS[os_type], domain],
            capture_output=True,
            text=True,
            timeout=LOOKUP_TIMEOUT_SECONDS,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "The lookup timed out."
    except FileNotFoundError:
        return "The lookup tool isn't installed on this server."
    return result.stdout + result.stderr


# --------------------------------------------------------------------------- Lab 2 helpers

MAX_EXPRESSION_LENGTH = 100
MAX_EXPONENT = 100
_BINARY_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARY_OPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


class UnsafeExpression(ValueError):
    pass


def safe_calculate(expression: str):
    """Evaluate arithmetic only, by walking the parsed syntax tree.

    eval() runs any Python, so "__import__('os').system(...)" was remote code execution.
    Here only number literals and + - * / // % ** and parentheses are allowed. Names,
    calls, attribute access and everything else are rejected before anything runs.
    """
    if len(expression) > MAX_EXPRESSION_LENGTH:
        raise UnsafeExpression(f"Expressions are limited to {MAX_EXPRESSION_LENGTH} characters.")
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise UnsafeExpression("That isn't a valid arithmetic expression.") from exc

    def walk(node):
        if isinstance(node, ast.Expression):
            return walk(node.body)
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _BINARY_OPS:
            left, right = walk(node.left), walk(node.right)
            if isinstance(node.op, ast.Pow) and abs(right) > MAX_EXPONENT:
                raise UnsafeExpression(f"Exponents are limited to {MAX_EXPONENT}.")  # stops 9**9**9 DoS
            return _BINARY_OPS[type(node.op)](left, right)
        if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
            return _UNARY_OPS[type(node.op)](walk(node.operand))
        raise UnsafeExpression("Only numbers and + - * / // % ** ( ) are allowed.")

    try:
        return walk(tree)
    except ZeroDivisionError as exc:
        raise UnsafeExpression("Division by zero.") from exc


# --------------------------------------------------------------------------- routes


@app.route("/")
def index():
    """Main page with command injection lab description"""
    return render_template("index.html")


@app.route("/lab1", methods=["GET", "POST"])
def lab1():
    """Lab 1: Name Server Lookup (fixed: no shell, allowlisted input)"""
    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        os_type = request.form.get("os", "")
        return render_template("lab1.html", output=dns_lookup(domain, os_type))
    return render_template("lab1.html")


@app.route("/lab2", methods=["GET", "POST"])
def lab2():
    """Lab 2: Calculator (fixed: AST-based arithmetic instead of eval)"""
    if request.method == "POST":
        try:
            output = safe_calculate(request.form.get("val", ""))
        except UnsafeExpression as exc:
            output = str(exc)
        return render_template("lab2.html", output=str(output))
    return render_template("lab2.html")


@app.route("/health")
def health_check():
    return "OK", 200


if __name__ == "__main__":
    # The debugger allows arbitrary code execution, so it's opt-in for local development only.
    debug = os.environ.get("FLASK_DEBUG", "").lower() in {"1", "true"}
    app.run(host=os.environ.get("HOST", "0.0.0.0"), port=5013, debug=debug)  # nosec B104 - container
