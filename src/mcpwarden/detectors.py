"""AST detectors for the seven MW rules.

Each detector walks a parsed module and returns Finding tuples of
(rule_id, lineno, col, message, evidence). All original code, written
against the weakness classes, never copied from any scanned project.
"""

import ast


def _call_name(call):
    """Dotted name of a call target, e.g. requests.get, os.chdir."""
    func = call.func
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
        return ".".join(reversed(parts))
    return ""


def _func_params(func):
    params = {a.arg for a in func.args.args}
    params.update(a.arg for a in func.args.kwonlyargs)
    if func.args.vararg:
        params.add(func.args.vararg.arg)
    if func.args.kwarg:
        params.add(func.args.kwarg.arg)
    return params


def _uses_param(node, params):
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in params:
            return True
    return False


def _tainted_names(func, params):
    """Parameters plus locals assigned from parameter derived values.

    One pass in source order, so a handler that does ``url = CONFIG[name]``
    and later fetches ``url`` is treated the same as using the parameter
    or subscript directly at the call site.
    """
    tainted = set(params)
    assigns = []
    for node in ast.walk(func):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            assigns.append((node.targets[0].id, node.value, node.lineno, node.col_offset))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            assigns.append((node.target.id, node.value, node.lineno, node.col_offset))
    assigns.sort(key=lambda item: (item[2], item[3]))
    for name, value, _line, _col in assigns:
        if _uses_param(value, tainted):
            tainted.add(name)
    return tainted


def _source_lines(source):
    return source.splitlines()


def _evidence(lines, lineno, span=0):
    start = max(0, lineno - 1 - span)
    end = min(len(lines), lineno + span)
    return "\n".join(lines[start:end]).strip()


# ---------------------------------------------------------------- MW001

_MW001_SINKS = {
    "open",
    "Path",
    "pathlib.Path",
    "send_file",
    "send_from_directory",
    "shutil.copyfile",
    "shutil.copy",
    "shutil.copy2",
    "shutil.move",
    "os.remove",
    "os.unlink",
}


def _mw001_validated(func):
    """True when the handler confines paths or allowlists the parameter."""
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if any(v in name for v in ("is_relative_to", "commonpath", "realpath", "resolve")):
                return True
            if name.endswith("startswith"):
                return True
        if isinstance(node, ast.Compare):
            if any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
                others = [node.left] + list(node.comparators)
                if any(isinstance(o, (ast.List, ast.Tuple, ast.Set, ast.Dict, ast.Name)) for o in others):
                    return True
    return False


def detect_mw001(tree, source, filename):
    lines = _source_lines(source)
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = _func_params(node)
        if not params or _mw001_validated(node):
            continue
        tainted = _tainted_names(node, params)
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            name = _call_name(call)
            if name not in _MW001_SINKS:
                continue
            args = list(call.args) + [kw.value for kw in call.keywords]
            if any(_uses_param(a, tainted) for a in args):
                out.append((
                    "MW001", call.lineno, call.col_offset,
                    "Tool parameter reaches a file operation with no path validation or root confinement",
                    _evidence(lines, call.lineno),
                ))
    return out


# ---------------------------------------------------------------- MW002

_TOKEN_WORDS = ("token", "api_key", "apikey", "auth", "secret", "password", "credential", "session_key")
_VERIFY_WORDS = ("verif", "authenticat", "validate", "check_token", "check_key")


def _is_tokenish(name):
    low = name.lower()
    return any(w in low for w in _TOKEN_WORDS)


def detect_mw002(tree, source, filename):
    lines = _source_lines(source)
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = _func_params(node)
        tokenish = {p for p in params if _is_tokenish(p)}
        if not tokenish:
            continue
        verified = False
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            name = _call_name(call).lower()
            if any(w in name for w in _VERIFY_WORDS) and _uses_param(call, tokenish):
                verified = True
                break
        if verified:
            continue
        for child in ast.walk(node):
            if not isinstance(child, ast.If):
                continue
            gated = None
            test = child.test
            if isinstance(test, ast.Name) and test.id in tokenish:
                gated = test.id
            elif (
                isinstance(test, ast.UnaryOp)
                and isinstance(test.op, ast.Not)
                and isinstance(test.operand, ast.Name)
                and test.operand.id in tokenish
            ):
                gated = test.operand.id
            if not gated:
                continue
            grants = any(
                isinstance(stmt, ast.Return) and stmt.value is not None
                for stmt in ast.walk(child)
                if stmt is not child
            )
            if grants:
                out.append((
                    "MW002", child.lineno, child.col_offset,
                    "Sensitive capability gated on mere truthiness of '%s' instead of a verification call" % gated,
                    _evidence(lines, child.lineno),
                ))
    return out


# ---------------------------------------------------------------- MW003

_MW003_FETCH = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.request",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.request",
    "urllib.request.urlopen", "urlopen",
}


def _mw003_validated(func):
    saw_parse = False
    saw_host_check = False
    for node in ast.walk(func):
        if isinstance(node, ast.Call) and "urlparse" in _call_name(node):
            saw_parse = True
        if isinstance(node, ast.Attribute) and node.attr == "hostname":
            saw_host_check = True
    return saw_parse and saw_host_check


def detect_mw003(tree, source, filename):
    lines = _source_lines(source)
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = _func_params(node)
        if _mw003_validated(node):
            continue
        tainted_names = _tainted_names(node, params)
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            if _call_name(call) not in _MW003_FETCH:
                continue
            url_arg = call.args[0] if call.args else None
            for kw in call.keywords:
                if kw.arg == "url":
                    url_arg = kw.value
            if url_arg is None or isinstance(url_arg, ast.Constant):
                continue
            tainted = _uses_param(url_arg, tainted_names) or isinstance(url_arg, (ast.Subscript, ast.Attribute))
            if tainted:
                out.append((
                    "MW003", call.lineno, call.col_offset,
                    "URL from user or config input passed to an HTTP fetch with no host validation",
                    _evidence(lines, call.lineno),
                ))
    return out


# ---------------------------------------------------------------- MW004

_MW004_CALLS = {
    "os.chdir",
    "sys.path.append", "sys.path.insert", "sys.path.remove", "sys.path.pop",
    "os.putenv", "os.unsetenv",
}


def detect_mw004(tree, source, filename):
    lines = _source_lines(source)
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and _call_name(child) in _MW004_CALLS:
                out.append((
                    "MW004", child.lineno, child.col_offset,
                    "Tool handler mutates process global state (%s)" % _call_name(child),
                    _evidence(lines, child.lineno),
                ))
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if (
                        isinstance(target, ast.Subscript)
                        and isinstance(target.value, ast.Attribute)
                        and target.value.attr == "environ"
                    ):
                        out.append((
                            "MW004", child.lineno, child.col_offset,
                            "Tool handler writes to os.environ (global state mutation)",
                            _evidence(lines, child.lineno),
                        ))
    return out


# ---------------------------------------------------------------- MW005

def _is_netloc(node):
    return isinstance(node, ast.Attribute) and node.attr == "netloc"


def _looks_like_url_var(node):
    return isinstance(node, ast.Name) and "url" in node.id.lower()


def detect_mw005(tree, source, filename):
    lines = _source_lines(source)
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        operands = [node.left] + list(node.comparators)
        for op, left, right in zip(node.ops, operands, operands[1:]):
            if isinstance(op, ast.Eq):
                if _is_netloc(left) or _is_netloc(right):
                    out.append((
                        "MW005", node.lineno, node.col_offset,
                        "Host check compares urlparse netloc instead of hostname (ports and userinfo slip through)",
                        _evidence(lines, node.lineno),
                    ))
            elif isinstance(op, ast.In):
                if _looks_like_url_var(right) and (
                    (isinstance(left, ast.Constant) and isinstance(left.value, str))
                    or isinstance(left, ast.Name)
                ):
                    out.append((
                        "MW005", node.lineno, node.col_offset,
                        "Substring host matching on the raw URL string instead of parsed hostname equality",
                        _evidence(lines, node.lineno),
                    ))
    return out


# ---------------------------------------------------------------- MW006

_MW006_CALLS = {
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "os.system", "os.popen",
}


def _mw006_interpolated(cmd, params):
    if isinstance(cmd, ast.JoinedStr):
        return True
    if isinstance(cmd, ast.Call) and _call_name(cmd).endswith("format"):
        return True
    if isinstance(cmd, ast.BinOp) and isinstance(cmd.op, (ast.Add, ast.Mod)):
        # Concatenation counts only when a parameter (or a local derived
        # from one) flows in. Joining pure literals is a fixed command.
        return _uses_param(cmd, params)
    return False


def _is_constant_expr(node):
    """True when an expression is built only from literal constants."""
    allowed = (ast.Constant, ast.BinOp, ast.UnaryOp, ast.Tuple, ast.List,
               ast.Add, ast.Mod, ast.USub, ast.UAdd)
    return all(isinstance(n, allowed) for n in ast.walk(node))


def detect_mw006(tree, source, filename):
    lines = _source_lines(source)
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = _func_params(node)
        tainted = _tainted_names(node, params)
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            name = _call_name(call)
            if name not in _MW006_CALLS:
                continue
            cmd = call.args[0] if call.args else None
            for kw in call.keywords:
                if kw.arg in ("args", "cmd", "command"):
                    cmd = kw.value
            shell = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in call.keywords
            )
            if cmd is None:
                continue
            interpolated = _mw006_interpolated(cmd, tainted)
            literal_only = _is_constant_expr(cmd)
            if (shell and not literal_only) or interpolated or (name in ("os.system", "os.popen") and not literal_only):
                out.append((
                    "MW006", call.lineno, call.col_offset,
                    "Shell command built from input (command injection)",
                    _evidence(lines, call.lineno),
                ))
    return out


# ---------------------------------------------------------------- MW007

def detect_mw007(tree, source, filename):
    lines = _source_lines(source)
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    out.append((
                        "MW007", node.lineno, node.col_offset,
                        "TLS certificate verification explicitly disabled (verify=False)",
                        _evidence(lines, node.lineno),
                    ))
            if _call_name(node) == "ssl._create_unverified_context":
                out.append((
                    "MW007", node.lineno, node.col_offset,
                    "Unverified SSL context created (certificate checks disabled)",
                    _evidence(lines, node.lineno),
                ))
        if isinstance(node, ast.Attribute) and node.attr == "CERT_NONE":
            out.append((
                "MW007", node.lineno, node.col_offset,
                "TLS verify mode set to CERT_NONE (no peer verification)",
                _evidence(lines, node.lineno),
            ))
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Attribute)
                    and target.attr == "check_hostname"
                    and isinstance(node.value, ast.Constant)
                    and node.value.value is False
                ):
                    out.append((
                        "MW007", node.lineno, node.col_offset,
                        "TLS hostname checking disabled on SSL context",
                        _evidence(lines, node.lineno),
                    ))
    return out


DETECTORS = {
    "MW001": detect_mw001,
    "MW002": detect_mw002,
    "MW003": detect_mw003,
    "MW004": detect_mw004,
    "MW005": detect_mw005,
    "MW006": detect_mw006,
    "MW007": detect_mw007,
}
