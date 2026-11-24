"""Static analysis: find functions in a Python package that are worth fuzzing.

We look for entry points that take untrusted-looking input (text, bytes, buffers)
and do something interesting with it (parse, decode, load, unpack...). The score
is a cheap heuristic; the LLM makes the final pick.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

HOT_WORDS = {
    "parse": 5, "load": 4, "loads": 5, "decode": 5, "deserialize": 5, "unpack": 5,
    "unmarshal": 5, "read": 3, "from": 3, "tokenize": 4, "lex": 4, "scan": 2,
    "unescape": 4, "unquote": 4, "split": 2, "convert": 2, "normalize": 3,
    "eval": 3, "compile": 3, "render": 2, "format": 1, "extract": 3, "validate": 2,
    "expand": 3, "inflate": 4, "decompress": 5, "base64": 3, "url": 2, "json": 3,
    "xml": 3, "html": 3, "csv": 3, "yaml": 3, "toml": 3, "ini": 2, "date": 2,
    "time": 1, "version": 2, "path": 1, "query": 2, "header": 3, "cookie": 3,
}
INPUT_PARAMS = {
    "data", "text", "s", "string", "buf", "buffer", "source", "src", "content",
    "raw", "line", "lines", "payload", "blob", "stream", "value", "input", "expr",
    "expression", "markup", "doc", "document", "b", "fp", "url", "query", "header",
}
INPUT_ANNOTATIONS = {"str", "bytes", "bytearray", "memoryview", "AnyStr", "Buffer"}
SKIP_DIRS = {"tests", "test", "testing", "_vendor", "vendor", "docs", "examples", "benchmarks"}


@dataclass
class Candidate:
    module: str            # importable dotted path, e.g. "pkg.sub"
    qualname: str          # "func" or "Class.method"
    signature: str
    docstring: str
    source: str
    file: str
    lineno: int
    score: float
    helpers: dict[str, str] = field(default_factory=dict)  # same-module helpers it calls

    @property
    def target_id(self) -> str:
        return f"{self.module}:{self.qualname}"


def _module_name(pkg_root: Path, file: Path) -> str:
    rel = file.relative_to(pkg_root.parent).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _signature(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    return f"def {fn.name}({ast.unparse(fn.args)})" + (
        f" -> {ast.unparse(fn.returns)}" if fn.returns else ""
    )


def _score(fn: ast.FunctionDef | ast.AsyncFunctionDef, is_method: bool) -> float:
    name = fn.name.lower()
    score = 0.0
    for word, w in HOT_WORDS.items():
        if word in name.split("_") or name.startswith(word):
            score += w
    args = [a for a in fn.args.posonlyargs + fn.args.args if a.arg not in ("self", "cls")]
    if not args:
        return -1  # nothing to feed it
    for a in args[:2]:
        if a.arg.lower() in INPUT_PARAMS:
            score += 3
        if a.annotation is not None and any(
            t in ast.unparse(a.annotation) for t in INPUT_ANNOTATIONS
        ):
            score += 3
    if len(args) > 5:
        score -= 2
    if ast.get_docstring(fn):
        score += 1
    # bigger bodies have more room for bugs, up to a point
    score += min(len(fn.body), 30) / 10
    if is_method and not any(
        isinstance(d, ast.Name) and d.id in ("classmethod", "staticmethod")
        for d in fn.decorator_list
    ):
        score -= 2  # needs an instance; harder to harness
    return score


def _called_names(fn: ast.AST) -> set[str]:
    out = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            out.add(node.func.id)
    return out


def find_package_root(target: Path) -> Path:
    """Accept a package dir, a module file, or a project dir containing src/<pkg> or <pkg>."""
    target = target.resolve()
    if target.is_file():
        return target
    if (target / "__init__.py").exists():
        return target
    for base in (target / "src", target):
        if base.is_dir():
            pkgs = [p for p in base.iterdir() if (p / "__init__.py").exists() and p.name not in SKIP_DIRS]
            if len(pkgs) == 1:
                return pkgs[0]
            if len(pkgs) > 1:
                names = ", ".join(sorted(p.name for p in pkgs))
                raise SystemExit(f"Several packages under {base}: {names}. Point at one of them.")
    raise SystemExit(f"No Python package found at {target}")


def scan(target: Path, limit: int = 40) -> list[Candidate]:
    root = find_package_root(target)
    files = [root] if root.is_file() else [
        f for f in root.rglob("*.py")
        if not any(part in SKIP_DIRS or part.startswith(".") for part in f.relative_to(root).parts[:-1])
    ]
    cands: list[Candidate] = []
    for f in files:
        try:
            src = f.read_text(encoding="utf-8")
            tree = ast.parse(src)
        except (SyntaxError, UnicodeDecodeError):
            continue
        module = f.stem if root.is_file() else _module_name(root, f)
        if any(p.startswith("_") and p != "__init__" for p in module.split(".")[1:]):
            privmod = True
        else:
            privmod = False
        top_funcs = {
            n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

        def add(fn, qual, is_method):
            if fn.name.startswith("_") or isinstance(fn, ast.AsyncFunctionDef):
                return
            s = _score(fn, is_method) - (2 if privmod else 0)
            if s <= 0:
                return
            helpers = {
                name: ast.get_source_segment(src, top_funcs[name]) or ""
                for name in sorted(_called_names(fn))
                if name in top_funcs and name != fn.name
            }
            cands.append(Candidate(
                module=module, qualname=qual, signature=_signature(fn),
                docstring=ast.get_docstring(fn) or "",
                source=ast.get_source_segment(src, fn) or "",
                file=str(f), lineno=fn.lineno, score=round(s, 2), helpers=helpers,
            ))

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                add(node, node.name, False)
            elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
                for sub in node.body:
                    if isinstance(sub, ast.FunctionDef):
                        add(sub, f"{node.name}.{sub.name}", True)
    cands.sort(key=lambda c: c.score, reverse=True)
    return cands[:limit]


def import_root(target: Path) -> Path:
    """Directory that must be on sys.path for the package to import."""
    root = find_package_root(target)
    return root.parent
