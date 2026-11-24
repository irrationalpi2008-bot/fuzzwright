"""buggylib: small text and byte parsers."""


class ParseError(ValueError):
    """Raised for malformed input."""


UNITS = {"h": 3600, "m": 60, "s": 1}


def parse_duration(text: str) -> int:
    """Parse '1h30m', '45s', '2h' into seconds. Raises ParseError on bad input."""
    if not text:
        raise ParseError("empty")
    total, num = 0, ""
    for i, ch in enumerate(text):
        if ch.isdigit():
            num += ch
        elif ch in UNITS:
            if not num:
                raise ParseError(f"unit without number at {i}")
            total += int(num) * UNITS[ch]
            num = ""
        else:
            raise ParseError(f"bad char {ch!r}")
    return total


def parse_kv(text: str) -> dict[str, str]:
    """Parse 'a=1;b=2' into a dict. Raises ParseError on bad input."""
    out = {}
    for part in text.split(";"):
        if not part:
            continue
        key, value = part.split("=")
        out[key.strip()] = value.strip()
    return out


def escape(s: str) -> str:
    """Escape ';' and '=' so the result is safe inside parse_kv values."""
    return s.replace(";", "\\;").replace("=", "\\=")


def unescape(s: str) -> str:
    """Inverse of escape()."""
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            out.append(s[i + 1])
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def decode_rle(data: bytes) -> bytes:
    """Decode run-length pairs (count, byte). Raises ParseError on odd length."""
    if len(data) % 2:
        raise ParseError("odd length")
    out = bytearray()
    i = 0
    while i < len(data):
        count, byte = data[i], data[i + 1]
        out += bytes([byte]) * count
        i += count and 2
    return bytes(out)


def parse_nested(text: str):
    """Parse nested lists like '[1,[2,3]]'. Raises ParseError on bad input."""
    pos = 0

    def value():
        nonlocal pos
        if pos >= len(text):
            raise ParseError("eof")
        if text[pos] == "[":
            pos += 1
            items = []
            while text[pos] != "]":
                items.append(value())
                if text[pos] == ",":
                    pos += 1
            pos += 1
            return items
        start = pos
        while pos < len(text) and text[pos].isdigit():
            pos += 1
        if start == pos:
            raise ParseError(f"unexpected {text[pos]!r}")
        return int(text[start:pos])

    result = value()
    if pos != len(text):
        raise ParseError("trailing data")
    return result
