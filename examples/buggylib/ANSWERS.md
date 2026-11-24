# buggylib answer key

`buggylib` is a demo target with planted bugs. The source has no hints, so the
LLM has to find them the way it would in a real library. Don't add hint
comments to the source.

| Function | Planted bug |
|---|---|
| `parse_duration` | A trailing number without a unit is silently dropped: `"1h5"` gives 3600. |
| `parse_kv` | `part.split("=")` raises `ValueError` on `"a"` or `"a=b=c"` instead of `ParseError`. |
| `escape` / `unescape` | The backslash itself isn't escaped, so the round-trip breaks: `unescape(escape("\\a")) == "a"` (the input is backslash + `a`). |
| `decode_rle` | A zero count never advances `i`, so the loop never ends (`b"\x00\x00"`). |
| `parse_nested` | `IndexError` on unterminated input such as `"[1,"`. |

Found by fuzzwright that I didn't plant: `str.isdigit()` is true for characters
like `"²"`, and `int()` then rejects them, so `parse_duration` and
`parse_nested` raise `ValueError` instead of `ParseError`.
