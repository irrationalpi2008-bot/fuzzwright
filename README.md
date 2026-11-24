# fuzzwright

**Point it at a Python package. It reads the code, writes fuzz harnesses, runs them in a sandbox, and gives you bug reports with verified repros.**

```bash
uvx --from git+https://github.com/irrationalpi2008-bot/fuzzwright fuzzwright hunt ./my-package
```

> Early alpha. Not on PyPI yet; install from GitHub as shown.

Illustrative output:

```
scan 31 candidate entry points in mylib
  → mylib.config:parse_duration   hand-rolled tokenizer, trailing-input handling looks fragile
  → mylib.codec:decode_rle        loop index depends on decoded data
──────────────────────── mylib.codec:decode_rle ────────────────────────
  ✗ Hang at check  input=b'\x00\x00'
    bug/high: Infinite loop when a run has count 0 (repro: hung)
──────────────────────── mylib.config:parse_duration ───────────────────
  ✗ AssertionError at harness.py:check  input='0h0'
    bug/medium: Trailing number without unit is silently dropped (repro: raised)
────────────────────────────────────────────────────────────────────────
2 likely bug(s), 2 unique failure(s) in 94s for ~$0.31
report: fuzzwright-out/REPORT.md
```

<!-- TODO: replace the block above with a GIF recorded with `vhs` or asciinema -->

## Why

Fuzzing finds real bugs, but almost nobody does it. Writing a good harness means
understanding the input format, building a generator that gets past the first
`if`, and deciding which exceptions count as bugs. That takes an expert an
afternoon per function.

fuzzwright gives that afternoon to an LLM:

1. **Scan.** It parses your package with `ast` and ranks public functions that take outside input: parsers, decoders, loaders and converters.
2. **Pick.** Claude reads the shortlist and chooses the functions most likely to break.
3. **Write a harness.** For each function, Claude reads the source and writes a [Hypothesis](https://hypothesis.works) harness. The generator follows the input's grammar (the delimiters, escapes and nesting the parser expects) and also feeds raw noise. The harness can also `assert` properties the code promises, such as round-trips, so it catches wrong answers as well as crashes.
4. **Fuzz.** It runs the harness thousands of times in a sandbox, with per-call hang detection. Hypothesis shrinks each failing input down to a minimal one, and later rounds skip bugs already found so they can't hide deeper ones.
5. **Fix the harness.** If the harness itself is broken, Claude gets the error and fixes it, up to 3 attempts.
6. **Triage.** Claude labels each unique crash `bug`, `likely_bug`, `expected_behavior` or `harness_artifact`, gives a severity, explains the root cause and suggests a fix.
7. **Verify.** The repro script Claude wrote is run again in the sandbox, and the report shows whether it actually reproduced the failure.

## What it catches

| Failure | Example |
|---|---|
| Undocumented exceptions | `IndexError` escaping a parser that promises `ParseError` |
| Hangs | a zero-length run in an RLE decoder makes the loop spin forever |
| Broken contracts | `unescape(escape(s)) != s` |
| Silent wrong answers | `"1h5"` parsed as 3600 seconds |
| Resource exhaustion | `RecursionError`, `MemoryError` from deep nesting |
| Native crashes | segfaults in C extensions (it records the input before each call) |

## Install

```bash
uv tool install git+https://github.com/irrationalpi2008-bot/fuzzwright
export ANTHROPIC_API_KEY=...      # or: ant auth login
```

The target package must be importable by the Python that runs fuzzwright. The
simplest way is to run fuzzwright from inside the project's environment:

```bash
cd my-package && uv run --with git+https://github.com/irrationalpi2008-bot/fuzzwright fuzzwright hunt .
```

## Usage

```bash
fuzzwright hunt <path>            # full pipeline
fuzzwright hunt <path> -n 10 --examples 5000 --effort xhigh
fuzzwright scan <path>            # see what it would target (no API calls)
fuzzwright run harness.py --target <path>   # run your own harness (no API calls)
```

Results go to `fuzzwright-out/`:

```
REPORT.md            summary table
findings/01-*.md     one file per bug: minimal input, root cause, repro, suggested fix, traceback
findings.json        machine-readable results
targets/*/harness.py the generated harnesses, which you can keep as regression tests
```

The exit code is `1` when likely bugs are found, so you can use it in CI.

Try it on the bundled demo library, which has five planted bugs:

```bash
uv run fuzzwright hunt examples/buggylib
```

## Safety

fuzzwright runs code written by an LLM against code you may not trust, so every harness runs isolated:

- **bubblewrap** (Linux, used automatically when present): read-only filesystem, no network, private `/tmp` and PID namespace.
- **Always:** environment variables that look like secrets (`*KEY*`, `*TOKEN*`, `*SECRET*`...) are removed, and memory, CPU and wall-clock limits apply.

On macOS or Windows, or without bubblewrap, run it inside a container.

## Responsible disclosure

The verdicts come from an LLM. Confirm each one by hand before filing it. If a
finding might be a security issue in someone else's project, report it
privately through the project's `SECURITY.md` or the GitHub security advisory
form, not in a public issue.

## Cost

A 5-target hunt typically makes 10–20 calls. The report prints the exact cost.
Use `--model claude-sonnet-5-5` or `--effort medium` to make it cheaper.

## Roadmap

- [ ] Coverage feedback: send uncovered branches back to Claude to improve the harness
- [ ] Coverage-guided engine (Atheris) next to Hypothesis
- [ ] C/C++ via libFuzzer, Rust via cargo-fuzz, Go native fuzzing
- [ ] GitHub Action: fuzz the functions changed in each PR
- [ ] Export each finding as a ready-made pytest regression test
- [ ] Public "bugs found" hall of fame

## Development

```bash
uv sync
uv run pytest            # offline: uses a scripted stand-in for the LLM
```

## License

MIT
