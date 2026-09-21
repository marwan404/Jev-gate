# Jev Gate

A tiny defensive project that uses TypeSafe Jev as a **judgment layer** in front of deterministic Python policy.

The program takes a shell command and asks Jev four questions at once:

- What category is it?
- How risky is it (0–4)?
- Is it straightforwardly reversible?
- Should human confirmation be required?

Python then applies the local policy. Jev does **not** execute the command.

## Setup

Requires Python 3.10+.

```powershell
uv sync
Copy-Item .env.example .env
```

Put your API key in `.env`:

```text
TYPESAFE_API_KEY=your_key_here
```

## Run

```powershell
uv run jev-gate "dir"
uv run jev-gate "python --version"
uv run jev-gate "git status"
uv run jev-gate "rm -rf ./build"
```

On Windows, pass a command as one quoted argument so the program receives the whole command string.

## Why this is cool

Traditional code can easily answer rules like:

```python
if command.startswith("rm"):
    block()
```

But real commands and natural-language intent are messy. Jev handles the fuzzy classification; ordinary Python stays responsible for the actual security policy.

This is intentionally a classifier/gate, not a command executor.
