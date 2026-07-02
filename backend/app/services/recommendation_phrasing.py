"""Normalise finding remediation text so every recommendation reads as
"It is recommended to ...".

House style: a finding's Recommendations section should open with the phrase
"It is recommended to <verb> ...". Most library remediations are already written
in the imperative ("Validate uploaded files...", "Implement a strict CSP...",
"Disable directory listing..."), so the transform lower-cases that leading
imperative verb and prefixes the standard phrase, which reads grammatically:

    "Validate uploaded files using ..."
      -> "It is recommended to validate uploaded files using ..."

Edge cases handled:
  * Already starts with "It is recommended" (any case)  -> unchanged.
  * Starts with a bullet / dash list ("- Apply ...")    -> "It is recommended to
    apply the following measures:\n- Apply ...".
  * Starts with a non-verb / heading / code fence        -> "It is recommended to
    apply the following remediation:\n<original>".
  * Empty / whitespace-only                              -> unchanged.

Pure + idempotent: running it twice produces the same output.
"""
from __future__ import annotations

import re

_PREFIX = "It is recommended to "

# Common imperative verbs that open a remediation sentence. Lower-casing one of
# these and prefixing "It is recommended to " yields grammatical output. Kept
# broad — anything not here falls through to the safe "apply the following"
# wrapper so we never emit a broken sentence.
_IMPERATIVE_VERBS = {
    "validate", "implement", "ensure", "apply", "use", "set", "add", "remove",
    "disable", "enable", "configure", "restrict", "replace", "avoid", "update",
    "upgrade", "sanitise", "sanitize", "encode", "verify", "store", "rename",
    "prevent", "mark", "run", "mitigate", "review", "limit", "enforce",
    "require", "block", "patch", "harden", "rotate", "deploy", "adopt",
    "perform", "consider", "define", "establish", "introduce", "migrate",
    "redirect", "remediate", "reduce", "segment", "separate", "whitelist",
    "allowlist", "blocklist", "deny", "drop", "filter", "escape", "hash",
    "salt", "sign", "encrypt", "decrypt", "audit", "log", "monitor", "alert",
    "test", "scan", "rebuild", "refactor", "rewrite", "isolate", "lock",
    "unlock", "expire", "invalidate", "revoke", "issue", "generate", "install",
    "uninstall", "remediate", "address", "fix", "correct", "amend", "modify",
    "change", "adjust", "tighten", "strengthen", "minimise", "minimize",
    "maximise", "maximize", "wrap", "bind", "scope", "constrain", "cap",
    "throttle", "rate", "validate", "normalise", "normalize", "canonicalise",
    "canonicalize", "parameterise", "parameterize", "quote", "tag", "label",
    "classify", "document", "communicate", "notify", "educate", "train",
    "provide", "supply", "grant", "assign", "delegate", "centralise",
    "centralize", "standardise", "standardize", "automate", "schedule",
    "back", "backup", "snapshot", "archive", "purge", "delete", "clear",
    "reset", "restart", "reload", "reconfigure", "reinstall", "reimage",
}

# Verbs that need the final 'e' restored if we lower-case (none currently; the
# set above already holds lower-case base forms). Kept as a hook for clarity.


def _is_done(text: str) -> bool:
    return bool(re.match(r"(?is)^\s*it\s+is\s+recommended\b", text or ""))


def format_recommendation(text: str | None) -> str:
    """Return `text` rephrased to open with "It is recommended to ...".

    Returns the input unchanged when it is empty or already in the desired form.
    """
    if not text or not text.strip():
        return text or ""
    if _is_done(text):
        return text

    # Preserve any leading whitespace so we don't disturb indentation.
    stripped = text.lstrip()
    lead_ws = text[: len(text) - len(stripped)]

    # Bullet / dash / numbered list opener -> wrap as a lead-in.
    if re.match(r"^([-*•]|\d+[.)])\s", stripped):
        return f"{lead_ws}{_PREFIX}apply the following measures:\n{stripped}"

    # Code fence / heading / non-letter opener -> safe wrapper.
    first_word_match = re.match(r"^([A-Za-z][A-Za-z'-]*)(\b.*)$", stripped, re.S)
    if not first_word_match:
        return f"{lead_ws}{_PREFIX}apply the following remediation:\n{stripped}"

    first, rest = first_word_match.group(1), first_word_match.group(2)
    if first.lower() in _IMPERATIVE_VERBS:
        # Grammatical: "It is recommended to <verb> <rest>".
        return f"{lead_ws}{_PREFIX}{first.lower()}{rest}"

    # Non-imperative opener (e.g. "The application should...", "Cookies must...").
    # Wrap rather than risk a broken sentence.
    return f"{lead_ws}{_PREFIX}apply the following remediation:\n{stripped}"
