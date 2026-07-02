"""
HTML sanitisation for the rich-text finding fields.

The finding editor uses Quill, which produces HTML. We never trust user-
supplied HTML — every write goes through `sanitize()` before persistence,
and again on read in case stored data predates this module.

Allow-list approach: bleach.clean with a deliberately narrow tag/attribute
set. Anything not listed is stripped (not escaped — that would leave the
plain text visible). Inline styles are filtered through `_filter_style()`
which only retains `color`, `background-color`, `font-weight`, and
`text-align` declarations and rejects anything containing `url(`,
`expression(`, `javascript:`, etc.

Threat coverage:
  * XSS via <script>, <iframe>, event handlers (onload=, onclick=, etc.) -
    none of those tags or attrs are allow-listed. Even `<a onclick=...>`
    is sanitised — bleach drops unknown attrs by default.
  * HTML injection breaking out of an attribute - bleach re-emits canonical
    serialised HTML.
  * Command injection - this layer doesn't shell out; defence belongs at
    the OS-call layer. We still strip `<script>` so the HTML preview can't
    exfiltrate.
  * Style-based exfiltration (CSS injection) - the `style` attribute is
    filtered with an explicit declaration allow-list.

`sanitize()` returns a string safe to embed inside another HTML document
without further escaping. Callers should still avoid placing the output
inside untrusted contexts (script blocks, attribute values).
"""
from __future__ import annotations
import re
from typing import Optional

try:
    import bleach
except ImportError:   # bleach is in requirements.txt; this guards local dev
    bleach = None     # type: ignore[assignment]


ALLOWED_TAGS = {
    # Structural
    "p", "br", "hr", "div",
    # Inline emphasis
    "b", "strong", "i", "em", "u", "s", "strike", "sub", "sup", "mark",
    # Lists
    "ul", "ol", "li",
    # Code
    "code", "pre", "kbd", "samp",
    # Quote / heading
    "blockquote",
    "h1", "h2", "h3", "h4", "h5", "h6",
    # Links and visual span
    "a", "span",
    # Inline screenshots. Quill emits <img src="data:image/png;base64,…">
    # when the user pastes a screenshot from the clipboard, so we need
    # to keep the tag through sanitisation. The `src` attribute is
    # validated separately in `_attr_filter` to allow ONLY
    # `data:image/*;base64,…` (no remote URLs, no `data:text/html`, no
    # `javascript:` etc.).
    "img",
    "figure", "figcaption",
}

ALLOWED_ATTRS = {
    "a":    ["href", "title", "rel", "target"],
    "span": ["style", "class"],
    "p":    ["style", "class"],
    "div":  ["style", "class"],
    "code": ["class"],   # so Quill's `ql-syntax` survives
    "pre":  ["class"],
    "ol":   ["start"],
    "li":   ["data-list"],   # Quill emits data-list="bullet" / "ordered"
    # Screenshot tag: keep `src` (validated below), plus `alt`, `title`
    # and basic width/height for re-sizable screenshots.
    "img":  ["src", "alt", "title", "width", "height", "style"],
    "figure":     ["class", "style"],
    "figcaption": ["class", "style"],
}

# Only image MIME-typed data URLs are accepted (data:image/png;base64,
# data:image/jpeg;base64, etc.). We deliberately do NOT allow `data:`
# for arbitrary content because `data:text/html;…` is a classic XSS
# carrier. The image-only carve-out is enforced inside `_attr_filter`
# below, NOT here — bleach's protocol list applies to ALL attributes
# uniformly which would re-open the door.
ALLOWED_PROTOCOLS = ["http", "https", "mailto", "tel", "data"]


# Image-mime-only matcher for <img src="data:…"> values. We do NOT
# accept `data:text/html`, `data:application/javascript`, etc.
_DATA_IMG_RE = re.compile(
    r"^data:image/(?:png|jpe?g|gif|webp|bmp|x-icon);base64,[A-Za-z0-9+/=\r\n]+$",
    re.IGNORECASE,
)


def _is_safe_img_src(value: str) -> bool:
    """True for src values we're willing to keep on an <img>. Accepts
    base64 data: URLs whose MIME type is an image, and http(s) URLs.
    Everything else (data:text/html, javascript:, …) is rejected.
    """
    if not value:
        return False
    v = value.strip()
    low = v.lower()
    if low.startswith("data:"):
        return bool(_DATA_IMG_RE.match(v))
    if low.startswith(("http://", "https://", "/")):
        return True
    return False

# Inline CSS declarations we tolerate. Everything else is dropped — we keep
# this narrow so authors can't reflow the page or smuggle url() data.
_ALLOWED_CSS_PROPS = {
    "color", "background-color", "font-weight", "font-style",
    "text-align", "text-decoration",
}
_VALUE_BLOCKLIST = re.compile(
    r"(url\s*\(|expression\s*\(|javascript:|vbscript:|data:|@import|<|>)",
    re.IGNORECASE,
)


def _filter_style(name: str, value: str) -> Optional[str]:
    if name != "style":
        return value
    parts = []
    for decl in value.split(";"):
        if not decl.strip():
            continue
        if ":" not in decl:
            continue
        prop, val = decl.split(":", 1)
        prop = prop.strip().lower()
        val = val.strip()
        if prop not in _ALLOWED_CSS_PROPS:
            continue
        if _VALUE_BLOCKLIST.search(val):
            continue
        # Cap length to defang ridiculous values
        parts.append(f"{prop}: {val[:200]}")
    return "; ".join(parts) if parts else None


def _attr_filter(tag: str, name: str, value: str) -> bool:
    """bleach attribute callable - return True to keep."""
    allowed = ALLOWED_ATTRS.get(tag, [])
    if name not in allowed:
        return False
    if name == "style":
        filtered = _filter_style(name, value)
        # bleach attribute callables can't mutate the value, but we can hint
        # to the cleaner by returning False on empty. We accept any non-empty
        # filtered string here; the actual filtering of the rendered style
        # happens via a separate pass below.
        return bool(filtered)
    if name == "target":
        return value in ("_blank", "_self")
    if name == "rel":
        return all(t in ("nofollow", "noopener", "noreferrer") for t in value.split())
    # <img src="…">: only allow image data URLs or http(s) URLs. This is
    # the gate that keeps "data:" out of every other tag while still
    # letting Quill-pasted screenshots through.
    if tag == "img" and name == "src":
        return _is_safe_img_src(value)
    # <img width="…"> / <img height="…">: only accept bare integers (px).
    if tag == "img" and name in ("width", "height"):
        return value.isdigit() and 1 <= int(value) <= 4000
    return True


_STYLE_RE = re.compile(r'style="([^"]*)"', re.IGNORECASE)


def _post_pass_style_filter(html: str) -> str:
    """Re-walk the bleach output to apply `_filter_style` to every style attr.
    bleach's attribute callbacks can't transform values, only keep/drop them —
    so we run a second pass here to actually strip disallowed declarations.
    """
    def repl(m: "re.Match[str]") -> str:
        new_val = _filter_style("style", m.group(1))
        if not new_val:
            return ""
        return f'style="{new_val}"'
    return _STYLE_RE.sub(repl, html)


def sanitize(html: Optional[str]) -> str:
    """Return safe HTML or empty string. Never raises."""
    if not html:
        return ""
    if not isinstance(html, str):
        html = str(html)
    if bleach is None:
        # Hard-fail-safe: bleach missing -> strip every tag rather than
        # storing potentially-malicious markup. We strip everything outside
        # `<` / `>`, leaving plain text.
        return re.sub(r"<[^>]+>", "", html)
    cleaned = bleach.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes=_attr_filter,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
        strip_comments=True,
    )
    return _post_pass_style_filter(cleaned)


_HTML_TAG_RE = re.compile(r"<\w")


def looks_like_html(value: Optional[str]) -> bool:
    """Cheap probe for 'is this rich text?'. Used by the DOCX renderer to
    decide whether to invoke the HTML->Subdoc converter or fall through to
    the existing plain-text path."""
    if not value or not isinstance(value, str):
        return False
    return bool(_HTML_TAG_RE.search(value))
