"""
DRAFT-watermark stripper for uploaded .docx templates.

Why this exists
---------------
Every VibeDocs-bundled report template — and most consultant-authored
custom templates — ships with a "DRAFT" diagonal watermark baked into
the header. When the renderer ALSO injects its own "DRAFT" watermark
(via `docx_generator._inject_watermark` whenever `is_draft=True`), the
final document ends up with two overlapping watermarks on every page,
which looks visibly broken (cf. the user-submitted screenshots showing
double "DRAFT" wordart stacked at slightly different angles).

Right answer: strip every PRE-EXISTING watermark at upload time so the
template starts watermark-free. Then on render the consultant gets
exactly one watermark (the renderer's), exactly where the renderer
intends it, and never sees a "ghost" from the source template.

What counts as a watermark
--------------------------
We treat any of the following inside a header part as a watermark and
remove it:

  * `<v:textpath ... string="DRAFT">` — the classic VML wordart shape,
    used by Word's built-in "Watermark → DRAFT" feature. We also match
    any case variant ("draft", "Draft", "DRAFT - Confidential", etc.)
    via a case-insensitive substring test.
  * `<v:shape ... id="DRAFT_WM" ... >` — our own renderer's stamp,
    matched by its known id so re-uploads don't accumulate copies.
  * `<mc:AlternateContent>` blocks whose descendants include a
    DrawingML text body containing "draft" (newer DrawingML-format
    watermarks Word 2010+ writes for the same feature).

For each match we walk up to the nearest enclosing `<w:sdt>` (Word
wraps native watermarks in a Structured Document Tag) and remove that
whole block. If there's no SDT ancestor we fall back to removing the
nearest `<w:p>` or `<mc:AlternateContent>` — whichever encloses the
shape first. Strip-paragraph is safe because real Word watermarks
ALWAYS live in their own paragraph; they're never inline with body
content.

Scope
-----
We only touch `word/header*.xml` parts. Body / footer / footnotes are
left alone — watermarks technically can be authored into the body or
footers, but doing so is highly unusual and the user's complaint is
specifically about header-anchored DRAFT marks repeating on every
page. If we ever see a body-anchored watermark complaint we can
broaden the file-pattern then.
"""
from __future__ import annotations
from pathlib import Path
import logging
import os
import shutil
import tempfile
import zipfile

from lxml import etree

log = logging.getLogger(__name__)


# Namespaces that participate in watermark XML. Keep these in sync with
# whatever Word writes — adding a new ns is cheap, removing one might
# leak a watermark variant past us.
_NS = {
    "w":  "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "v":  "urn:schemas-microsoft-com:vml",
    "mc": "http://schemas.openxmlformats.org/markup-compatibility/2006",
    "a":  "http://schemas.openxmlformats.org/drawingml/2006/main",
    "wps":"http://schemas.microsoft.com/office/word/2010/wordprocessingShape",
}

# Tokens we treat as "this is a draft watermark". Case-insensitive.
# Use substring match so "Draft", "DRAFT - Internal Only", "Sample Draft"
# all get caught. Keep this list short — false positives that strip
# legitimate header content are worse than the occasional missed
# watermark (which the user can manually delete).
_DRAFT_TOKENS = ("draft",)


def _contains_draft(s: str | None) -> bool:
    if not s:
        return False
    low = s.lower()
    return any(tok in low for tok in _DRAFT_TOKENS)


def _q(tag: str) -> str:
    """Resolve a `prefix:local` short tag to a Clark-notation qname."""
    prefix, _, local = tag.partition(":")
    return f"{{{_NS[prefix]}}}{local}"


def _nearest_ancestor(elem, qnames: tuple[str, ...]):
    """Walk up from `elem` and return the first ancestor whose tag is
    in `qnames`, or None if we reach the root first."""
    cur = elem.getparent()
    while cur is not None:
        if cur.tag in qnames:
            return cur
        cur = cur.getparent()
    return None


_SAFE_PARSER = etree.XMLParser(resolve_entities=False)


def _strip_header_xml(xml_bytes: bytes) -> tuple[bytes, int]:
    """Parse one header part, remove every DRAFT watermark we can find,
    serialise back. Returns ``(new_bytes, removed_count)``.

    If nothing matches, we return the original bytes verbatim — saves
    a re-serialisation pass and a zip-write that would have touched
    the mtime for no reason.
    """
    try:
        root = etree.fromstring(xml_bytes, _SAFE_PARSER)
    except Exception as e:
        log.warning("watermark stripper: skipping malformed header (%s)", e)
        return xml_bytes, 0

    removed = 0
    to_remove: list = []

    # 1. VML textpath wordart whose string attribute mentions "draft".
    for tp in root.iter(_q("v:textpath")):
        if _contains_draft(tp.get("string")):
            to_remove.append(tp)

    # 2. Our own renderer's tag — matched by id so we don't accidentally
    #    leave a stale copy from a previous render pass.
    for shape in root.iter(_q("v:shape")):
        if shape.get("id") == "DRAFT_WM":
            to_remove.append(shape)

    # 3. DrawingML text bodies (newer Word format) that contain a "draft"
    #    text run anywhere inside.
    for txbody in root.iter(_q("wps:txbx")):
        joined = "".join(t.text or "" for t in txbody.iter(_q("a:t")))
        if _contains_draft(joined):
            to_remove.append(txbody)

    # For each match, walk up to the nearest BIG container we can
    # safely drop. Order of preference:
    #   1. <w:sdt>  — Word's native watermark wrapper. Removing it
    #      drops the watermark cleanly with its bookkeeping.
    #   2. <mc:AlternateContent> — newer DrawingML watermark wrapper.
    #   3. <w:p>    — the paragraph holding the watermark shape.
    # We dedupe by element identity so a single paragraph that contains
    # multiple draft tokens doesn't get scheduled for removal twice
    # (lxml would still tolerate it, but it's cleaner this way).
    container_tags = (_q("w:sdt"), _q("mc:AlternateContent"), _q("w:p"))
    drop_set: set = set()
    drops: list = []
    for el in to_remove:
        ancestor = _nearest_ancestor(el, container_tags)
        if ancestor is None:
            # Last resort: drop the shape/pict itself.
            target = el
            # Walk up to the nearest <w:pict> so we delete the whole
            # picture, not just the text-effect runs.
            pict = _nearest_ancestor(el, (_q("w:pict"),))
            if pict is not None:
                target = pict
        else:
            target = ancestor
        if id(target) in drop_set:
            continue
        drop_set.add(id(target))
        drops.append(target)

    for target in drops:
        parent = target.getparent()
        if parent is not None:
            parent.remove(target)
            removed += 1

    if not removed:
        return xml_bytes, 0

    # Preserve original XML declaration when re-serialising; Word is
    # picky about the standalone attribute and the BOM.
    return (
        etree.tostring(
            root, xml_declaration=True, encoding="UTF-8", standalone=True
        ),
        removed,
    )


def strip_draft_watermarks(docx_path: Path) -> int:
    """Remove every recognisable DRAFT watermark from the headers in a
    .docx file, in place. Returns the total number of watermark
    elements removed.

    Idempotent — running it twice on the same file removes nothing the
    second time. Safe to call from any upload path; if the file has
    no watermarks, the work is a single zip read + XPath scan and
    completes in <10 ms for typical VibeDocs templates.

    Failure modes:
      * Malformed XML in a header → that header is left untouched and
        a warning is logged. Other headers are still processed.
      * I/O error during the atomic swap → the temp file is cleaned up
        and the original file is preserved. Caller can retry.
    """
    docx_path = Path(docx_path)
    if not docx_path.exists():
        raise FileNotFoundError(docx_path)

    patches: dict[str, bytes] = {}
    total_removed = 0

    with zipfile.ZipFile(docx_path, "r") as zf:
        for info in zf.infolist():
            name = info.filename
            if not name.startswith("word/header") or not name.endswith(".xml"):
                continue
            content = zf.read(name)
            new_content, n = _strip_header_xml(content)
            if n:
                patches[name] = new_content
                total_removed += n

    if total_removed == 0:
        return 0

    # Atomic re-zip via temp file so a failure mid-write never leaves
    # the user with a half-rewritten .docx.
    #
    # CRITICAL: the temp filename MUST be unique per call. The previous
    # implementation used a FIXED name (`X_template.wmstrip.tmp.docx`).
    # `gen_word_templates._regenerate_word_templates()` runs at module
    # import time, and uvicorn workers / autoreload import the module
    # concurrently — so two processes would regenerate the same
    # `X_template.docx` and BOTH create the same fixed temp path. One
    # process's `shutil.move` consumed/clobbered the other's temp
    # mid-write, raising `FileNotFoundError: ...wmstrip.tmp.docx`. The
    # strip then silently failed (caught by the caller), the VibeDocs
    # source's baked-in DRAFT survived, and the renderer stacked a
    # second DRAFT on top → the double-watermark the user reported on
    # every template except the one that happened to win the race.
    #
    # `tempfile.mkstemp` in the SAME directory gives a collision-proof
    # name AND keeps the final `os.replace` on one filesystem (atomic).
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{docx_path.stem}.wmstrip-", suffix=".docx",
        dir=str(docx_path.parent),
    )
    os.close(fd)            # we only needed the unique path; reopen via zipfile
    tmp = Path(tmp_name)
    try:
        with zipfile.ZipFile(docx_path, "r") as zin, \
             zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = patches.get(item.filename)
                if data is not None:
                    zout.writestr(item, data)
                else:
                    zout.writestr(item, zin.read(item.filename))
        # os.replace is atomic within a filesystem and overwrites the
        # destination in one syscall — no window where docx_path is
        # missing, so a concurrent reader/render never sees a partial.
        os.replace(str(tmp), str(docx_path))
    finally:
        # Clean up the tmp on any failure path. os.replace on success
        # already consumed it.
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass

    log.info("strip_draft_watermarks: removed %d watermark(s) from %s",
             total_removed, docx_path.name)
    return total_removed
