"""
DOCX generation using docxtpl (Jinja2 inside Word).

How it works
------------
The VibeDocs Word template carries Jinja2 placeholders directly inside the document.
Examples of placeholders you can drop into the .docx:

    {{ project.client_name }}
    {{ project.testing_window }}
    {{ details.executive_summary }}

    Findings table (Jinja loop using docxtpl's {%tr ... %} / {%tc ... %} syntax):

      | # | Title | Severity | CVSS | Status |
      | {%tr for f in findings %} |
      | {{ loop.index }} | {{ f.title }} | {{ f.severity }} | {{ f.cvss_score }} | {{ f.status }} |
      | {%tr endfor %} |

    Per-finding detail block (Jinja paragraph loop using {%p ... %}):

      {%p for f in findings %}
      Finding {{ loop.index }}: {{ f.title }}
      Severity: {{ f.severity }} ({{ f.cvss_score }})
      Affected: {{ f.affected_asset }}
      Description: {{ f.description }}
      Impact: {{ f.impact }}
      Remediation: {{ f.remediation }}
      Status: {{ f.status }}
      Retest notes: {{ f.retest_notes }}
      {% for img in f.screenshot_objs %}
      {{ img }}
      {% endfor %}
      {%p endfor %}

After rendering, if `is_draft=True`, we inject a draft watermark into the document headers
by stamping a WordArt-style text shape into header1.xml.

The Nmap "Discovered Services" table is rendered as a docxtpl table loop too:

      | Host | Hostname | Port | Proto | Service | Product | Version |
      | {%tr for r in nmap_rows %} |
      | {{ r.host }} | {{ r.hostname }} | {{ r.port }} | {{ r.protocol }} | {{ r.service }} | {{ r.product }} | {{ r.version }} |
      | {%tr endfor %} |

If a placeholder is missing the renderer just leaves it blank rather than crashing.
"""
from __future__ import annotations
import os
import shutil
import subprocess
import zipfile
import re
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Any
import tempfile

from docxtpl import DocxTemplate, InlineImage
from docx.shared import Mm, Cm

# Every screenshot (uploaded, inline-pasted, retest) renders at this fixed
# width and is centred. ~18.47 cm == the full content width of an A4 page with
# the VibeDocs template's 0.5" margins. Tall images that would overflow the
# page height fall back to a height-bound size instead.
SCREENSHOT_WIDTH_CM = 18.46
SCREENSHOT_MAX_H_MM = 230
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

from ..config import settings


# ---- Image format normalisation ----
# python-docx does not support WebP. Any WebP screenshot must be
# converted to PNG before being wrapped in InlineImage. The converted
# file lands in the system tmp directory and is NOT cleaned up during
# the same process run — it persists only until the next OS tmp-purge
# (acceptable; each render is rare and files are <a few MB).
_SUPPORTED_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".tiff", ".tif", ".bmp", ".wmf"}


def _ensure_supported_image(path_str: str) -> str:
    """Return a supported image path. Converts WebP → PNG via Pillow if needed.
    Returns the original path unchanged for all other formats."""
    p = Path(path_str)
    if p.suffix.lower() in _SUPPORTED_EXTS:
        return path_str
    try:
        from PIL import Image as _PILImage
        out_path = Path(tempfile.gettempdir()) / (p.stem + "_converted.png")
        with _PILImage.open(p) as img:
            img.convert("RGB").save(out_path, "PNG")
        return str(out_path)
    except Exception:
        # If conversion fails, return original and let docxtpl raise a
        # clear error rather than a confusing one.
        return path_str


_HTML_IMG_RE = re.compile(r'<img\b', re.IGNORECASE)
_SCREENSHOT_TOKEN_RE = re.compile(r'\[Screenshot\s+\d+\]', re.IGNORECASE)


def _count_html_images(html_text: str) -> int:
    """Count <img> tags and [Screenshot N] tokens in an HTML string."""
    return (len(_HTML_IMG_RE.findall(html_text or ""))
            + len(_SCREENSHOT_TOKEN_RE.findall(html_text or "")))


def _sized_image(tpl: "DocxTemplate", path_str: str,
                 max_w_mm: float | None = None,
                 max_h_mm: float = SCREENSHOT_MAX_H_MM) -> "InlineImage":
    """Create an InlineImage at the fixed screenshot width (SCREENSHOT_WIDTH_CM),
    preserving aspect ratio. If that would make the image taller than max_h_mm
    (page height), bind to height instead so it never overflows the page."""
    supported = _ensure_supported_image(path_str)
    w_cm = SCREENSHOT_WIDTH_CM
    try:
        from PIL import Image as _PILImage
        with _PILImage.open(supported) as img:
            w_px, h_px = img.size
        h_at_full_w_mm = (h_px / w_px) * (w_cm * 10.0) if w_px else 0
        if h_at_full_w_mm and h_at_full_w_mm > max_h_mm:
            return InlineImage(tpl, supported, height=Mm(max_h_mm))
        return InlineImage(tpl, supported, width=Cm(w_cm))
    except Exception:
        return InlineImage(tpl, supported, width=Cm(w_cm))


# Detailed-findings chapter number. Findings render as 3.1, 3.2, ... so each
# finding's screenshots are captioned "Figure 3.<finding>-<n>". Centralised
# so it's a one-line change if a template ever moves detailed findings.
DETAILED_FINDINGS_CHAPTER = 3


def _add_image_with_caption(sd, path_str: str, label: str, caption_text: str = "",
                            max_h_mm: float = SCREENSHOT_MAX_H_MM) -> None:
    """Append a fixed-width (SCREENSHOT_WIDTH_CM), centred image + caption
    paragraph 'Figure <label>[: caption]' to an existing Subdoc `sd`. Caption
    font styling (Verdana 8pt grey) is applied later by the centring pass.
    """
    from docx.enum.text import WD_ALIGN_PARAGRAPH as _WD
    supported = _ensure_supported_image(path_str)
    img_para = sd.add_paragraph()
    img_para.alignment = _WD.CENTER
    run = img_para.add_run()
    w_cm = SCREENSHOT_WIDTH_CM
    try:
        from PIL import Image as _PILImage
        with _PILImage.open(supported) as _img:
            w_px, h_px = _img.size
        h_at_full_w_mm = (h_px / w_px) * (w_cm * 10.0) if w_px else 0
        if h_at_full_w_mm and h_at_full_w_mm > max_h_mm:
            run.add_picture(supported, height=Mm(max_h_mm))
        else:
            run.add_picture(supported, width=Cm(w_cm))
    except Exception:
        try:
            run.add_picture(supported, width=Cm(w_cm))
        except Exception:                                   # pragma: no cover
            pass
    cap = f"Figure {label}"
    if caption_text and caption_text.strip():
        cap += f": {caption_text.strip()}"
    try:
        cap_p = sd.add_paragraph(cap, style="Caption")
    except Exception:
        cap_p = sd.add_paragraph()
        cap_p.add_run(cap).italic = True
    cap_p.alignment = _WD.CENTER


def _image_caption_subdoc(tpl: "DocxTemplate", path_str: str, label: str,
                          caption_text: str = ""):
    """One image + caption as its OWN Subdoc — for templates that loop
    `{% for img in f.screenshot_objs %}{{ img }}{% endfor %}`."""
    sd = tpl.new_subdoc()
    _add_image_with_caption(sd, path_str, label, caption_text)
    return sd


def _images_caption_subdoc(tpl: "DocxTemplate", items: list[tuple]):
    """All images + captions in a SINGLE Subdoc — for templates that render
    the group with a bare `{{ f.retest_objs }}` (no loop). `items` is a list
    of (path, label, caption_text). Returns "" when empty so the placeholder
    renders nothing.
    """
    if not items:
        return ""
    sd = tpl.new_subdoc()
    for path_str, label, caption_text in items:
        _add_image_with_caption(sd, path_str, label, caption_text)
    return sd


# ---- Watermark XML stamped into headers when is_draft=True ----

_WATERMARK_XML = """
<w:p xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
     xmlns:v="urn:schemas-microsoft-com:vml"
     xmlns:o="urn:schemas-microsoft-com:office:office"
     xmlns:w10="urn:schemas-microsoft-com:office:word">
  <w:r>
    <w:rPr><w:noProof/></w:rPr>
    <w:pict>
      <v:shapetype id="_x0000_t136" coordsize="21600,21600" o:spt="136" adj="10800"
                   path="m@7,l@8,m@5,21600l@6,21600e">
        <v:formulas>
          <v:f eqn="sum #0 0 10800"/>
          <v:f eqn="prod #0 2 1"/>
          <v:f eqn="sum 21600 0 @1"/>
          <v:f eqn="sum 0 0 @2"/>
          <v:f eqn="sum 21600 0 @3"/>
          <v:f eqn="if @0 @3 0"/>
          <v:f eqn="if @0 21600 @1"/>
          <v:f eqn="if @0 0 @2"/>
          <v:f eqn="if @0 @4 21600"/>
          <v:f eqn="mid @5 @6"/>
          <v:f eqn="mid @8 @5"/>
          <v:f eqn="mid @7 @8"/>
          <v:f eqn="mid @6 @7"/>
          <v:f eqn="sum @6 0 @5"/>
        </v:formulas>
        <v:path o:extrusionok="f" gradientshapeok="t" o:connecttype="custom"
                o:connectlocs="@9,0;@10,10800;@11,21600;@12,10800"
                o:connectangles="270,180,90,0" textpathok="t"/>
        <v:textpath on="t" fitshape="t"/>
      </v:shapetype>
      <v:shape id="DRAFT_WM" type="#_x0000_t136" style="position:absolute;
        margin-left:0;margin-top:0;width:500pt;height:120pt;rotation:-30;
        z-index:-251658240;mso-position-horizontal:center;mso-position-vertical:center;
        mso-position-horizontal-relative:margin;mso-position-vertical-relative:margin"
        fillcolor="#999999" stroked="f">
        <v:fill opacity=".25"/>
        <v:textpath style="font-family:&quot;Arial&quot;;font-size:1pt" string="DRAFT"/>
      </v:shape>
    </w:pict>
  </w:r>
</w:p>
""".strip()


_TAG_RE = re.compile(r"\{[%{][^}%]*[%}]\}")           # complete tag in one text node
_TAG_OPEN_RE = re.compile(r"\{[%{]")                   # tag opener {{ or {%

# Both {%tr for %} and {%tr endfor %} living in the same <w:tr> row defeats
# docxtpl's preprocessor — its greedy regex collapses the row to whichever tag
# comes LAST (always the endfor), silently dropping the for and producing an
# "Encountered unknown tag 'endfor'" Jinja error at render time. We detect the
# pattern in our own preprocessor and split the row into three: a for-only
# row, the original data row with both tags stripped, then an endfor-only row.
_TR_RE = re.compile(r"<w:tr\b[^>]*>(?:(?!<w:tr\b).)*?</w:tr>", re.DOTALL)
_INNER_FOR_RE  = re.compile(r"\{%\s*tr\s+for\s+[^}%]*%\}")
_INNER_ENDFOR_RE = re.compile(r"\{%\s*tr\s+endfor\s*%\}")
# Same problem can hit paragraph loops if a consultant edits a {%p for %} +
# {%p endfor %} into the same paragraph by mistake. Cover it for symmetry.
_P_RE = re.compile(r"<w:p\b[^>]*>(?:(?!<w:p\b).)*?</w:p>", re.DOTALL)
_INNER_P_FOR_RE  = re.compile(r"\{%\s*p\s+for\s+[^}%]*%\}")
_INNER_P_ENDFOR_RE = re.compile(r"\{%\s*p\s+endfor\s*%\}")


_RAW_OPEN_RE   = re.compile(r"\{%\s*raw\s*%\}", re.IGNORECASE)
_RAW_CLOSE_RE  = re.compile(r"\{%\s*endraw\s*%\}", re.IGNORECASE)


def _balance_raw_blocks(xml: str) -> str:
    """Strip all `{% raw %}` / `{% endraw %}` markers from a Word
    template part so the placeholders *inside* them actually render.

    Why STRIP rather than close-and-keep:

    The placeholder docs page on this site shows examples like:
        `{% raw %}{{ project.client_name }}{% endraw %}`
    The `{% raw %}` wrapper is purely a Jinja escape so the literal
    text `{{ project.client_name }}` displays in the BROWSER without
    Jinja substituting it. When a consultant copies that example
    verbatim into their Word template they bring the wrapper with
    them — and Jinja, encountering it at *render* time, dutifully
    treats everything inside as a literal string. The placeholder
    then ships to the rendered DOCX / PDF as raw text instead of
    being filled with the project data.

    An earlier version of this function tried to *close* unmatched
    `{% raw %}` opens by appending `{% endraw %}` before `</w:body>`.
    That worked around the syntax error but turned every placeholder
    in between into literal text — making the whole cover page show
    `{{ project.client_name }}` instead of "Acme Corp".

    Right answer: there's no legitimate use of `{% raw %}` inside a
    VAPT report template — every `{{ … }}` in the document is meant
    to be substituted. So we strip the markers entirely (both opens
    AND closes). Placeholders inside now render normally; balanced
    `{% raw %}…{% endraw %}` blocks lose their literalness (which was
    user error anyway — there's no UI path that creates a legitimate
    one).
    """
    if not _RAW_OPEN_RE.search(xml) and not _RAW_CLOSE_RE.search(xml):
        return xml
    xml = _RAW_OPEN_RE.sub("", xml)
    xml = _RAW_CLOSE_RE.sub("", xml)
    return xml


def _fix_split_jinja_tags(docx_path: Path) -> None:
    """
    Glue Jinja2 tags that Word has split across multiple <w:r>/<w:t> runs.

    When a user opens a docxtpl template in Microsoft Word, Word frequently
    inserts run breaks inside a single piece of text (e.g. spellcheck markers,
    autocorrect, language tags). The result is that a tag like

        {%p for f in findings %}

    becomes split across several <w:r><w:t>...</w:t></w:r> elements such that
    docxtpl's start-tag regex no longer matches the opener, while it still
    matches the closer `{%p endfor %}` (which got typed in one keystroke).
    The user then sees:

        TemplateSyntaxError: Encountered unknown tag 'endfor'.

    This preprocessor scans word/document.xml + every header/footer XML, finds
    text nodes containing a `{{` or `{%` opener with no matching close, and
    folds the *following sibling* text-runs into the first one until the tag
    is complete. The XML structure is otherwise preserved, so formatting on
    the first run wins (typical Word behaviour).

    Idempotent — running it twice does nothing on a clean file.
    """
    parts_to_fix = []
    with zipfile.ZipFile(docx_path, "r") as zf:
        for info in zf.infolist():
            if not (info.filename == "word/document.xml" or
                    info.filename.startswith("word/header") or
                    info.filename.startswith("word/footer")):
                continue
            content = zf.read(info.filename).decode("utf-8", errors="replace")
            if "{{" not in content and "{%" not in content:
                continue
            # Three passes — in order:
            #   1. Glue split tags so the row-splitter can see them.
            #   2. Split same-row for/endfor pairs (docxtpl quirk).
            #   3. Auto-close unmatched `{% raw %}` blocks so a paste
            #      from the placeholder docs renders instead of dying
            #      with "Missing end of raw directive".
            fixed = _merge_split_tags(content)
            fixed = _split_same_row_loops(fixed)
            fixed = _balance_raw_blocks(fixed)
            if fixed != content:
                parts_to_fix.append((info.filename, fixed))

    if not parts_to_fix:
        return

    # Rewrite the zip with patched parts. Use a tmp path to stay safe.
    tmp = docx_path.with_suffix(".tagfix.tmp.docx")
    with zipfile.ZipFile(docx_path, "r") as zin, \
         zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
        patches = dict(parts_to_fix)
        for item in zin.infolist():
            data = patches.get(item.filename)
            if data is not None:
                zout.writestr(item, data.encode("utf-8"))
            else:
                zout.writestr(item, zin.read(item.filename))
    shutil.move(str(tmp), str(docx_path))


# Inner machinery — operates on one XML part.
# Strategy: walk run-level text runs as a list, and for each <w:t> node whose
# text contains an unbalanced opener, keep absorbing the next sibling <w:t>
# inside the same <w:p> paragraph until the tag is balanced or we exit the
# paragraph (then we give up; nothing to merge that wouldn't break layout).

_RUN_TEXT_RE = re.compile(
    r"(<w:r\b[^>]*>(?:(?!</w:r>).)*?<w:t(?:\s[^>]*)?>)([^<]*)(</w:t>(?:(?!</w:r>).)*?</w:r>)",
    re.DOTALL,
)
_PARA_RE = re.compile(r"<w:p\b[^>]*>(?:(?!</w:p>).)*?</w:p>", re.DOTALL)


def _tags_unbalanced(s: str) -> bool:
    """True if `s` contains a `{{` or `{%` with no matching close yet."""
    # Strip complete tags first, then look for stray openers.
    stripped = _TAG_RE.sub("", s)
    return bool(_TAG_OPEN_RE.search(stripped))


def _merge_split_tags(xml: str) -> str:
    """For each <w:p> paragraph, merge text runs until tag openers have closers."""

    def fix_paragraph(pmatch: "re.Match[str]") -> str:
        para = pmatch.group(0)
        # Collect text runs in order
        runs = list(_RUN_TEXT_RE.finditer(para))
        if len(runs) < 2:
            return para
        out_para = para
        # We rebuild paragraph by mutating spans found in `runs` left-to-right.
        # To avoid invalidating indices when text grows, work from the end:
        # but we WANT to absorb *forward*. So instead: build a result string
        # by walking runs sequentially and re-emit the paragraph.
        # Approach: split paragraph into [pre, run_block, gap, run_block, ...]
        result = []
        cursor = 0
        i = 0
        while i < len(runs):
            r = runs[i]
            result.append(para[cursor:r.start()])
            run_prefix, run_text, run_suffix = r.group(1), r.group(2), r.group(3)
            # If this run's text contains an unbalanced opener, absorb following runs
            j = i + 1
            while _tags_unbalanced(run_text) and j < len(runs):
                nxt = runs[j]
                run_text = run_text + nxt.group(2)
                j += 1
            # Emit the (possibly merged) run
            result.append(run_prefix + run_text + run_suffix)
            cursor = r.end()
            # If we merged forward, skip over absorbed runs and ALSO the XML
            # between them (which is purely formatting markup we throw away,
            # because the formatting of run i wins for the merged text).
            if j > i + 1:
                cursor = runs[j - 1].end()
            i = j
        result.append(para[cursor:])
        return "".join(result)

    return _PARA_RE.sub(fix_paragraph, xml)


def _split_same_row_loops(xml: str) -> str:
    """Where a single <w:tr> contains BOTH {%tr for ...%} AND {%tr endfor %},
    rewrite into three rows: (for-only) (data row, tags stripped) (endfor-only).

    docxtpl's row preprocessor is a greedy regex over `<w:tr>...{%tr ...%}...</w:tr>`
    that collapses the entire row to a single Jinja tag — when two markers
    coexist in the same row, the LAST one wins (always the endfor) and the
    matching `{% for %}` vanishes, producing an unmatched-endfor crash at
    render time. The gen_word_templates.py starter templates ship in this
    shape (for in the first cell, endfor in the last cell of the same row),
    so we patch it up on the fly instead of forcing the user to regenerate.

    Idempotent: rows that already have at most one marker pass through.
    """
    def fix_row(m: "re.Match[str]") -> str:
        row = m.group(0)
        has_for    = bool(_INNER_FOR_RE.search(row))
        has_endfor = bool(_INNER_ENDFOR_RE.search(row))
        if not (has_for and has_endfor):
            return row
        # Pull the for-tag text (so we preserve the loop variable)
        for_match = _INNER_FOR_RE.search(row)
        for_text = for_match.group(0)
        # Strip both markers from the original row to make the "data" row.
        data_row = _INNER_FOR_RE.sub("", row, count=1)
        data_row = _INNER_ENDFOR_RE.sub("", data_row, count=1)
        # Build for-only / endfor-only rows by cloning the data row and
        # replacing the contents of every <w:t> with empty text, then
        # injecting the marker into the FIRST <w:t> of the new row.
        for_only_row = _row_with_only_marker(row, for_text)
        endfor_only_row = _row_with_only_marker(row, "{%tr endfor %}")
        return for_only_row + data_row + endfor_only_row

    out = _TR_RE.sub(fix_row, xml)

    # Mirror logic for paragraph loops in case a consultant collapses
    # {%p for ...%} + {%p endfor %} into a single <w:p>.
    def fix_para(m: "re.Match[str]") -> str:
        para = m.group(0)
        has_for    = bool(_INNER_P_FOR_RE.search(para))
        has_endfor = bool(_INNER_P_ENDFOR_RE.search(para))
        if not (has_for and has_endfor):
            return para
        for_match = _INNER_P_FOR_RE.search(para)
        for_text = for_match.group(0)
        data_para = _INNER_P_FOR_RE.sub("", para, count=1)
        data_para = _INNER_P_ENDFOR_RE.sub("", data_para, count=1)
        for_only_para = _para_with_only_marker(para, for_text)
        endfor_only_para = _para_with_only_marker(para, "{%p endfor %}")
        return for_only_para + data_para + endfor_only_para

    return _P_RE.sub(fix_para, out)


_WT_OPEN_RE = re.compile(r"<w:t\b[^>]*>")


def _row_with_only_marker(row_xml: str, marker_text: str) -> str:
    """Return a copy of `row_xml` where every <w:t> body is emptied and the
    marker is injected into the first <w:t> element only. Preserves the row's
    cell / paragraph / run structure so Word stays happy."""
    # Empty every <w:t>...</w:t>
    stripped = re.sub(
        r"(<w:t\b[^>]*>)(?:(?!</w:t>).)*</w:t>",
        r"\1</w:t>",
        row_xml,
        flags=re.DOTALL,
    )
    # Inject marker into the FIRST <w:t> element
    def inject(m):
        return m.group(0) + marker_text
    return _WT_OPEN_RE.sub(inject, stripped, count=1)


def _para_with_only_marker(para_xml: str, marker_text: str) -> str:
    """Paragraph-level twin of `_row_with_only_marker`."""
    stripped = re.sub(
        r"(<w:t\b[^>]*>)(?:(?!</w:t>).)*</w:t>",
        r"\1</w:t>",
        para_xml,
        flags=re.DOTALL,
    )
    return _WT_OPEN_RE.sub(lambda m: m.group(0) + marker_text, stripped, count=1)


def _inject_watermark(docx_path: Path) -> None:
    """Insert a DRAFT watermark into every header in the .docx."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        with zipfile.ZipFile(docx_path, "r") as zf:
            # Zip slip guard: reject any entry whose resolved path escapes tmp_path
            _resolved_tmp = tmp_path.resolve()
            for _info in zf.infolist():
                if not str((tmp_path / _info.filename).resolve()).startswith(
                    str(_resolved_tmp)
                ):
                    raise ValueError(
                        f"Zip slip detected in template: {_info.filename!r}"
                    )
            zf.extractall(tmp_path)

        word_dir = tmp_path / "word"
        # If template has no header at all, fall back to skipping silently.
        modified = False
        for header in word_dir.glob("header*.xml"):
            content = header.read_text(encoding="utf-8")
            if "DRAFT_WM" in content:
                continue
            # Insert just before the closing </w:hdr>
            new_content = content.replace(
                "</w:hdr>",
                _WATERMARK_XML + "</w:hdr>",
                1,
            )
            if new_content != content:
                header.write_text(new_content, encoding="utf-8")
                modified = True

        if not modified:
            return  # nothing changed

        # Rezip
        out = docx_path.with_suffix(".tmp.docx")
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(tmp_path):
                for name in files:
                    fp = Path(root) / name
                    arc = fp.relative_to(tmp_path).as_posix()
                    zf.write(fp, arc)
        shutil.move(str(out), str(docx_path))


def _flatten_subdoc_paragraphs(docx_path: Path) -> int:
    """Repair the "Subdoc inside `<w:t>`" pattern docxtpl leaves when
    a rich-text placeholder like ``{{ f.remediation }}`` isn't the
    only thing in its paragraph.

    The problem
    -----------
    docxtpl substitutes Subdoc objects as raw XML at the placeholder's
    position. If the placeholder was authored as
    ``<w:r><w:t>{{ f.remediation }}</w:t></w:r>`` (which `python-docx`
    always emits — there's no way to put text directly in a paragraph
    without a run), then after substitution we get::

        <w:p>
          <w:pPr>...SubHeading style...</w:pPr>
          <w:r>
            <w:t xml:space="preserve">
              <w:p>...subdoc paragraph 1...</w:p>
              <w:p>...subdoc paragraph 2 with a drawing...</w:p>
            </w:t>
          </w:r>
        </w:p>

    That's malformed OOXML — ``<w:p>`` can't legally live inside
    ``<w:t>``. Word renders it leniently (extracts text and even most
    drawings), but **LibreOffice silently drops every drawing inside
    the nested paragraphs** during PDF conversion. That's why pasted-
    in-editor screenshots vanish from the rendered PDF even though
    they're physically present in the .docx.

    The fix
    -------
    Walk the body, find every ``<w:t>`` whose direct children include
    ``<w:p>``, and PROMOTE those inner paragraphs to body level —
    placing them where the outer paragraph (the placeholder paragraph)
    sat, then deleting the outer paragraph. Idempotent: a clean
    document has no ``<w:t>``→``<w:p>`` nesting, so the function is
    a no-op on already-clean files.

    Returns the number of outer paragraphs that were unwrapped.
    """
    NS_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    qn_t = f"{{{NS_W}}}t"
    qn_p = f"{{{NS_W}}}p"

    with zipfile.ZipFile(docx_path, "r") as zf:
        if "word/document.xml" not in zf.namelist():
            return 0
        xml_bytes = zf.read("word/document.xml")

    from lxml import etree
    try:
        root = etree.fromstring(xml_bytes)
    except etree.XMLSyntaxError:
        return 0

    unwrapped = 0
    # We need to scan for <w:t> elements that have <w:p> children.
    # `iter(qn_t)` walks every <w:t> in the tree.
    bad_paragraphs: list = []
    for t in root.iter(qn_t):
        nested_ps = [c for c in t if c.tag == qn_p]
        if not nested_ps:
            continue
        # Walk up to the nearest <w:p> ancestor — that's the OUTER
        # paragraph (the one whose placeholder triggered the
        # substitution). We drop that and put the nested ps in its
        # place.
        outer_p = t
        while outer_p is not None and outer_p.tag != qn_p:
            outer_p = outer_p.getparent()
        if outer_p is None:
            continue
        bad_paragraphs.append((outer_p, nested_ps))

    # Mutate now — done after collecting so we don't trip the iterator.
    for outer_p, nested_ps in bad_paragraphs:
        parent = outer_p.getparent()
        if parent is None:
            continue
        idx = list(parent).index(outer_p)
        # Insert the nested paragraphs in order at the outer's position.
        for offset, np in enumerate(nested_ps):
            # Detach np from its current parent first.
            np_parent = np.getparent()
            if np_parent is not None:
                np_parent.remove(np)
            parent.insert(idx + offset, np)
        # Remove the now-empty outer placeholder paragraph.
        parent.remove(outer_p)
        unwrapped += 1

    if unwrapped == 0:
        return 0

    new_xml = etree.tostring(
        root, xml_declaration=True, encoding="UTF-8", standalone=True,
    )

    # Atomic re-zip — same pattern as the other post-render passes.
    tmp = docx_path.with_suffix(".flatten.tmp.docx")
    try:
        with zipfile.ZipFile(docx_path, "r") as zin, \
             zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename == "word/document.xml":
                    zout.writestr(item, new_xml)
                else:
                    zout.writestr(item, zin.read(item.filename))
        shutil.move(str(tmp), str(docx_path))
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass

    return unwrapped


def _enable_update_fields_on_open(docx_path: Path) -> None:
    """Stamp ``<w:updateFields w:val="true"/>`` into ``word/settings.xml``.

    This is Word's official "refresh every field the next time the
    document is opened" flag. It covers:
      * Table of Contents — so the consultant's report TOC picks up
        every freshly-rendered "Finding N: …" Heading 2 without the
        user having to right-click → Update Field.
      * Multilevel-list Heading 2 numbering ("3.1, 3.2, …") — Word
        recalculates these when the document opens.
      * Page references / cross-references in headers + footers.

    LibreOffice (which we use for DOCX → PDF conversion) honours the
    same flag during conversion, so the previewed PDF gets a refreshed
    TOC too.

    Idempotent — if ``<w:updateFields>`` already exists we set its
    val attribute to ``true``; otherwise we inject one as the first
    child of ``<w:settings>``. We do nothing if the .docx has no
    ``word/settings.xml`` (unusual but valid for stripped-down
    templates), since there's no field that could exist without it.
    """
    SETTINGS = "word/settings.xml"
    NS_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    qname_update = f"{{{NS_W}}}updateFields"
    qname_val    = f"{{{NS_W}}}val"

    # Read settings.xml out of the zip first; bail if absent.
    with zipfile.ZipFile(docx_path, "r") as zf:
        names = set(zf.namelist())
        if SETTINGS not in names:
            return
        original = zf.read(SETTINGS)

    # Parse + mutate via lxml so we preserve every other setting Word
    # cares about (compatibility shims, default tab stops, etc.).
    from lxml import etree
    try:
        root = etree.fromstring(original)
    except etree.XMLSyntaxError:
        return

    existing = root.find(qname_update)
    if existing is None:
        new_el = etree.SubElement(root, qname_update)
        new_el.set(qname_val, "true")
        # Word reads settings.xml top-down; convention is for
        # updateFields to live near the top. Move it to position 0
        # so we match what Word writes natively.
        root.remove(new_el)
        root.insert(0, new_el)
    else:
        existing.set(qname_val, "true")

    new_xml = etree.tostring(
        root, xml_declaration=True, encoding="UTF-8", standalone=True,
    )
    if new_xml == original:
        return

    # Atomic re-zip — same pattern as the watermark stripper.
    tmp = docx_path.with_suffix(".updatefields.tmp.docx")
    try:
        with zipfile.ZipFile(docx_path, "r") as zin, \
             zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename == SETTINGS:
                    zout.writestr(item, new_xml)
                else:
                    zout.writestr(item, zin.read(item.filename))
        shutil.move(str(tmp), str(docx_path))
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _apply_chapter_page_footers(docx_path: Path) -> int:
    """Make headless LibreOffice render chapter-relative page numbers ("2-1").

    The VibeDocs templates number body pages "chapter-page" via
    ``<w:pgNumType w:chapStyle="1"/>`` on each body section. Word honours that
    (Heading-1 chapter number + "-" + page), but headless LibreOffice — which
    VibeDocs uses for docx→pdf — IGNORES ``chapStyle`` and prints just the plain PAGE
    number ("1"). That breaks the footer AND, downstream, the Contents / Tables /
    Figures page references (``_patch_toc_pages`` reads the footer label from the
    rendered PDF).

    Fix: replace ``chapStyle`` with an explicit, LibreOffice-compatible
    construction. Each body section gets its OWN footer that prints a STATIC
    chapter number + "-" immediately before the live PAGE field, and ``chapStyle``
    is dropped from that section's ``pgNumType`` (so Word shows the same thing
    rather than double-prefixing). The PAGE field still resets per section
    (``start="1"``), so it renders 1, 2, 3 … within the chapter → "2-1", "2-2".

    Body sections are the ones whose ``pgNumType`` carries ``chapStyle`` (the
    roman front matter does not). The per-chapter page reset guarantees exactly
    one section per chapter, so the Nth body section in document order is
    chapter N.

    Returns the number of body-section footers rewritten (0 = nothing to do).
    Idempotent: once ``chapStyle`` is gone there are no body sections left to
    process, so a second run is a no-op.
    """
    from lxml import etree

    NS_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    NS_CT = "http://schemas.openxmlformats.org/package/2006/content-types"
    NS_PR = "http://schemas.openxmlformats.org/package/2006/relationships"
    def w(t): return f"{{{NS_W}}}{t}"
    def rid_q(t): return f"{{{NS_R}}}{t}"
    XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"
    FOOTER_CT = "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"
    FOOTER_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer"

    try:
        with zipfile.ZipFile(docx_path, "r") as z:
            names = z.namelist()
            parts = {n: z.read(n) for n in names}
    except Exception:
        return 0
    if "word/document.xml" not in parts or "[Content_Types].xml" not in parts:
        return 0
    if "word/_rels/document.xml.rels" not in parts:
        return 0

    try:
        doc = etree.fromstring(parts["word/document.xml"])
        rels = etree.fromstring(parts["word/_rels/document.xml.rels"])
        ct = etree.fromstring(parts["[Content_Types].xml"])
    except etree.XMLSyntaxError:
        return 0

    sects = doc.findall(".//" + w("sectPr"))
    body_idx = [i for i, s in enumerate(sects)
                if (s.find(w("pgNumType")) is not None
                    and s.find(w("pgNumType")).get(w("chapStyle")) is not None)]
    if not body_idx:
        return 0

    relmap = {rel.get("Id"): rel.get("Target") for rel in rels}
    used_ids = set(relmap.keys())
    def _next_rid():
        n = 1
        while f"rId{900 + n}" in used_ids:
            n += 1
        rid = f"rId{900 + n}"
        used_ids.add(rid)
        return rid

    # Highest existing footerN.xml index, so new parts don't collide.
    seq = max([int(re.search(r"footer(\d+)\.xml", n).group(1))
               for n in names if re.match(r"word/footer\d+\.xml$", n)] or [0])

    def _default_footer_target(upto: int):
        """The default-footer Target this section uses: its own, else the nearest
        preceding section's (Word footer inheritance)."""
        for j in range(upto, -1, -1):
            for fr in sects[j].findall(w("footerReference")):
                if (fr.get(w("type")) or "default") == "default":
                    return relmap.get(fr.get(rid_q("id")))
        return None

    def _add_prefix_and_reset(froot, chapter: str) -> bool:
        """Insert a static '<chapter>-' run before the PAGE field and reset the
        field's cached result to '1' (so Word doesn't briefly show a stale
        '3-1' beside the new prefix before fields refresh)."""
        for p in froot.iter(w("p")):
            runs = p.findall(w("r"))
            for i, rn in enumerate(runs):
                it = rn.find(w("instrText"))
                if it is None or not it.text or "PAGE" not in it.text.upper():
                    continue
                begin = next((j for j in range(i, -1, -1)
                              if (runs[j].find(w("fldChar")) is not None
                                  and runs[j].find(w("fldChar")).get(w("fldCharType")) == "begin")), None)
                if begin is None:
                    continue
                sep = end = None
                for k in range(i, len(runs)):
                    fc = runs[k].find(w("fldChar"))
                    if fc is None:
                        continue
                    ft = fc.get(w("fldCharType"))
                    if ft == "separate" and sep is None:
                        sep = k
                    elif ft == "end":
                        end = k
                        break
                nr = etree.Element(w("r"))
                t = etree.SubElement(nr, w("t"))
                t.set(XML_SPACE, "preserve")
                t.text = f"{chapter}-"
                runs[begin].addprevious(nr)
                if sep is not None and end is not None:
                    first = True
                    for k in range(sep + 1, end):
                        tt = runs[k].find(w("t"))
                        if tt is not None:
                            tt.text = "1" if first else ""
                            first = False
                return True
        return False

    # Resolve each body section's ORIGINAL (inherited) footer BEFORE mutating —
    # otherwise the footerReference we add to section N pollutes the lookup for
    # section N+1 (its new rId isn't in relmap → resolves to None → skipped, and
    # the section then inherits the previous chapter's footer).
    src_targets = [_default_footer_target(bi) for bi in body_idx]

    rewritten = 0
    for chapter, (bi, target) in enumerate(zip(body_idx, src_targets), start=1):
        sec = sects[bi]
        if not target:
            continue
        src_part = "word/" + target
        if src_part not in parts:
            continue
        try:
            froot = etree.fromstring(parts[src_part])
        except etree.XMLSyntaxError:
            continue
        if not _add_prefix_and_reset(froot, str(chapter)):
            continue

        seq += 1
        new_part = f"word/footer{seq}.xml"
        parts[new_part] = etree.tostring(froot, xml_declaration=True,
                                         encoding="UTF-8", standalone=True)
        rid = _next_rid()
        rel_el = etree.SubElement(rels, f"{{{NS_PR}}}Relationship")
        rel_el.set("Id", rid)
        rel_el.set("Type", FOOTER_REL)
        rel_el.set("Target", f"footer{seq}.xml")
        ov = etree.SubElement(ct, f"{{{NS_CT}}}Override")
        ov.set("PartName", f"/word/footer{seq}.xml")
        ov.set("ContentType", FOOTER_CT)

        # Point this section's default footer at the new part (replace or add).
        existing = next((fr for fr in sec.findall(w("footerReference"))
                         if (fr.get(w("type")) or "default") == "default"), None)
        if existing is not None:
            existing.set(rid_q("id"), rid)
        else:
            fr = etree.Element(w("footerReference"))
            fr.set(w("type"), "default")
            fr.set(rid_q("id"), rid)
            # Schema: header/footer references lead the sectPr — insert after the
            # last existing reference, else at the very front.
            anchor = None
            for child in sec:
                if child.tag in (w("headerReference"), w("footerReference")):
                    anchor = child
            if anchor is not None:
                anchor.addnext(fr)
            else:
                sec.insert(0, fr)

        # Drop chapStyle so Word renders "<chapter>-page" too (no double prefix).
        pg = sec.find(w("pgNumType"))
        if pg is not None and pg.get(w("chapStyle")) is not None:
            del pg.attrib[w("chapStyle")]
            # chapSep is meaningless without chapStyle — remove if present.
            if pg.get(w("chapSep")) is not None:
                del pg.attrib[w("chapSep")]
        rewritten += 1

    if not rewritten:
        return 0

    parts["word/document.xml"] = etree.tostring(doc, xml_declaration=True,
                                                encoding="UTF-8", standalone=True)
    parts["word/_rels/document.xml.rels"] = etree.tostring(rels, xml_declaration=True,
                                                           encoding="UTF-8", standalone=True)
    parts["[Content_Types].xml"] = etree.tostring(ct, xml_declaration=True,
                                                  encoding="UTF-8", standalone=True)

    tmp = docx_path.with_suffix(".chapftr.tmp.docx")
    try:
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
            for n in (names + [f"word/footer{i}.xml" for i in range(seq - rewritten + 1, seq + 1)]):
                if n in parts:
                    zout.writestr(n, parts[n])
        shutil.move(str(tmp), str(docx_path))
    except Exception:
        try: tmp.unlink(missing_ok=True)
        except Exception: pass
        return 0
    return rewritten


def _fix_table_caption_numbers(docx_path: Path) -> int:
    """Replace the live STYLEREF/SEQ chapter-number fields in "Table N-N:"
    captions with computed STATIC text ("1-1", "2-1", …).

    The VibeDocs table captions number themselves with
    ``{ STYLEREF 1 \\s }-{ SEQ Table \\* ARABIC \\s 1 }``. Word renders that as
    "1-1" (chapter number + table number, reset per chapter), but headless
    LibreOffice renders ``STYLEREF 1 \\s`` as the chapter TEXT ("Executive
    Summary-1") and does not reset the SEQ per chapter — so captions come out
    wrong AND the Table of Tables can't match them in the PDF (its entries stay
    on the cached "1"). Figure captions don't have this problem because VibeDocs emits
    them as static text already.

    Static text renders identically in Word and LibreOffice. The chapter number
    increments at each Heading 1; the table counter resets per chapter — matching
    Word's ``\\s 1`` semantics. Must run before the Table-of-Tables rebuild so the
    ToT collects the corrected text, and before PDF conversion so
    ``_patch_toc_pages`` can find each caption.

    Returns the number of captions rewritten.
    """
    from lxml import etree

    NS_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    def w(t): return f"{{{NS_W}}}{t}"
    XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"

    try:
        with zipfile.ZipFile(docx_path, "r") as z:
            names = z.namelist()
            xml = z.read("word/document.xml")
    except Exception:
        return 0
    try:
        root = etree.fromstring(xml)
    except etree.XMLSyntaxError:
        return 0
    body = root.find(w("body"))
    if body is None:
        return 0

    def _is_h1(p) -> bool:
        pPr = p.find(w("pPr"))
        if pPr is None:
            return False
        ps = pPr.find(w("pStyle"))
        if ps is None:
            return False
        return (ps.get(w("val")) or "").lower().replace(" ", "") == "heading1"

    chapter = 0
    tcount = 0
    rewritten = 0
    for p in body.iter(w("p")):
        if _is_h1(p):
            chapter += 1
            tcount = 0
            continue
        if chapter == 0:
            continue
        text = "".join((t.text or "") for t in p.iter(w("t"))).strip()
        if not text.lower().startswith("table "):
            continue
        instr = "".join((it.text or "") for it in p.iter(w("instrText")))
        if "SEQ" not in instr.upper() and "STYLEREF" not in instr.upper():
            continue

        runs = p.findall(w("r"))
        first_i = last_i = None
        for i, rn in enumerate(runs):
            fc = rn.find(w("fldChar"))
            if fc is None:
                continue
            ft = fc.get(w("fldCharType"))
            if ft == "begin" and first_i is None:
                first_i = i
            if ft == "end":
                last_i = i
        if first_i is None or last_i is None or last_i < first_i:
            continue

        tcount += 1
        static = etree.Element(w("r"))
        rpr = runs[first_i].find(w("rPr"))
        if rpr is not None:
            static.append(etree.fromstring(etree.tostring(rpr)))
        t = etree.SubElement(static, w("t"))
        t.set(XML_SPACE, "preserve")
        t.text = f"{chapter}-{tcount}"
        runs[first_i].addprevious(static)
        for i in range(first_i, last_i + 1):
            p.remove(runs[i])
        rewritten += 1

    if not rewritten:
        return 0

    new_xml = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)
    tmp = docx_path.with_suffix(".capnum.tmp.docx")
    try:
        with zipfile.ZipFile(docx_path, "r") as zin, \
             zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                zout.writestr(item, new_xml if item.filename == "word/document.xml"
                              else zin.read(item.filename))
        shutil.move(str(tmp), str(docx_path))
    except Exception:
        try: tmp.unlink(missing_ok=True)
        except Exception: pass
        return 0
    return rewritten


def _rebuild_toc(docx_path: Path, *, mode: str = "headings") -> int:
    """Rebuild a TOC field's cached entries so the rendered PDF is correct
    (LibreOffice does NOT evaluate TOC fields on convert).

    mode="headings": the main Table of Contents (Heading 1/2/3).
    mode="figures":  the Table of Figures (`TOC \\c "Figure"`) — lists every
                     "Figure …" caption paragraph. Needed because the figure
                     captions use a custom "3.x-n" number (not a Word SEQ field),
                     so Word's native SEQ-based collection can't see them; we
                     populate the cache directly.
    mode="tables":   the Table of Tables (`TOC \\c "Table"`) — lists every
                     "Table …" caption paragraph, same mechanism as figures so
                     all three tables keep a consistent chapter-relative ("3-1")
                     page-number format after the PDF page-patch pass.

    The problem
    -----------
    VibeDocs source templates ship with a TOC that lists ONE example
    finding ("3.1 Public Facing Intranet Login Page with null
    account"). When the consultant generates a report with 7 findings,
    Word's TOC field is still a live `{ TOC \\o "1-3" \\h }` field —
    so opening the file in Word and pressing F9 fixes it. But
    LibreOffice's headless docx → pdf conversion DOES NOT evaluate
    TOC fields, and ``<w:updateFields w:val="true"/>`` only triggers
    the "Update fields on open" prompt in interactive Word. So the
    PDF preview keeps showing the source template's stale single-
    entry TOC regardless of how many findings the consultant added.

    Fix
    ---
    After the docxtpl render lands, walk every Heading 1/2/3 paragraph
    in the body, capture (or generate) a bookmark anchor for each,
    build TOC entry paragraphs (with hyperlinks for click-nav and
    PAGEREF fields for page numbers — LibreOffice DOES update
    PAGEREF), and splice them in to replace the TOC field's cached
    content (the paragraph block between the ``<w:fldChar
    fldCharType="separate"/>`` and ``<w:fldChar fldCharType="end"/>``
    markers of the TOC field). The Field code itself (the
    `<w:instrText> TOC \\o ... </w:instrText>` part) is left
    intact so Word still recognises it as a TOC and refreshes
    further on F9.

    Numbering
    ---------
    The dotted chapter numbers ("3.1, 3.2, 3.3, …") are computed from
    Heading 1 / Heading 2 / Heading 3 order rather than read from the
    multilevel-list — the list-defined numbers aren't materialised in
    the rendered docx yet (Word/LibreOffice compute them at display
    time). For a docxtpl-rendered report where the multilevel-list
    is correctly set up on the document, the computed numbers match
    what the user sees in the actual section headings.

    Idempotent — running this on an already-rebuilt file replaces the
    cached entries with the same set.

    Returns the count of TOC entries written (0 if no TOC was found).
    """
    from lxml import etree

    NS_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    def qn(tag: str) -> str: return f"{{{NS_W}}}{tag}"

    with zipfile.ZipFile(docx_path, "r") as zf:
        if "word/document.xml" not in zf.namelist():
            return 0
        xml_bytes = zf.read("word/document.xml")

    try:
        root = etree.fromstring(xml_bytes)
    except etree.XMLSyntaxError:
        return 0
    body = root.find(qn("body"))
    if body is None:
        return 0

    # Step 1 — Walk every <w:fldChar> in document order to bound the
    # TOC field. We're looking for a 'begin' whose accompanying
    # instrText starts with " TOC " (with the leading space — that
    # disambiguates from TOC2 / TOC1 paragraph styles which contain
    # the literal "TOC" inside their pStyle value but never inside an
    # instrText).
    fld_chars = list(root.iter(qn("fldChar")))
    if not fld_chars:
        return 0

    toc_begin = toc_separate = toc_end = None
    # We track "are we inside a TOC field right now" by counting begin/end.
    # When we hit a begin, peek ahead at the next instrText sibling chain
    # to check the field code.
    instr_re = re.compile(r"\s*TOC\b", re.IGNORECASE)
    for fc in fld_chars:
        ft = fc.get(qn("fldCharType"))
        if ft == "begin":
            # Look at the run after this for an instrText.
            # The instrText might live in the SAME <w:r> as this fldChar,
            # or in a following <w:r> within the same paragraph.
            run = fc.getparent()
            para = run.getparent() if run is not None else None
            if para is None: continue
            # Search runs after the begin-bearing run for instrText
            seen_self = False
            instr_text = ""
            for r in para.findall(qn("r")):
                if r is run:
                    seen_self = True
                if not seen_self:
                    continue
                it = r.find(qn("instrText"))
                if it is not None and it.text:
                    instr_text += it.text
            if not instr_re.match(instr_text):
                # Not the TOC field — could be PAGEREF / SEQ / etc.
                continue
            # Distinguish the main heading TOC from the caption TOFs
            # (Table of Figures / Tables) which carry `\c "Figure"` / `\c "Table"`.
            low_instr = instr_text.lower()
            is_caption_toc = "\\c" in instr_text
            if mode == "headings" and is_caption_toc:
                continue                       # skip ToF/ToT in heading mode
            if mode == "figures" and '\\c "figure"' not in low_instr:
                continue                       # only the Table of Figures
            if mode == "tables" and '\\c "table"' not in low_instr:
                continue                       # only the Table of Tables
            toc_begin = fc
            break

    if toc_begin is None:
        return 0

    # Step 2 — find the matching 'separate' and 'end' for THIS field.
    # docx fields nest, so we have to track depth. begin = +1, end = -1.
    depth = 0
    start_seen = False
    for fc in fld_chars:
        ft = fc.get(qn("fldCharType"))
        if fc is toc_begin:
            start_seen = True
            depth = 1
            continue
        if not start_seen:
            continue
        if ft == "begin":
            depth += 1
        elif ft == "end":
            depth -= 1
            if depth == 0:
                toc_end = fc
                break
        elif ft == "separate" and depth == 1:
            toc_separate = fc
    if toc_separate is None or toc_end is None:
        return 0

    # Step 3 — figure out which paragraphs (BODY-level <w:p>) the
    # cached TOC entries occupy. The 'separate' fldChar sits inside
    # some run inside some paragraph at body level — call that the
    # "separator paragraph". The 'end' fldChar sits inside another
    # body-level paragraph — the "terminator paragraph". The cached
    # TOC entries are EVERY body-level paragraph strictly BETWEEN
    # those two. We remove those and insert our rebuilt entries
    # there.
    def _walk_to_body_paragraph(node):
        cur = node.getparent() if node is not None else None
        while cur is not None and cur.tag != qn("p"):
            cur = cur.getparent()
        return cur
    sep_para = _walk_to_body_paragraph(toc_separate)
    end_para = _walk_to_body_paragraph(toc_end)
    if sep_para is None or end_para is None:
        return 0
    # The body-level container for these paragraphs (usually the body
    # itself, but could be inside an sdtContent — be safe).
    sep_parent = sep_para.getparent()
    end_parent = end_para.getparent()
    if sep_parent is None or sep_parent is not end_parent:
        return 0

    children = list(sep_parent)
    try:
        sep_idx = children.index(sep_para)
        end_idx = children.index(end_para)
    except ValueError:
        return 0
    if end_idx <= sep_idx:
        return 0

    # Step 4 — Collect heading paragraphs. We walk every body-level
    # paragraph (and paragraphs inside sdt content) looking for
    # Heading 1/2/3 styles. We DON'T include any Heading that already
    # has a "TOCx" pStyle (those are the current TOC entries from
    # the cached block we're about to delete).
    HEADING_TO_LEVEL = {
        "Heading1": 1, "Heading2": 2, "Heading3": 3,
        "heading 1": 1, "heading 2": 2, "heading 3": 3,
    }
    # Anchor counter for headings missing bookmarks.
    next_anchor_id = [99100]   # high to avoid colliding with template bookmarks
    def _next_anchor():
        next_anchor_id[0] += 1
        return (f"_Toc_vibedocs_{next_anchor_id[0]}", next_anchor_id[0])

    def _para_text(p):
        return "".join((t.text or "") for t in p.iter(qn("t")))

    def _ensure_bookmark(p):
        """Return the first `_Toc*` bookmark anchor on this paragraph,
        creating one if none exists."""
        for bm in p.findall(qn("bookmarkStart")):
            nm = bm.get(qn("name"))
            if nm and nm.startswith("_Toc"):
                return nm
        # Create one
        anchor, bm_id = _next_anchor()
        bm_start = etree.Element(qn("bookmarkStart"))
        bm_start.set(qn("id"), str(bm_id))
        bm_start.set(qn("name"), anchor)
        bm_end = etree.Element(qn("bookmarkEnd"))
        bm_end.set(qn("id"), str(bm_id))
        # Insert bm_start at the START of the paragraph (after pPr if
        # present) and bm_end at the END so the entire paragraph is
        # the bookmark range.
        pPr = p.find(qn("pPr"))
        if pPr is not None:
            pPr.addnext(bm_start)
        else:
            p.insert(0, bm_start)
        p.append(bm_end)
        return anchor

    # Skip headings that live inside the TOC field itself (defensive).
    toc_para_set = set(id(c) for c in children[sep_idx:end_idx + 1])

    # --- Caption modes: collect every "Figure …" / "Table …" caption para ---
    if mode in ("figures", "tables"):
        caption_prefix = "figure " if mode == "figures" else "table "
        fig_entries = []   # (text, anchor)
        for p in body.iter(qn("p")):
            if id(p) in toc_para_set:
                continue
            text = _para_text(p).strip()
            low = text.lower()
            if not low.startswith(caption_prefix):
                continue
            # Skip the "Table of Contents / Tables / Figures" section headings:
            # they begin with the same word ("Table …") but are never real
            # captions. Real captions read "Table N: …" / "Figure N: …", so a
            # "<prefix>of " start unambiguously marks a TOC heading.
            if low.startswith(caption_prefix + "of "):
                continue
            pPr = p.find(qn("pPr"))
            sval = ""
            if pPr is not None:
                ps = pPr.find(qn("pStyle"))
                if ps is not None:
                    sval = (ps.get(qn("val")) or "").lower()
            # Skip existing ToF/TOC entry paragraphs (the cached block style).
            if "toc" in sval or "tableoffigures" in sval or "tableof" in sval:
                continue
            anchor = _ensure_bookmark(p)
            fig_entries.append((text, anchor))
        if not fig_entries:
            return 0
        headings = []   # not used in caption (figures/tables) modes
    else:
        headings = collected_headings = []
        chap_n = [0, 0, 0]   # counters for H1/H2/H3
        for p in body.iter(qn("p")):
            if id(p) in toc_para_set:
                continue
            pPr = p.find(qn("pPr"))
            if pPr is None:
                continue
            pStyle = pPr.find(qn("pStyle"))
            if pStyle is None:
                continue
            style_val = pStyle.get(qn("val"))
            if style_val not in HEADING_TO_LEVEL:
                continue
            level = HEADING_TO_LEVEL[style_val]
            text = _para_text(p).strip()
            if not text:
                continue
            anchor = _ensure_bookmark(p)
            # Compute the dotted number for this heading. New H1 → bump
            # chap[0], reset 1+2. New H2 → bump chap[1], reset 2.
            if level == 1:
                chap_n[0] += 1; chap_n[1] = 0; chap_n[2] = 0
                number = f"{chap_n[0]}.0"
            elif level == 2:
                chap_n[1] += 1; chap_n[2] = 0
                number = f"{chap_n[0]}.{chap_n[1]}"
            else:
                chap_n[2] += 1
                number = f"{chap_n[0]}.{chap_n[1]}.{chap_n[2]}"
            headings.append((level, number, text, anchor))
        if not headings:
            return 0

    # Step 5 — Build new TOC entry paragraphs.
    def _build_toc_entry(level, number, text, anchor):
        """One TOC entry paragraph with TOCx style + hyperlink + a
        PAGEREF field for the page number."""
        # The TOC style names in the rendered docx mirror Word's
        # convention: TOC1 / TOC2 / TOC3.
        toc_style = f"TOC{level}"

        p = etree.Element(qn("p"))
        # pPr
        pPr = etree.SubElement(p, qn("pPr"))
        pSt = etree.SubElement(pPr, qn("pStyle"))
        pSt.set(qn("val"), toc_style)
        tabs = etree.SubElement(pPr, qn("tabs"))
        # Right tab with dot leader — same convention the source TOC uses.
        rtab = etree.SubElement(tabs, qn("tab"))
        rtab.set(qn("val"), "right")
        rtab.set(qn("leader"), "dot")
        rtab.set(qn("pos"), "10457")
        rPr_def = etree.SubElement(pPr, qn("rPr"))
        nproof = etree.SubElement(rPr_def, qn("noProof"))

        # Hyperlink wraps everything so the WHOLE row is clickable.
        hyp = etree.SubElement(p, qn("hyperlink"))
        hyp.set(qn("anchor"), anchor)
        hyp.set(qn("history"), "1")

        def _r_text(parent, text_value, hyperlink_style=True):
            r = etree.SubElement(parent, qn("r"))
            rPr = etree.SubElement(r, qn("rPr"))
            if hyperlink_style:
                rStyle = etree.SubElement(rPr, qn("rStyle"))
                rStyle.set(qn("val"), "Hyperlink")
            etree.SubElement(rPr, qn("noProof"))
            t = etree.SubElement(r, qn("t"))
            t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            t.text = text_value
            return r

        def _r_tab(parent):
            r = etree.SubElement(parent, qn("r"))
            rPr = etree.SubElement(r, qn("rPr"))
            etree.SubElement(rPr, qn("noProof"))
            etree.SubElement(r, qn("tab"))
            return r

        # "3.1 \t Title \t PAGE"
        _r_text(hyp, number)
        _r_text(hyp, " ")          # single space between number and title
        _r_text(hyp, text)
        _r_tab(hyp)                # right-tab to push page number to the right margin

        # PAGEREF field
        def _r_fld(parent, fld_type):
            r = etree.SubElement(parent, qn("r"))
            rPr = etree.SubElement(r, qn("rPr"))
            etree.SubElement(rPr, qn("noProof"))
            fc = etree.SubElement(r, qn("fldChar"))
            fc.set(qn("fldCharType"), fld_type)
        def _r_instr(parent, instr_text):
            r = etree.SubElement(parent, qn("r"))
            rPr = etree.SubElement(r, qn("rPr"))
            etree.SubElement(rPr, qn("noProof"))
            it = etree.SubElement(r, qn("instrText"))
            it.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            it.text = instr_text

        _r_fld(hyp, "begin")
        _r_instr(hyp, f" PAGEREF {anchor} \\h ")
        _r_fld(hyp, "separate")
        # Cached page-number text. LibreOffice updates PAGEREF at
        # PDF-export time, so this value is overwritten with the real
        # page number — but provide a placeholder so Word users who
        # never refresh fields still see something sensible.
        _r_text(hyp, "1")
        _r_fld(hyp, "end")
        return p

    def _build_figure_entry(text, anchor):
        """One Table-of-Figures entry: the full caption text ('Figure 3.x-n:
        …') + dot-leader tab + PAGEREF page number, hyperlinked to the
        caption's bookmark. Uses the 'TableofFigures' style if present, else
        falls back to 'TOC1'."""
        p = etree.Element(qn("p"))
        pPr = etree.SubElement(p, qn("pPr"))
        pSt = etree.SubElement(pPr, qn("pStyle"))
        pSt.set(qn("val"), "TableofFigures")
        tabs = etree.SubElement(pPr, qn("tabs"))
        rtab = etree.SubElement(tabs, qn("tab"))
        rtab.set(qn("val"), "right"); rtab.set(qn("leader"), "dot"); rtab.set(qn("pos"), "10457")
        etree.SubElement(etree.SubElement(pPr, qn("rPr")), qn("noProof"))

        hyp = etree.SubElement(p, qn("hyperlink"))
        hyp.set(qn("anchor"), anchor); hyp.set(qn("history"), "1")

        def _r_text(parent, value, hyperlink_style=True):
            r = etree.SubElement(parent, qn("r"))
            rPr = etree.SubElement(r, qn("rPr"))
            if hyperlink_style:
                etree.SubElement(rPr, qn("rStyle")).set(qn("val"), "Hyperlink")
            etree.SubElement(rPr, qn("noProof"))
            t = etree.SubElement(r, qn("t"))
            t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            t.text = value
            return r

        def _r_tab(parent):
            r = etree.SubElement(parent, qn("r"))
            etree.SubElement(etree.SubElement(r, qn("rPr")), qn("noProof"))
            etree.SubElement(r, qn("tab"))

        def _r_fld(parent, fld_type):
            r = etree.SubElement(parent, qn("r"))
            etree.SubElement(etree.SubElement(r, qn("rPr")), qn("noProof"))
            etree.SubElement(r, qn("fldChar")).set(qn("fldCharType"), fld_type)

        def _r_instr(parent, instr_text):
            r = etree.SubElement(parent, qn("r"))
            etree.SubElement(etree.SubElement(r, qn("rPr")), qn("noProof"))
            it = etree.SubElement(r, qn("instrText"))
            it.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            it.text = instr_text

        _r_text(hyp, text)
        _r_tab(hyp)
        _r_fld(hyp, "begin")
        _r_instr(hyp, f" PAGEREF {anchor} \\h ")
        _r_fld(hyp, "separate")
        _r_text(hyp, "1")
        _r_fld(hyp, "end")
        return p

    if mode in ("figures", "tables"):
        new_entries = [_build_figure_entry(t, a) for t, a in fig_entries]
    else:
        new_entries = [_build_toc_entry(*h) for h in headings]

    # Step 6 — Remove cached entries. There are TWO sources of stale
    # content we have to clean up:
    #   (a) Paragraphs strictly BETWEEN sep_para and end_para — every
    #       TOC entry that lives in its own paragraph. Walk + remove.
    #   (b) Content INSIDE sep_para AFTER the `separate` fldChar (and
    #       inside end_para BEFORE the `end` fldChar) — the source
    #       templates pack the FIRST cached TOC entry into the same
    #       paragraph as the `separate` fldChar (so the source's
    #       "1.0 Executive Summary 1-4" ends up adjacent to the
    #       fldChar markers). Without removing this we'd keep the
    #       stale first entry as a duplicate alongside our rebuilt
    #       ones — visibly the "TOC shows two copies of Executive
    #       Summary" bug.
    for victim in children[sep_idx + 1:end_idx]:
        sep_parent.remove(victim)

    def _strip_after(fld_char, para):
        """Remove every sibling of `fld_char`'s ancestor <w:r> that comes
        AFTER it within `para`. We walk from after the fldChar's parent
        <w:r> to the end of the paragraph, removing each."""
        # The fldChar lives in <w:r>; remove every subsequent direct
        # child of <w:p> after that <w:r>.
        host_r = fld_char.getparent()
        while host_r is not None and host_r.getparent() is not para:
            host_r = host_r.getparent()
        if host_r is None:
            return
        # Collect siblings that follow `host_r`.
        following = list(host_r.itersiblings())
        for sib in following:
            para.remove(sib)

    def _strip_before(fld_char, para):
        """Remove every direct sibling of `fld_char`'s ancestor <w:r>
        that comes BEFORE it within `para`, EXCEPT the paragraph's
        <w:pPr>. The pPr stays so the paragraph keeps its styling."""
        host_r = fld_char.getparent()
        while host_r is not None and host_r.getparent() is not para:
            host_r = host_r.getparent()
        if host_r is None:
            return
        preceding = list(host_r.itersiblings(preceding=True))
        for sib in preceding:
            if sib.tag == qn("pPr"):
                continue
            para.remove(sib)

    _strip_after(toc_separate, sep_para)
    _strip_before(toc_end, end_para)

    # Insert new entries after the separator paragraph (= before the
    # terminator).
    insert_at = list(sep_parent).index(sep_para) + 1
    for entry in new_entries:
        sep_parent.insert(insert_at, entry)
        insert_at += 1

    new_xml = etree.tostring(
        root, xml_declaration=True, encoding="UTF-8", standalone=True,
    )
    if new_xml == xml_bytes:
        return len(new_entries)

    tmp = docx_path.with_suffix(".toc.tmp.docx")
    try:
        with zipfile.ZipFile(docx_path, "r") as zin, \
             zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename == "word/document.xml":
                    zout.writestr(item, new_xml)
                else:
                    zout.writestr(item, zin.read(item.filename))
        shutil.move(str(tmp), str(docx_path))
    finally:
        if tmp.exists():
            try: tmp.unlink()
            except OSError: pass

    return len(new_entries)


def add_border_to_all_images(docx_path: Path) -> None:
    """
    Post-process a rendered Word document to add black 1pt borders to all inline images.
    This makes screenshots more visible in the final report.
    Modifies the document in place.
    """
    from docx import Document
    
    doc = Document(str(docx_path))
    modified = False
    
    for paragraph in doc.paragraphs:
        for run in paragraph.runs:
            # Check if this run contains an inline picture element
            pics = run._element.xpath('.//pic:pic')
            for pic in pics:
                # Find or create spPr (shape properties) element
                spPr = pic.find(qn('pic:spPr'))
                if spPr is None:
                    spPr = OxmlElement('pic:spPr')
                    pic.append(spPr)
                
                # Find or create ln (line/outline) element
                ln = spPr.find(qn('a:ln'))
                if ln is None:
                    ln = OxmlElement('a:ln')
                    ln.set('w', '12700')  # 1pt border width (12700 EMUs = 1pt)
                    spPr.append(ln)
                else:
                    # Update existing border width
                    ln.set('w', '12700')
                
                # Clear any existing fill, then add solid black fill
                for child in list(ln):
                    ln.remove(child)
                
                solidFill = OxmlElement('a:solidFill')
                srgbClr = OxmlElement('a:srgbClr')
                srgbClr.set('val', '000000')  # Black color
                solidFill.append(srgbClr)
                ln.append(solidFill)
                
                modified = True
    
    if modified:
        doc.save(str(docx_path))


def _left_align_image_paragraphs(docx_path: Path) -> None:
    """Centre every paragraph that contains an inline image or is a figure
    caption, and style captions (Verdana 8pt grey).

    (Name kept for call-site compatibility; behaviour is now CENTER — the team
    wants screenshots + captions centred, not flush-left.)
    """
    from docx import Document
    from docx.shared import Pt, RGBColor
    doc = Document(str(docx_path))
    # Screenshots VibeDocs inserts are INLINE images (<wp:inline>). Decorative
    # template shapes — e.g. the green Confidentiality-panel background — are
    # ANCHORED/floating (<wp:anchor>). We only ever want to centre real inline
    # screenshots; centring an anchored-shape paragraph also centres that page's
    # body text and jumbles it (the Confidentiality Statement bug).
    _WP_NS = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
    _inline_tag = f"{{{_WP_NS}}}inline"
    _CAPTION_GREY = RGBColor.from_string("7F7F7F")   # 127,127,127
    _CENTER = 1  # WD_ALIGN_PARAGRAPH.CENTER
    modified = False

    def _style_caption_runs(paragraph) -> None:
        """Figure captions: Verdana 8pt, grey 127,127,127."""
        for run in paragraph.runs:
            try:
                run.font.name = "Verdana"
                run.font.size = Pt(8)
                run.font.color.rgb = _CAPTION_GREY
            except Exception:
                continue

    for paragraph in doc.paragraphs:
        if paragraph._element.findall(f".//{_inline_tag}"):
            paragraph.alignment = _CENTER
            modified = True
        else:
            # Centre Caption-styled paragraphs and programmatically-added
            # "Figure N" fallback paragraphs (when Caption style is absent).
            is_caption_style = (
                paragraph.style and paragraph.style.name == "Caption"
            )
            text = paragraph.text.strip()
            is_figure_text = text.startswith("Figure ") and len(text) < 200
            if is_caption_style or is_figure_text:
                paragraph.alignment = _CENTER
                _style_caption_runs(paragraph)
                modified = True
    if modified:
        doc.save(str(docx_path))


# ---- Public entry point ----

def render_report(
    template_path: Path,
    output_path: Path,
    context: dict[str, Any],
    inline_images: dict[str, str] | None = None,
    is_draft: bool = True,
    embed_attachments: list[dict] | None = None,
) -> Path:
    """
    Render `template_path` against `context` and write to `output_path`.

    `inline_images` is an optional dict of {placeholder_name: file_path}. Each entry is
    available in the template as `{{ images.<placeholder_name> }}`.

    Returns the output path.
    """
    # Defensive copy: docxtpl opens the file in place. We make a temp copy
    # and run _fix_split_jinja_tags on it so Word-induced tag splitting
    # (e.g. {%p for f in findings %} broken across <w:r> runs by autocorrect)
    # doesn't blow up rendering with "Encountered unknown tag 'endfor'".
    with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as tf:
        prep_path = Path(tf.name)
    shutil.copyfile(str(template_path), str(prep_path))
    try:
        _fix_split_jinja_tags(prep_path)
        tpl = DocxTemplate(str(prep_path))
        _render_and_save(tpl, prep_path, output_path, context, inline_images,
                         is_draft, embed_attachments=embed_attachments)
    finally:
        try: prep_path.unlink()
        except FileNotFoundError: pass

    return output_path


def _extract_caption(entry) -> str:
    """Pull the caption string out of a `{path, caption}` screenshot
    entry. Returns "" for any shape that doesn't carry one."""
    if isinstance(entry, dict):
        cap = entry.get("caption")
        if isinstance(cap, str):
            return cap.strip()
    return ""


def _render_and_save(tpl, prep_path: Path, output_path: Path,
                     context: dict, inline_images: dict | None,
                     is_draft: bool,
                     embed_attachments: list[dict] | None = None) -> None:
    """The original render body, moved here so we can wrap the template copy.

    `embed_attachments` is threaded from the public `render_report`
    entry point so the post-render OLE-embed pass below can see it.
    It may also be supplied via the side-channel `_embed_attachments`
    key on `context` — see the pop block immediately below.
    """
    # Work on a shallow copy so that InlineImage / Subdoc objects we
    # create below (which are bound to THIS template instance) don't
    # leak back to the caller. Findings are individually shallow-copied
    # for the same reason.
    import copy as _copy
    context = {**context}
    if "findings" in context:
        context["findings"] = [dict(f) for f in context["findings"]]
    # Wrap image paths as InlineImage objects
    images = {}
    if inline_images:
        for key, path in inline_images.items():
            if path and Path(path).exists():
                images[key] = _sized_image(tpl, path)
            else:
                images[key] = ""

    # For findings with screenshots, attach InlineImage objects.
    #
    # `screenshots` schema changed in the per-finding-captions session
    # from a flat list of path strings to a list of `{path, caption}`
    # dicts. The renderer must accept BOTH forms forever so legacy
    # findings keep rendering. The helper below extracts the path
    # regardless of shape and drops anything that isn't a usable
    # filesystem reference — passing a dict straight to `Path(...)` /
    # `InlineImage(...)` is what produced the
    # `TypeError: argument should be a str ... not 'dict'` preview
    # error.
    def _shot_path(entry):
        if isinstance(entry, str):
            return entry
        if isinstance(entry, dict):
            p = entry.get("path")
            return p if isinstance(p, str) else None
        return None

    from . import html_sanitize, html_to_docx
    # Visual order in the VibeDocs template is:
    #   Affected Asset → Observations(description) → [SCREENSHOTS section] →
    #   Steps to Reproduce(poc_steps) → Implications(impact) →
    #   Recommendations(remediation) → references → Management Comments
    #   (client_statement) → Follow-Up Observations(retest_notes) →
    #   [RETEST SCREENSHOTS section].
    # So only affected_asset + description sit BEFORE the uploaded-screenshots
    # section; everything else comes AFTER it. This ordering drives the
    # per-finding "Figure 3.<f>-<n>" sequence so the numbers run in the same
    # order a reader sees the figures.
    _PRE_SHOT_FIELDS = (
        "affected_asset", "description",
    )
    _POST_SHOT_FIELDS = (
        "poc_steps", "impact", "remediation", "references",
        "client_statement", "retest_notes",
    )

    # Figures are numbered PER FINDING and restart at 1 for each finding:
    # "Figure 3.<finding>-<n>" where 3.<finding> is the finding's chapter
    # (chapter 3 = Detailed Findings) and <n> counts every figure in visual
    # order within that finding:
    #   1. inline images in _PRE_SHOT_FIELDS
    #   2. uploaded screenshots  (screenshot_items)
    #   3. inline images in _POST_SHOT_FIELDS
    #   4. uploaded retest evidence  (retest_items)
    for f in context.get("findings", []):
        # Local base 1 — every finding restarts its figure counter.
        f["fig_start"] = 1
        f["fig_prefix"] = f"{DETAILED_FINDINGS_CHAPTER}.{f.get('index', 0)}"

        # Count inline images in each group and record per-field offsets.
        _pre_offsets: dict[str, int] = {}
        _pre_total = 0
        for _key in _PRE_SHOT_FIELDS:
            _val = f.get(_key) or ""
            if html_sanitize.looks_like_html(_val):
                _pre_offsets[_key] = _pre_total
                _pre_total += _count_html_images(_val)

        _shot_count = sum(
            1 for x in (f.get("screenshots") or [])
            if _shot_path(x) and Path(_shot_path(x)).exists()
        )

        _post_offsets: dict[str, int] = {}
        _post_total = 0
        for _key in _POST_SHOT_FIELDS:
            _val = f.get(_key) or ""
            if html_sanitize.looks_like_html(_val):
                _post_offsets[_key] = _post_total
                _post_total += _count_html_images(_val)

        _retest_count = sum(
            1 for x in (f.get("retest_evidence") or [])
            if _shot_path(x) and Path(_shot_path(x)).exists()
        )

        f["_pre_offsets"] = _pre_offsets
        f["_pre_total"] = _pre_total
        f["_post_offsets"] = _post_offsets
        f["_post_total"] = _post_total

    for f in context.get("findings", []):
        # Normalise the per-finding screenshot list to plain path strings
        # BEFORE creating InlineImage wrappers. The Path() existence
        # check below then operates on a real path, not a dict.
        _shot_paths = [
            sp for sp in (_shot_path(x) for x in (f.get("screenshots") or []))
            if sp and Path(sp).exists()
        ]
        # screenshot_captions: parallel list of per-screenshot caption strings
        f["screenshot_captions"] = [
            (_extract_caption(x) if isinstance(x, dict) else "")
            for x in (f.get("screenshots") or [])
            if _shot_path(x) and Path(_shot_path(x)).exists()
        ]
        _pre_total = f.get("_pre_total", 0)
        _post_total = f.get("_post_total", 0)
        _captions = f.get("screenshot_captions") or []
        _prefix = f.get("fig_prefix", "")

        def _fig_label(num: int) -> str:
            return f"{_prefix}-{num}" if _prefix else str(num)

        # Uploaded screenshots: wrap each as image + numbered caption so the
        # template's bare `{{ img }}` loop still gets "Figure 3.<f>-<n>".
        # Local number = pre-group inline images + this screenshot's index.
        f["screenshot_objs"] = [
            _image_caption_subdoc(
                tpl, sp,
                _fig_label(f["fig_start"] + _pre_total + i),
                (_captions[i] if i < len(_captions) else ""),
            )
            for i, sp in enumerate(_shot_paths)
        ]
        # screenshot_items kept for any template that loops it explicitly.
        f["screenshot_items"] = [
            {
                "img": _sized_image(tpl, sp),
                "fig_num": _fig_label(f["fig_start"] + _pre_total + i),
                "caption": (_captions[i] if i < len(_captions) and _captions[i]
                            else f.get("title", "")),
            }
            for i, sp in enumerate(_shot_paths)
        ]

        # Retest evidence has historically been path-strings; accept
        # the dict form too for forward compatibility.
        _retest_entries = [
            x for x in (f.get("retest_evidence") or [])
            if _shot_path(x) and Path(_shot_path(x)).exists()
        ]
        _retest_paths = [_shot_path(x) for x in _retest_entries]
        _retest_caps = [
            (_extract_caption(x) if isinstance(x, dict) else "")
            for x in _retest_entries
        ]
        # Retest figures: numbered after screenshots + post-screenshot inline
        # images. The template renders these with a bare `{{ f.retest_objs }}`
        # (no for-loop), so they must be ONE Subdoc, not a list.
        _retest_fig_start = f["fig_start"] + _pre_total + len(_shot_paths) + _post_total
        f["retest_objs"] = _images_caption_subdoc(
            tpl,
            [
                (sp, _fig_label(_retest_fig_start + i),
                 (_retest_caps[i] if i < len(_retest_caps) else ""))
                for i, sp in enumerate(_retest_paths)
            ],
        )
        f["retest_items"] = [
            {
                "img": _sized_image(tpl, sp),
                "fig_num": _fig_label(_retest_fig_start + i),
            }
            for i, sp in enumerate(_retest_paths)
        ]
        # Convert rich-text (HTML) fields into Subdoc objects so Quill-authored
        # formatting (bold / lists / colours / code blocks) survives into Word.
        # Plain-text fields stay as plain strings — the renderer accepts both.
        # Pass the finding's uploaded screenshot paths so inline
        # `[Screenshot N]` tokens in the rich text get replaced with the
        # matching image at render time. The list is 1-based from the
        # consultant's perspective — `[Screenshot 2]` -> the second
        # uploaded file.
        # Trigger HTML→Subdoc conversion when EITHER the value looks like
        # HTML (Quill-authored rich text) OR it contains an inline
        # `[Screenshot N]` token. The token-resolution code lives inside
        # `html_to_subdoc`, so a plain-text Steps-to-Reproduce paragraph
        # that just types `[Screenshot 1]` on its own line would never
        # otherwise see the rewriter and would render the literal token
        # text. Adding the token check here is what the consultant
        # actually meant — "this is a placeholder for the screenshot at
        # index N", regardless of whether they wrapped the rest of the
        # field in formatted HTML.
        _SCREENSHOT_TOKEN_RE = re.compile(
            r"\[\s*screen\s*shot\s+\d+\s*\]", re.IGNORECASE,
        )

        def _wants_subdoc(value: str | None) -> bool:
            if not value:
                return False
            if html_sanitize.looks_like_html(value):
                return True
            if _shot_paths and _SCREENSHOT_TOKEN_RE.search(value):
                return True
            return False

        def _plaintext_to_html(value: str) -> str:
            """Wrap a plain-text field in minimal HTML so the html_to_subdoc
            parser preserves newlines as line breaks. We split on every
            newline and emit each line as its own `<p>`; that way a
            consultant who hit Enter between Steps to Reproduce items
            ends up with one paragraph per step in the rendered docx,
            matching what they typed in the editor.
            """
            from html import escape as _html_escape
            lines = (value or "").split("\n")
            return "".join(
                "<p>" + _html_escape(ln) + "</p>" for ln in lines
            )

        # Base figure number for post-screenshot fields: after pre-group images
        # and all uploaded screenshots.
        _post_fig_base = f["fig_start"] + _pre_total + len(_shot_paths)

        for key in _PRE_SHOT_FIELDS + _POST_SHOT_FIELDS:
            val = f.get(key)
            if _wants_subdoc(val):
                payload = val if html_sanitize.looks_like_html(val) \
                          else _plaintext_to_html(val)
                _field_fig_start = 0
                if html_sanitize.looks_like_html(val):
                    if key in _PRE_SHOT_FIELDS:
                        _offset = f.get("_pre_offsets", {}).get(key)
                        if _offset is not None:
                            _field_fig_start = f["fig_start"] + _offset
                    else:
                        _offset = f.get("_post_offsets", {}).get(key)
                        if _offset is not None:
                            _field_fig_start = _post_fig_base + _offset
                try:
                    f[key] = html_to_docx.html_to_subdoc(
                        tpl, payload,
                        inline_images=_shot_paths,
                        fig_start=_field_fig_start,
                        fig_prefix=f.get("fig_prefix", ""),
                    )
                except Exception:
                    # Fall back to plain text on conversion error rather than
                    # losing the field entirely.
                    f[key] = re.sub(r"<[^>]+>", "", val)

    context["images"] = images

    # Wrap the severity chart (if generated by the caller) as an InlineImage
    # so the Word template can use {{ severity_chart }} directly.
    chart_path = context.get("severity_chart_path")
    if chart_path and Path(chart_path).exists():
        context["severity_chart"] = InlineImage(tpl, chart_path, width=Mm(160))
    else:
        context["severity_chart"] = ""

    context["generated_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Pop the side-channel `_embed_attachments` list — it carries
    # OLE-embed instructions for the post-render pass and must NOT
    # reach docxtpl (any unknown key in autoescape=True mode is
    # harmless but cluttering the context). Prefer the explicit
    # `embed_attachments` arg passed by the caller; fall back to
    # the context for callers that still embed the list there.
    ctx_embed = context.pop("_embed_attachments", None)
    if embed_attachments is None:
        embed_attachments = ctx_embed

    output_path.parent.mkdir(parents=True, exist_ok=True)
    # autoescape=True is REQUIRED — without it, any user-supplied string
    # containing `<`, `>`, or `&` is injected into the docx XML verbatim
    # and breaks the document structure. Real-world case that motivated
    # this: a consultant put `<JWT_TOKEN>` / `<REFRESH_TOKEN>` placeholders
    # inside `affected_asset`. docxtpl substituted them as literal XML
    # elements; lxml + Word saw `<JWT_TOKEN>...</w:t></w:p><w:p>...` as
    # nested content and dragged every subsequent finding INSIDE that
    # unclosed tag. The PDF preview then only showed the first few
    # findings before the structure imploded.
    #
    # Subdoc / InlineImage / RichText all implement `__html__`, so
    # MarkupSafe treats them as already-escaped — those still render
    # exactly as before. Only bare string fields like `affected_asset`,
    # `title`, `cvss_vector`, etc. get their angle-bracket / ampersand
    # characters HTML-encoded (`&lt;` / `&gt;` / `&amp;`), which is the
    # correct OOXML on-disk encoding and renders back to the original
    # literal characters in Word.
    tpl.render(context, autoescape=True)
    tpl.save(str(output_path))

    # Post-render passes — each one is best-effort and isolated, so a
    # failure in one pass can't corrupt the output. Order matters
    # only insofar as later passes see whatever earlier passes wrote.
    # Wrap each in try/except — if a pass blows up, we'd rather ship
    # the un-decorated docxtpl output than a half-corrupt file the
    # user can't open in Word.
    import logging as _logging
    _passlog = _logging.getLogger(__name__)

    # Inject rendered values into docProps/custom.xml so that LibreOffice
    # resolves cover-page DOCPROPERTY fields (reportType, reportDate, etc.)
    # from the actual report data during DOCX → PDF conversion.
    try:
        _inject_custom_xml_values(output_path, context)
    except Exception as e:                                      # pragma: no cover
        _passlog.warning("custom.xml injection skipped: %s", e)

    # Patch docProps/app.xml <Company> so LibreOffice resolves SDT data
    # bindings (w:dataBinding xpath=".../Company[1]") with the project
    # company alias.  Without this, LibreOffice reads the hardcoded value
    # baked into the template's app.xml and overwrites the docxtpl-rendered
    # {{ details.company_alias }} content in the footer and body SDTs.
    # After patching app.xml, also strip the w:dataBinding elements so
    # LibreOffice cannot re-override on a subsequent open/convert.
    try:
        _company_alias_val = str(
            (context.get('project') or {}).get('company_alias')
            or (context.get('details') or {}).get('company_alias')
            or ''
        )
        _inject_app_xml_company(output_path, _company_alias_val)
        _strip_sdt_data_bindings(output_path)
    except Exception as e:                                      # pragma: no cover
        _passlog.warning("app.xml company / SDT-binding strip skipped: %s", e)

    # Remove yellow highlight formatting carried over from template
    # placeholder runs (docxtpl keeps run formatting when substituting).
    try:
        _strip_yellow_highlights(output_path)
    except Exception as e:                                      # pragma: no cover
        _passlog.warning("yellow-highlight strip skipped: %s", e)

    # CRITICAL FIRST PASS: flatten nested <w:p> elements that ended up
    # inside <w:t> text nodes after docxtpl substituted Subdoc objects
    # at placeholders that weren't bare-paragraph (`{{p ... }}`) form.
    # Without this, LibreOffice drops drawings inside the nested paras
    # during DOCX → PDF conversion — which is what produces the
    # "pasted screenshots invisible in PDF" symptom. Word is more
    # forgiving but the output is still technically malformed OOXML.
    try:
        _flatten_subdoc_paragraphs(output_path)
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("subdoc-paragraph flatten skipped: %s", e)

    # OLE-embed every finding-attachment xlsx into the document. The
    # post-render pass walks `f.description` paragraphs looking for
    # the "Refer to the attached file: …" marker the context builder
    # inserts and replaces it with a centred Excel icon + caption.
    # When the consultant opens the docx in Word they get a
    # double-clickable embedded spreadsheet; the PDF preview shows
    # the icon as a static image. Failure here is non-fatal — the
    # docx still ships with the marker text intact, so the reader
    # always knows the file exists even if the visual icon couldn't
    # be wired up.
    if embed_attachments:
        try:
            from .docx_attachments import embed_xlsx_attachments
            embedded = embed_xlsx_attachments(output_path, embed_attachments)
            if embedded:
                _passlog.info(
                    "embed_xlsx_attachments: %d xlsx file(s) inlined", embedded
                )
        except Exception as e:                              # pragma: no cover
            _passlog.warning("xlsx-attachment embed skipped: %s", e)

    try:
        # Severity-cell auto-colouring (uses atomic temp-file +
        # validation internally, so its own corruption can't leak).
        _apply_severity_cell_colors(output_path)
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("severity-cell colouring skipped: %s", e)

    # Status colouring: Open -> red, Closed -> black (summary table +
    # per-finding detail Status line). Best-effort, atomic internally.
    try:
        _apply_status_colors(output_path)
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("status colouring skipped: %s", e)

    # Relabel the per-finding "CVSS 4.0 Risk Rating" detail header to the
    # version actually in use (e.g. after a re-rate to CVSS 3.1).
    try:
        _relabel_cvss_version(output_path, str(context.get("cvss_version") or "4.0"))
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("cvss version relabel skipped: %s", e)

    # Keep the per-finding detail table inside the page frame: soft-wrap the long
    # CVSS vector + fix the table layout so LibreOffice can't expand a column past
    # the right margin (which clipped the trailing CWE column).
    try:
        _constrain_findings_tables(output_path)
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("findings-table constrain skipped: %s", e)

    # First finding flows after the chapter heading; subsequent findings each
    # start on a new page.
    try:
        _paginate_findings(output_path)
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("findings pagination skipped: %s", e)

    # Combined-report multi-chapter: insert chapter headings between finding groups
    # when multiple test sections are defined (Web VAPT + API VAPT, etc.).
    _report_sections = context.get("report_sections") or []
    _finding_chap_idxs = context.get("_finding_chapter_idxs") or []
    if _report_sections and len(_report_sections) > 1 and _finding_chap_idxs:
        try:
            _add_combined_chapter_headings(
                output_path, _report_sections, _finding_chap_idxs)
        except Exception as e:                              # pragma: no cover
            _passlog.warning("combined chapter headings skipped: %s", e)

    # Exec-summary findings-table caption "as of <date>" -> last testing date.
    try:
        _fix_findings_caption_date(output_path, str(context.get("findings_as_of") or ""))
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("findings caption date skipped: %s", e)

    # §2.3 Testing Coverage: OWASP Top 10 2021 -> 2025 (label + category list).
    try:
        _relabel_owasp_2025(output_path)
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("owasp 2025 relabel skipped: %s", e)

    # Make the "Confidentiality Statement" title visible on the green panel.
    try:
        _ensure_confidentiality_title(output_path)
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("confidentiality title fix skipped: %s", e)

    # Cover title: collapse the doubled "<agency> (<agency>)" into one.
    try:
        _collapse_doubled_client_name(
            output_path, str((context.get("project") or {}).get("client_name") or ""))
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("client-name de-dup skipped: %s", e)

    # §2.5 schedule table: Fieldwork = initial window, Follow Up = retest window.
    try:
        _fill_schedule_table(
            output_path,
            str(context.get("fieldwork_window") or ""),
            str(context.get("followup_window") or ""))
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("schedule table fill skipped: %s", e)

    # GovTech CSG ICT RMM: remove the §2.6.2 section + the RMM column when the
    # report has the RMM methodology disabled.
    if not context.get("rmm_enabled", True):
        try:
            _strip_rmm(output_path)
        except Exception as e:                              # pragma: no cover
            _passlog.warning("RMM strip skipped: %s", e)

    # ---- Watermark model (rev 2026-05-16) ----
    # Every VibeDocs master template SHIPS WITH a "DRAFT" watermark
    # baked into its headers. We no longer strip it at boot and no
    # longer inject our own — that two-sided approach is exactly what
    # produced the stacked double-DRAFT (baked-in survived a failed
    # strip, then our injection landed on top).
    #
    # New rule, single source of truth:
    #   * is_draft  → DO NOTHING. The template's own native DRAFT
    #     renders, exactly once. (in_review forces is_draft upstream.)
    #   * NOT draft → STRIP the native DRAFT from the rendered output
    #     so an approved / published / signed-off deliverable ships
    #     clean (zero watermarks).
    # There is never a second watermark to stack, so a double-DRAFT
    # is structurally impossible regardless of which template (master
    # OR consultant-uploaded custom) the report uses.
    if not is_draft:
        try:
            from .watermark import strip_draft_watermarks
            removed = strip_draft_watermarks(output_path)
            _passlog.info(
                "approved render: stripped %d DRAFT watermark(s)", removed)
        except Exception as e:                              # pragma: no cover
            _passlog.warning("approved-render watermark strip skipped: %s", e)
    else:
        # Draft render: ensure a DRAFT watermark is present. Master templates
        # ship with one baked in, but consultant-uploaded templates may not.
        # Inject only when the rendered docx has no VML watermark already —
        # avoids double-stacking on VibeDocs master templates.
        try:
            if not _docx_has_draft_vml_watermark(output_path):
                _inject_watermark(output_path)
                _passlog.info("draft render: injected DRAFT watermark (template had none)")
        except Exception as e:                              # pragma: no cover
            _passlog.warning("draft watermark inject skipped: %s", e)

    # Add black borders to all screenshots for better visibility
    try:
        add_border_to_all_images(output_path)
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("image border pass skipped: %s", e)

    # Left-align all paragraphs containing inline images
    try:
        _left_align_image_paragraphs(output_path)
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("image left-align pass skipped: %s", e)

    # Force Word / LibreOffice to refresh every TOC + numbering field
    # the next time the file is opened. Useful for Word — the user
    # gets prompted "Update fields?" → Yes. LibreOffice's headless PDF
    # conversion (our preview / generate pipeline) IGNORES this flag,
    # so we ALSO rebuild the TOC cached content programmatically
    # below — that's what makes the PDF preview show every finding
    # in the TOC without a manual Word round-trip.
    try:
        _enable_update_fields_on_open(output_path)
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("update-fields-on-open flag skipped: %s", e)

    # Table captions ("Table 1-1:"): replace the STYLEREF/SEQ chapter-number
    # fields with static text, because LibreOffice renders STYLEREF \s as the
    # chapter NAME, not the number. Must precede the Table-of-Tables rebuild so
    # the ToT collects the corrected text and _patch_toc_pages can match it.
    try:
        _n_caps = _fix_table_caption_numbers(output_path)
        if _n_caps:
            _passlog.info("Table caption numbers staticised: %d", _n_caps)
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("table caption number fix skipped: %s", e)

    # Chapter-relative page numbers ("2-1"): rewrite each body section's footer
    # to print a static chapter number + the live PAGE field, because LibreOffice
    # ignores Word's pgNumType chapStyle. Runs before the TOC rebuild so the
    # PDF footer label is correct when _patch_toc_pages later reads it back.
    try:
        _n_ftr = _apply_chapter_page_footers(output_path)
        if _n_ftr:
            _passlog.info("Chapter-page footers applied to %d body section(s)", _n_ftr)
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("chapter-page footer pass skipped: %s", e)

    # Rebuild the TOC cached content to reflect the actual heading
    # list in the rendered document. The VibeDocs source templates
    # ship with a TOC that lists ONE example finding ("3.1 Public
    # Facing Intranet Login Page"); without this pass, every report
    # still shows just that one entry in the TOC regardless of how
    # many findings the consultant has. LibreOffice's docx→pdf
    # conversion doesn't auto-update TOC fields even with the flag
    # set above, so we have to write the entries ourselves.
    try:
        _rebuild_toc(output_path)
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("TOC rebuild skipped: %s", e)

    # Table of Figures: same problem (LibreOffice won't evaluate the field),
    # plus our captions use a custom "3.x-n" number rather than a Word SEQ
    # field, so Word's native collection can't see them either. Populate the
    # ToF cache from the actual "Figure …" caption paragraphs.
    try:
        _n_figs = _rebuild_toc(output_path, mode="figures")
        if _n_figs:
            _passlog.info("Table of Figures rebuilt with %d entries", _n_figs)
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("Table of Figures rebuild skipped: %s", e)

    # Table of Tables: same LibreOffice limitation. Rebuilding the cache from
    # the actual "Table …" caption paragraphs keeps the third table consistent
    # with the Contents and Figures tables — the PAGEREF cells then receive the
    # chapter-relative "3-1" page labels in _patch_toc_pages on PDF export.
    try:
        _n_tbls = _rebuild_toc(output_path, mode="tables")
        if _n_tbls:
            _passlog.info("Table of Tables rebuilt with %d entries", _n_tbls)
    except Exception as e:                                  # pragma: no cover
        _passlog.warning("Table of Tables rebuild skipped: %s", e)


# ============================================================
# custom.xml value injection — post-render pass
# ============================================================

def _inject_custom_xml_values(docx_path: Path, context: dict) -> None:
    """Render Jinja2 expressions in docProps/custom.xml using string-safe context values.

    The master Word templates now contain Jinja2 expressions in their custom.xml
    property values (e.g. ``{{ details.client_name }}``). docxtpl does not process
    custom.xml, so after ``tpl.save()`` those expressions are still literal.
    This pass opens the rendered docx, renders any ``{{ … }}`` expressions in
    custom.xml with the report context, and writes it back.
    LibreOffice uses custom.xml to resolve cover-page DOCPROPERTY fields when
    converting DOCX → PDF, so this ensures the correct values appear.
    """
    import zipfile as _zf
    import re as _re
    from jinja2 import Environment as _JEnv, Undefined as _Undef

    part = 'docProps/custom.xml'
    with _zf.ZipFile(docx_path, 'r') as z:
        if part not in z.namelist():
            return
        xml = z.read(part).decode('utf-8')

    # Build a flat string-only context; skip complex objects (InlineImage, Subdoc, etc.)
    details = context.get('details') or {}
    _company_alias = str(
        (context.get('project') or {}).get('company_alias')
        or details.get('company_alias')
        or ''
    )
    flat: dict = {
        'details': {
            'client_name':       str(details.get('client_name') or ''),
            'application_name':  str(details.get('application_name') or ''),
            'report_type':       str(details.get('report_type') or ''),
            'report_date':       str(details.get('report_date') or ''),
            'report_year':       str(details.get('report_year') or ''),
            'doc_version':       str(context.get('report', {}).get('version') or details.get('doc_version') or '0.1'),
            # Company alias for DOCPROPERTY-based footer and inline references.
            'company_alias':     _company_alias,
        },
        'project': {
            'company_alias': _company_alias,
        },
    }

    # Render only if the XML actually contains Jinja2 expressions (quick guard)
    if '{{' not in xml:
        return

    # Use Jinja2's sandbox-free environment with autoescape so values are XML-safe
    env = _JEnv(autoescape=True)
    rendered = env.from_string(xml).render(flat)

    # Write the updated XML back into the docx (atomic temp-file approach)
    import tempfile as _tmp, shutil as _sh
    tmp = docx_path.with_suffix('.tmp.docx')
    names: list[str]
    parts: dict[str, bytes]
    with _zf.ZipFile(docx_path, 'r') as z:
        names = z.namelist()
        parts = {n: z.read(n) for n in names}
    parts[part] = rendered.encode('utf-8')
    with _zf.ZipFile(tmp, 'w', _zf.ZIP_DEFLATED) as z:
        for n in names:
            z.writestr(n, parts[n])
    tmp.replace(docx_path)


# ============================================================
# app.xml Company injection — post-render pass
# ============================================================

def _inject_app_xml_company(docx_path: Path, company_alias: str) -> None:
    """Patch docProps/app.xml <Company> with the project company alias.

    LibreOffice reads this element during DOCX→PDF conversion and uses it to
    populate SDT content controls bound via w:dataBinding to app.xml Company.
    Without this patch those SDTs always show the template's original hardcoded
    company name regardless of what docxtpl rendered into w:sdtContent.
    """
    import zipfile as _zf
    import re as _re
    import html as _html

    part = 'docProps/app.xml'
    with _zf.ZipFile(docx_path, 'r') as z:
        if part not in z.namelist():
            return
        names = z.namelist()
        parts = {n: z.read(n) for n in names}

    xml = parts[part].decode('utf-8')
    alias_escaped = _html.escape(company_alias, quote=False)

    new_xml, n = _re.subn(
        r'<Company>[^<]*</Company>',
        f'<Company>{alias_escaped}</Company>',
        xml,
    )
    if n == 0:
        # Element missing — insert before closing </Properties>
        new_xml = _re.sub(
            r'</Properties>',
            f'<Company>{alias_escaped}</Company></Properties>',
            xml, count=1,
        )
    if new_xml == xml:
        return

    parts[part] = new_xml.encode('utf-8')
    tmp = docx_path.with_suffix('.tmp.docx')
    with _zf.ZipFile(tmp, 'w', _zf.ZIP_DEFLATED) as z:
        for name in names:
            z.writestr(name, parts[name])
    tmp.replace(docx_path)


def _strip_sdt_data_bindings(docx_path: Path) -> int:
    """Remove <w:dataBinding .../> elements from all word/*.xml parts.

    SDTs with w:dataBinding are overwritten by LibreOffice during DOCX→PDF
    conversion using data from docProps/app.xml or custom.xml, which overwrites
    the Jinja2-rendered content docxtpl placed in w:sdtContent.  Removing the
    binding element turns each SDT into a plain content control that LibreOffice
    leaves untouched, so the rendered values survive into the PDF.

    Returns the count of binding elements removed.
    """
    import zipfile as _zf
    import re as _re

    with _zf.ZipFile(docx_path, 'r') as z:
        names = z.namelist()
        parts = {n: z.read(n) for n in names}

    total = 0
    for pname in names:
        if not (pname.startswith('word/') and pname.endswith('.xml')):
            continue
        xml = parts[pname].decode('utf-8', errors='replace')
        new_xml, count = _re.subn(
            r'<w:dataBinding\b.*?/>',
            '',
            xml,
            flags=_re.DOTALL,
        )
        if count:
            parts[pname] = new_xml.encode('utf-8')
            total += count

    if total == 0:
        return 0

    tmp = docx_path.with_suffix('.tmp.docx')
    with _zf.ZipFile(tmp, 'w', _zf.ZIP_DEFLATED) as z:
        for name in names:
            z.writestr(name, parts[name])
    tmp.replace(docx_path)
    return total


def _strip_yellow_highlights(docx_path: Path) -> int:
    """Remove yellow highlight formatting from all word/*.xml parts.

    docxtpl preserves run-level formatting from the template when substituting
    placeholder values.  Template placeholders that had yellow highlight applied
    (to make them visible during template authoring) carry that highlight into
    the rendered output.  This pass strips <w:highlight w:val="yellow"/> so the
    delivered report has clean, unhighlighted text.

    Returns the count of highlight elements removed.
    """
    import zipfile as _zf
    import re as _re

    with _zf.ZipFile(docx_path, 'r') as z:
        names = z.namelist()
        parts = {n: z.read(n) for n in names}

    total = 0
    for pname in names:
        if not (pname.startswith('word/') and pname.endswith('.xml')):
            continue
        xml = parts[pname].decode('utf-8', errors='replace')
        new_xml, count = _re.subn(
            r'<w:highlight\s+w:val="yellow"\s*/>',
            '',
            xml,
        )
        if count:
            parts[pname] = new_xml.encode('utf-8')
            total += count

    if total == 0:
        return 0

    tmp = docx_path.with_suffix('.tmp.docx')
    with _zf.ZipFile(tmp, 'w', _zf.ZIP_DEFLATED) as z:
        for name in names:
            z.writestr(name, parts[name])
    tmp.replace(docx_path)
    return total


# ============================================================
# Severity cell coloring — post-render pass
# ============================================================

# Background / font palette per severity — WORD REPORT only.
# The Excel Risk-Register tracker uses a different palette
# (`risk_register.SEVERITY_FILL_HEX` / `SEVERITY_FONT_HEX`) so the
# tracker import/export keeps matching the VibeDocs master template's
# original red/amber/green shades. The two palettes are deliberately
# decoupled — visual style of the Word deliverable can evolve without
# breaking the Excel round-trip.
#
# 2026-05 palette refresh: Critical is a soft pink-red (`#FF8686`)
# that reads better with black text than the previous deep red.
# Every other shade is dark enough to need white text for legibility.
SEVERITY_CELL_PALETTE = {
    "Critical":      ("C00000", "FFFFFF"),  # 192,0,0   dark red,   white text
    "High":          ("FF0000", "FFFFFF"),  # 255,0,0   red,        white text
    "Medium":        ("FFC000", "000000"),  # 255,192,0 amber,      black text
    "Low":           ("92D050", "000000"),  # 146,208,80 green,     black text
    "Informational": ("00B0F0", "000000"),  # 0,176,240 light blue, black text
    # Alias — the Word/Excel deliverables now display "Info" (shortened from
    # "Informational"); same palette so both spellings paint identically.
    "Info":          ("00B0F0", "000000"),
}


# `w:shd` must appear at a specific position inside `w:tcPr` per the
# OOXML schema (right after `w:tcBorders`, before `w:noWrap` etc.).
# `append()` puts it at the END which is schema-invalid AND triggers
# the "Word experienced an error trying to open the file" dialog the
# moment any `w:tcMar` / `w:vAlign` follows. List of element names
# that legally come BEFORE `w:shd` so we can find the right slot.
_TCPR_SHD_PREDECESSORS = (
    "cnfStyle", "tcW", "gridSpan", "hMerge", "vMerge", "tcBorders",
)


def _insert_shd_in_tcpr(tc_pr, shd) -> None:
    """Place `shd` at the correct OOXML schema position inside `tc_pr`.
    Skips re-inserting if a `shd` already exists (caller removed it).
    """
    from docx.oxml.ns import qn
    # Find the last predecessor element already present; new `shd`
    # goes right after it.
    insert_index = 0
    for i, child in enumerate(list(tc_pr)):
        tag = child.tag.split('}', 1)[-1] if '}' in child.tag else child.tag
        if tag in _TCPR_SHD_PREDECESSORS:
            insert_index = i + 1
    tc_pr.insert(insert_index, shd)


def _constrain_findings_tables(docx_path: Path) -> None:
    """Keep the per-finding detail table inside the page frame.

    The VibeDocs finding table is authored as ``tblW=100% (auto-fit)`` with a
    "CVSS Vector" column holding a long unbreakable token (e.g.
    ``CVSS:4.0/AV:N/AC:H/AT:N/...``). Headless LibreOffice grows that column to
    fit the token, pushing the table — and the trailing CWE column — past the
    right margin (the "CWE-28[5]" cut-off). Applied to every table whose header
    row carries a "CVSS Vector" cell:

      1. Soft-wrap the vector: insert U+200B (zero-width space) after each ``/``
         and ``:`` so it wraps WITHIN its column instead of forcing it wider.
      2. Fixed table layout (``table.autofit = False``) so columns honour their
         grid widths rather than growing to content. The template authors the
         table at ``tblW=100%``, so LibreOffice still scales it to fill the text
         frame — it just can no longer stretch a single column past the margin.
    """
    try:
        from docx import Document
    except Exception:                                       # pragma: no cover
        return
    try:
        doc = Document(str(docx_path))
    except Exception:                                       # pragma: no cover
        return

    ZWSP = "​"
    changed = False
    for table in doc.tables:
        try:
            rows = table.rows
        except Exception:
            continue
        if not rows:
            continue
        header = [(c.text or "").strip().lower() for c in rows[0].cells]
        if "cvss vector" not in header:
            continue
        vec_col = header.index("cvss vector")

        # (2) fixed layout — python-docx writes a schema-correct <w:tblLayout>.
        try:
            table.autofit = False
            changed = True
        except Exception:
            pass

        # (1) soft-wrap the CVSS vector cell(s)
        try:
            for row in rows[1:]:
                if vec_col >= len(row.cells):
                    continue
                cell = row.cells[vec_col]
                if "cvss" not in (cell.text or "").lower():
                    continue
                for para in cell.paragraphs:
                    for run in para.runs:
                        t = run.text
                        if t and ("/" in t or ":" in t):
                            nt = t.replace("/", "/" + ZWSP).replace(":", ":" + ZWSP)
                            if nt != t:
                                run.text = nt
                                changed = True
        except Exception:
            pass

    if changed:
        try:
            doc.save(str(docx_path))
        except Exception:                                   # pragma: no cover
            pass


def _apply_severity_cell_colors(docx_path: Path) -> None:
    """Walk every table in the rendered DOCX and paint any cell whose
    text is exactly a severity keyword with the matching fill + font
    colour.

    Best-effort, atomic, and self-defeating on failure: writes to a
    sibling temp file, verifies the temp file re-opens cleanly under
    python-docx, then atomically replaces the original. ANY failure
    along the way leaves the original docxtpl output untouched —
    the worst case is the deliverable ships without auto-coloured
    severity cells, NOT with a corrupted file Word can't open.

    Matching rule: `cell.text.strip()` must EQUAL one of the
    `SEVERITY_CELL_PALETTE` keys. We don't want to colour a cell whose
    description happens to contain the word "Critical" — only cells
    that ARE a severity value.
    """
    try:
        from docx import Document
        from docx.oxml.ns import qn
        from docx.oxml import OxmlElement
        from docx.shared import RGBColor
    except Exception:                                       # pragma: no cover
        return

    try:
        doc = Document(str(docx_path))
    except Exception:                                       # pragma: no cover
        # docxtpl produced output python-docx can't parse —
        # leave the file as-is and skip coloring entirely.
        return

    touched = False

    def _paint(cell, bg_hex: str, fg_hex: str) -> None:
        nonlocal touched
        try:
            tc_pr = cell._tc.get_or_add_tcPr()
            # Remove any existing shading first so we don't end up with
            # two `w:shd` tags in the same `tcPr` (Word would keep
            # only the first — frequently the VibeDocs template's
            # original "example" colour).
            for existing in list(tc_pr.findall(qn("w:shd"))):
                tc_pr.remove(existing)
            shd = OxmlElement("w:shd")
            shd.set(qn("w:val"), "clear")
            shd.set(qn("w:color"), "auto")
            shd.set(qn("w:fill"), bg_hex)
            # Schema-correct position — NOT `append()`.
            _insert_shd_in_tcpr(tc_pr, shd)
            # Font colour on every run in the cell.
            for paragraph in cell.paragraphs:
                for run in paragraph.runs:
                    try:
                        run.font.color.rgb = RGBColor.from_string(fg_hex)
                    except Exception:
                        continue
            touched = True
        except Exception:                                   # pragma: no cover
            # If even one cell mutation fails, skip it but keep going
            # — we still want every OTHER severity cell coloured.
            return

    # Severity keywords used to detect summary tables.
    _SEV_KEYS = frozenset(SEVERITY_CELL_PALETTE)

    def _vcenter_cell(cell) -> None:
        """Set a table cell's vertical alignment to center."""
        try:
            tc_pr = cell._tc.get_or_add_tcPr()
            existing = tc_pr.findall(qn("w:vAlign"))
            for e in existing:
                tc_pr.remove(e)
            va = OxmlElement("w:vAlign")
            va.set(qn("w:val"), "center")
            tc_pr.append(va)
        except Exception:
            pass

    def _normalize_severity_table(table) -> None:
        """If this table has a severity-header row, centre-align every cell
        in the table vertically and horizontally so all count values sit at
        the same position regardless of how the template was authored."""
        try:
            has_severity_row = False
            for row in table.rows:
                texts = {(c.text or "").strip() for c in row.cells}
                if len(texts & _SEV_KEYS) >= 2:
                    has_severity_row = True
                    break
            if not has_severity_row:
                return
            for row in table.rows:
                for cell in row.cells:
                    _vcenter_cell(cell)
                    # Also ensure paragraph horizontal alignment is centre
                    # for cells that contain only a number (count cells).
                    ct = (cell.text or "").strip()
                    if ct.isdigit():
                        for para in cell.paragraphs:
                            try:
                                para.alignment = 1  # WD_ALIGN_PARAGRAPH.CENTER
                            except Exception:
                                pass
        except Exception:
            pass

    # --- Chapter 2.6.2 GovTech CSG ICT RMM risk-rating matrix ---
    # This static table lists risk ratings (Low / Medium / Medium-High /
    # High / Very High) in a likelihood × impact grid. It is NOT a findings
    # table, so it must NOT be repainted with the per-finding severity
    # palette. Per spec: every rating word renders in BLACK font (the
    # template's own cell fills are kept), EXCEPT "Very High" which follows
    # the Critical scheme (dark-red fill, white font).
    _RMM_RISK_WORDS = {"low", "medium", "medium-high", "high", "very high"}

    def _is_rmm_matrix(table) -> bool:
        try:
            for row in table.rows:
                for c in row.cells:
                    t = (c.text or "").strip().lower()
                    if t in ("very high", "medium-high") or "highly likely" in t:
                        return True
        except Exception:                                   # pragma: no cover
            return False
        return False

    def _set_cell_font(cell, fg_hex: str) -> None:
        nonlocal touched
        for paragraph in cell.paragraphs:
            for run in paragraph.runs:
                try:
                    run.font.color.rgb = RGBColor.from_string(fg_hex)
                except Exception:
                    continue
        touched = True

    def _paint_rmm_matrix(table) -> None:
        for row in table.rows:
            for cell in row.cells:
                tl = (cell.text or "").strip().lower()
                if tl not in _RMM_RISK_WORDS:
                    continue
                if tl == "very high":
                    _paint(cell, "C00000", "FFFFFF")   # Critical scheme
                else:
                    _set_cell_font(cell, "000000")     # black font, keep fill

    def _rename_cell_text(cell, new: str) -> bool:
        """If the cell's text is exactly 'Informational', rewrite it to
        `new` ('Info') in-place, preserving the first run's formatting."""
        nonlocal touched
        for paragraph in cell.paragraphs:
            runs = paragraph.runs
            if not runs:
                continue
            if "".join(r.text for r in runs).strip() == "Informational":
                runs[0].text = new
                for r in runs[1:]:
                    r.text = ""
                touched = True
                return True
        return False

    def _walk_tables(tables) -> None:
        for table in tables:
            try:
                # The RMM matrix gets its own scheme and is excluded from
                # the per-finding palette (its High/Medium/Low cells would
                # otherwise be mis-painted as finding severities).
                if _is_rmm_matrix(table):
                    _paint_rmm_matrix(table)
                    continue
                _normalize_severity_table(table)
                for row in table.rows:
                    for cell in row.cells:
                        text = (cell.text or "").strip()
                        # Display rename: "Informational" -> "Info" anywhere
                        # it appears as a standalone severity cell (summary
                        # count table label AND per-finding Risk cells).
                        if text == "Informational":
                            _rename_cell_text(cell, "Info")
                            text = "Info"
                        if text in SEVERITY_CELL_PALETTE:
                            bg, fg = SEVERITY_CELL_PALETTE[text]
                            _paint(cell, bg, fg)
                        # Recurse into nested tables (VibeDocs's
                        # Management Comments nested table etc.).
                        try:
                            for inner_tbl in cell.tables:
                                _walk_tables([inner_tbl])
                        except Exception:                   # pragma: no cover
                            continue
            except Exception:                               # pragma: no cover
                continue

    _walk_tables(doc.tables)

    if not touched:
        return

    # ---- Atomic write: tmp → validate → replace ----
    import shutil as _shutil
    tmp_path = docx_path.with_suffix(docx_path.suffix + ".colortmp")
    try:
        doc.save(str(tmp_path))
    except Exception:                                       # pragma: no cover
        try: tmp_path.unlink(missing_ok=True)
        except Exception: pass
        return

    # Re-open the temp file to verify python-docx can read what it
    # just wrote. If it round-trips cleanly, atomic-replace; otherwise
    # discard and keep the original.
    try:
        Document(str(tmp_path))
    except Exception:                                       # pragma: no cover
        try: tmp_path.unlink(missing_ok=True)
        except Exception: pass
        return

    try:
        _shutil.move(str(tmp_path), str(docx_path))
    except Exception:                                       # pragma: no cover
        try: tmp_path.unlink(missing_ok=True)
        except Exception: pass
        return


# Status font colours for the Word deliverable.
#   Open   -> red   (still outstanding)
#   Closed -> black (remediated; no longer flagged red)
# Other statuses (e.g. "NA" for informational items) are left with whatever
# colour the template applied, so we don't accidentally recolour unrelated text.
_STATUS_FONT_HEX = {
    "open": "FF0000",            # outstanding -> red
    "closed": "000000",          # remediated -> black
    "na": "000000",              # informational / not-applicable -> black (not red)
    "n/a": "000000",
    "risk accepted": "000000",
    "false positive": "000000",
    "in remediation": "000000",
}


def _apply_status_colors(docx_path: Path) -> None:
    """Recolour finding-status text in the rendered DOCX: 'Open' red,
    'Closed' black. Walks both table cells (summary Risk Register) and
    body paragraphs (per-finding detail "Status" value). Atomic + best
    effort — any failure leaves the docxtpl output untouched.
    """
    try:
        from docx import Document
        from docx.shared import RGBColor
    except Exception:                                       # pragma: no cover
        return
    try:
        doc = Document(str(docx_path))
    except Exception:                                       # pragma: no cover
        return

    touched = False

    def _recolor_runs(paragraph) -> None:
        nonlocal touched
        key = (paragraph.text or "").strip().lower()
        hexv = _STATUS_FONT_HEX.get(key)
        if not hexv:
            return
        for run in paragraph.runs:
            try:
                run.font.color.rgb = RGBColor.from_string(hexv)
                touched = True
            except Exception:
                continue

    # Body paragraphs (per-finding detail Status line).
    for paragraph in doc.paragraphs:
        _recolor_runs(paragraph)

    # Table cells (summary Risk Register Status column + nested tables).
    def _walk(tables) -> None:
        for table in tables:
            try:
                for row in table.rows:
                    for cell in row.cells:
                        for paragraph in cell.paragraphs:
                            _recolor_runs(paragraph)
                        try:
                            for inner in cell.tables:
                                _walk([inner])
                        except Exception:                   # pragma: no cover
                            continue
            except Exception:                               # pragma: no cover
                continue

    _walk(doc.tables)

    if not touched:
        return

    import shutil as _shutil
    tmp_path = docx_path.with_suffix(docx_path.suffix + ".statustmp")
    try:
        doc.save(str(tmp_path))
        Document(str(tmp_path))                              # validate round-trip
        _shutil.move(str(tmp_path), str(docx_path))
    except Exception:                                       # pragma: no cover
        try: tmp_path.unlink(missing_ok=True)
        except Exception: pass
        return


def _relabel_cvss_version(docx_path: Path, version: str) -> None:
    """Relabel the per-finding detail header "CVSS 4.0 Risk Rating" to
    "CVSS <version> Risk Rating" so it matches the actual stored vectors after
    a re-rate. Only the standalone table-cell header is touched (safe); the
    2.6.1 methodology section ("CVSS Version 4.0 Risk Rating") is left alone.
    No-op unless `version` is a CVSS 3.x version.
    """
    if version not in ("3.0", "3.1"):
        return
    target = "CVSS 4.0 Risk Rating"
    repl = f"CVSS {version} Risk Rating"
    try:
        from docx import Document
    except Exception:                                       # pragma: no cover
        return
    try:
        doc = Document(str(docx_path))
    except Exception:                                       # pragma: no cover
        return
    changed = False

    def _replace_in_cell(cell) -> None:
        nonlocal changed
        for p in cell.paragraphs:
            runs = p.runs
            if not runs:
                continue
            if "".join(r.text for r in runs).strip() == target:
                runs[0].text = repl
                for r in runs[1:]:
                    r.text = ""
                changed = True

    def _walk(tables) -> None:
        for table in tables:
            try:
                for row in table.rows:
                    for cell in row.cells:
                        if target in (cell.text or ""):
                            _replace_in_cell(cell)
                        try:
                            for inner in cell.tables:
                                _walk([inner])
                        except Exception:                   # pragma: no cover
                            continue
            except Exception:                               # pragma: no cover
                continue

    _walk(doc.tables)
    if changed:
        try:
            doc.save(str(docx_path))
        except Exception:                                   # pragma: no cover
            pass


def _fix_findings_caption_date(docx_path: Path, as_of: str) -> None:
    """Set the "as of <date>" on the executive-summary findings-table caption to
    `as_of` (the last day of the testing window). Only the trailing date text is
    replaced — the leading "Table {SEQ}" auto-number field is left intact.
    """
    if not as_of:
        return
    try:
        from docx import Document
    except Exception:                                       # pragma: no cover
        return
    try:
        doc = Document(str(docx_path))
    except Exception:                                       # pragma: no cover
        return
    changed = False
    for p in doc.paragraphs:
        full = "".join(r.text for r in p.runs)
        low = full.lower()
        if "summary of findings based on cvss" not in low or " as of " not in low:
            continue
        cut = low.rfind(" as of ")
        keep_to = cut + len(" as of ")
        acc = 0
        for run in p.runs:
            rlen = len(run.text)
            if acc >= keep_to:
                run.text = ""
            elif acc + rlen > keep_to:
                run.text = run.text[: keep_to - acc]
            acc += rlen
        p.add_run(as_of)
        changed = True
    if changed:
        try:
            doc.save(str(docx_path))
        except Exception:                                   # pragma: no cover
            pass


_OWASP_2025_CATEGORIES = [
    "Broken Access Control",
    "Security Misconfiguration",
    "Software Supply Chain Failures",
    "Cryptographic Failures",
    "Injection",
    "Insecure Design",
    "Authentication Failures",
    "Software or Data Integrity Failures",
    "Security Logging & Alerting Failures",
    "Mishandling of Exceptional Conditions",
]
_OWASP_2021_CATEGORIES = {
    "broken access control", "cryptographic failures", "injection",
    "insecure design", "security misconfiguration",
    "vulnerable and outdated components",
    "identification and authentication failures",
    "software and data integrity failures",
    "security logging and monitoring failures",
    "server-side request forgery (ssrf)", "server-side request forgery",
}


def _relabel_owasp_2025(docx_path: Path) -> None:
    """In §2.3 Testing Coverage, change "OWASP Top 10 Web Application Risk 2021"
    to 2025 and replace the 2021 category list with the 2025 list (in order).
    No-op on templates that don't carry the 2021 list.
    """
    try:
        from docx import Document
    except Exception:                                       # pragma: no cover
        return
    try:
        doc = Document(str(docx_path))
    except Exception:                                       # pragma: no cover
        return
    paras = doc.paragraphs
    changed = False
    header_idx = None
    for i, p in enumerate(paras):
        if "owasp top 10 web application risk 2021" in (p.text or "").lower():
            for run in p.runs:
                if "2021" in run.text:
                    run.text = run.text.replace("2021", "2025")
                    changed = True
            header_idx = i
            break
    if header_idx is None:
        return
    next_cat = 0
    for p in paras[header_idx + 1: header_idx + 1 + 25]:
        if next_cat >= len(_OWASP_2025_CATEGORIES):
            break
        raw = (p.text or "").strip()
        if not raw:
            continue
        # Normalise: drop a trailing ";"/"."/"; and"/" and".
        key = re.sub(r"[;.]?\s*(?:and)?\s*$", "", raw, flags=re.IGNORECASE).strip().lower()
        # A category list item is either a known 2021 name, OR a short bullet
        # (≤ 60 chars). Once we've started replacing, a long paragraph (the
        # "Our web application…" intro) ends the list.
        is_cat = key in _OWASP_2021_CATEGORIES or len(raw) <= 60
        if not is_cat:
            if next_cat > 0:
                break
            continue
        last = (next_cat == len(_OWASP_2025_CATEGORIES) - 1)
        # Preserve the template's "; and" / "." list punctuation roughly.
        tail = "." if last else ("; and" if raw.endswith("and") else ";")
        new_text = _OWASP_2025_CATEGORIES[next_cat] + tail
        runs = p.runs
        if runs:
            runs[0].text = new_text
            for r in runs[1:]:
                r.text = ""
            changed = True
        next_cat += 1
    if changed:
        try:
            doc.save(str(docx_path))
        except Exception:                                   # pragma: no cover
            pass


def _strip_rmm(docx_path: Path) -> None:
    """Remove the GovTech CSG ICT RMM content when the report has it disabled:
      * the §2.6.x "… ICT Risk Management Methodology ('RMM') Risk Rating"
        section (heading + its tables, up to the next heading);
      * the "GovTech CSG ICT RMM Risk Rating" / "CSG ICT RMM" column from the
        Risk Register and per-finding detail tables.
    Atomic + validated: any failure leaves the document untouched.
    """
    try:
        from docx import Document
        from docx.text.paragraph import Paragraph
    except Exception:                                       # pragma: no cover
        return
    try:
        doc = Document(str(docx_path))
    except Exception:                                       # pragma: no cover
        return
    changed = False

    # 1. Remove the RMM methodology section (heading -> next heading).
    body = doc.element.body
    removing = False
    to_remove = []
    for ch in list(body.iterchildren()):
        tag = ch.tag.split('}', 1)[-1]
        if tag == "p":
            p = Paragraph(ch, doc)
            name = (p.style.name if p.style else "") or ""
            low = (p.text or "").strip().lower()
            is_heading = name.startswith("Heading")
            if not removing and is_heading and (
                "ict risk management methodology" in low
                or ("rmm" in low and "risk rating" in low)
            ):
                removing = True
                to_remove.append(ch)
                continue
            if removing:
                if is_heading:                # next heading ends the section
                    removing = False
                else:
                    to_remove.append(ch)
                    continue
        elif removing:
            to_remove.append(ch)
            continue
    for ch in to_remove:
        if ch.getparent() is not None:
            ch.getparent().remove(ch)
            changed = True

    # 2. Remove the RMM column from any table that has it.
    for table in doc.tables:
        if not table.rows:
            continue
        idx = None
        for ci, c in enumerate(table.rows[0].cells):
            t = (c.text or "").strip().lower()
            if "csg ict rmm" in t or "ict rmm risk rating" in t or "govtech csg" in t:
                idx = ci
                break
        if idx is None:
            continue
        if _delete_table_column(table, idx):
            changed = True

    if not changed:
        return
    import shutil as _sh
    tmp = docx_path.with_suffix(docx_path.suffix + ".rmmtmp")
    try:
        doc.save(str(tmp))
        Document(str(tmp))                                  # validate
        _sh.move(str(tmp), str(docx_path))
    except Exception:                                       # pragma: no cover
        try: tmp.unlink(missing_ok=True)
        except Exception: pass


def _delete_table_column(table, col_idx: int) -> bool:
    """Delete the column at `col_idx` from every row of `table`, plus its
    `w:gridCol`. Best-effort; returns True if anything was removed."""
    changed = False
    try:
        # Remove the grid column definition.
        grid = table._tbl.find(qn('w:tblGrid'))
        if grid is not None:
            cols = grid.findall(qn('w:gridCol'))
            if 0 <= col_idx < len(cols):
                grid.remove(cols[col_idx])
                changed = True
        for row in table.rows:
            tcs = row._tr.findall(qn('w:tc'))
            if 0 <= col_idx < len(tcs):
                row._tr.remove(tcs[col_idx])
                changed = True
    except Exception:                                       # pragma: no cover
        return changed
    return changed


def _fill_schedule_table(docx_path: Path, fieldwork: str, followup: str) -> None:
    """Fill the §2.5 "Overview of Security Testing Schedule" table:
      * the "… Fieldwork" row's date cell  = the initial testing window;
      * the "… Follow Up" row's date cell  = the retest / follow-up window.
    No-op when neither value is set."""
    if not (fieldwork or followup):
        return
    try:
        from docx import Document
    except Exception:                                       # pragma: no cover
        return
    try:
        doc = Document(str(docx_path))
    except Exception:                                       # pragma: no cover
        return

    def _set_cell(cell, text: str) -> None:
        if not text:
            return
        p = cell.paragraphs[0] if cell.paragraphs else cell.add_paragraph()
        runs = p.runs
        if runs:
            runs[0].text = text
            for r in runs[1:]:
                r.text = ""
        else:
            p.add_run(text)

    def _date_cell(cells):
        """First cell that is a SEPARATE cell from the label (not part of the
        label's horizontal merge) — that's the date cell. Falls back to the
        last cell."""
        label_tc = cells[0]._tc
        for dc in cells[1:]:
            if dc._tc is not label_tc:
                return dc
        return cells[-1]

    changed = False
    for t in doc.tables:
        for row in t.rows:
            cells = row.cells
            if len(cells) < 2:
                continue
            label = (cells[0].text or "").strip().lower()
            if "fieldwork" in label and fieldwork:
                _set_cell(_date_cell(cells), fieldwork)
                changed = True
            elif ("follow up" in label or "follow-up" in label) and followup:
                _set_cell(_date_cell(cells), followup)
                changed = True
    if changed:
        try:
            doc.save(str(docx_path))
        except Exception:                                   # pragma: no cover
            pass


def _collapse_doubled_client_name(docx_path: Path, client_display: str) -> None:
    """The cover title slot renders `clientFullName (clientShortName)`, but both
    DOCPROPERTY slots map to the same `{{ details.client_name }}`, so it comes
    out doubled — "Idemia (IDS) (Idemia (IDS))" (or "Idemia (Idemia)" with no
    short form). Collapse "<X> (<X>)" → "<X>" by clearing the duplicate run
    text only (field structure preserved; LibreOffice uses the cached result)."""
    cd = (client_display or "").strip()
    if not cd:
        return
    target = f"{cd} ({cd})"
    try:
        from docx import Document
    except Exception:                                       # pragma: no cover
        return
    try:
        doc = Document(str(docx_path))
    except Exception:                                       # pragma: no cover
        return
    changed = False
    for p in doc.paragraphs:
        runs = p.runs
        full = "".join(r.text for r in runs)
        idx = full.find(target)
        if idx < 0:
            continue
        # Clear exactly the " (<X>)" suffix: chars [idx+len(cd), idx+len(target)).
        start = idx + len(cd)
        end = idx + len(target)
        acc = 0
        for r in runs:
            rt = r.text
            rlen = len(rt)
            if rlen and not (acc + rlen <= start or acc >= end):
                cut_s = max(start, acc) - acc
                cut_e = min(end, acc + rlen) - acc
                r.text = rt[:cut_s] + rt[cut_e:]
            acc += rlen
        changed = True
    if changed:
        try:
            doc.save(str(docx_path))
        except Exception:                                   # pragma: no cover
            pass


def _ensure_confidentiality_title(docx_path: Path) -> None:
    """Make the "Confidentiality Statement" panel title render on the green
    statement page:
      1. Force its runs to white + bold (text visible on green background).
      2. Add pageBreakBefore=True on that paragraph so it always starts at the
         top of page 2, regardless of how much cover-page content precedes it.
    """
    try:
        from docx import Document
        from docx.shared import RGBColor
        from docx.oxml import OxmlElement
    except Exception:                                       # pragma: no cover
        return
    try:
        doc = Document(str(docx_path))
    except Exception:                                       # pragma: no cover
        return
    changed = False
    for p in doc.paragraphs:
        if (p.text or "").strip().lower() == "confidentiality statement":
            for run in p.runs:
                try:
                    run.font.color.rgb = RGBColor.from_string("FFFFFF")
                    run.font.bold = True
                    changed = True
                except Exception:
                    continue
            # Ensure paragraph always starts a new page (page 2).
            try:
                pPr = p._p.get_or_add_pPr()
                for existing in pPr.findall(qn('w:pageBreakBefore')):
                    pPr.remove(existing)
                pbb = OxmlElement('w:pageBreakBefore')
                pbb.set(qn('w:val'), '1')
                pPr.insert(0, pbb)
                changed = True
            except Exception:                               # pragma: no cover
                pass
    if changed:
        try:
            doc.save(str(docx_path))
        except Exception:                                   # pragma: no cover
            pass


def _add_combined_chapter_headings(
        docx_path: Path,
        sections: list,
        finding_chapter_idxs: list,
) -> None:
    """Insert a "Detailed Findings – <section label>" Heading 1 paragraph
    before the first finding of each test section when the report has multiple
    test sections defined (combined Web VAPT + API VAPT, etc.).

    Strategy:
    - Locate every Heading 2 paragraph inside the first "Detailed Findings"
      Heading 1 block; these are the individual finding titles.
    - They're in the same order as `finding_chapter_idxs`.
    - Wherever chapter_idx changes to a NEW value, insert a fresh Heading 1
      paragraph copying the style of the existing one, with text
      "N.0  Detailed Findings – <section label>" (N = DETAILED_FINDINGS_CHAPTER + idx).
    - Also update the ORIGINAL Heading 1 ("Detailed Findings – …") to use
      section 0's label (if defined) and chapter number 3.
    """
    try:
        from docx import Document
        from docx.oxml import OxmlElement
        from copy import deepcopy
    except Exception:                                       # pragma: no cover
        return
    try:
        doc = Document(str(docx_path))
    except Exception:                                       # pragma: no cover
        return

    if not sections or len(sections) < 2:
        return

    # Build a map: section_idx -> label
    sec_labels = {s.get("idx", i): s.get("label", f"Section {i+1}")
                  for i, s in enumerate(sections)}

    # Collect Heading 2 paragraphs that are inside the Detailed Findings block.
    in_detail = False
    detail_h1 = None
    detail_h2s = []   # in order
    for p in doc.paragraphs:
        name = (p.style.name if p.style else "") or ""
        if name.startswith("Heading 1"):
            if "detailed findings" in (p.text or "").strip().lower():
                in_detail = True
                detail_h1 = p
            else:
                if in_detail:
                    break  # left the detailed findings section
                in_detail = False
            continue
        if in_detail and name.startswith("Heading 2"):
            detail_h2s.append(p)

    if not detail_h2s or not detail_h1:
        return
    if len(detail_h2s) != len(finding_chapter_idxs):
        # Mismatch — bail rather than insert at wrong position.
        return

    # Update the original Heading 1 text to reflect section 0 label & chapter 3.
    s0_label = sec_labels.get(0, "")
    if s0_label and detail_h1 is not None:
        ch3_text = f"{DETAILED_FINDINGS_CHAPTER}.0\tDetailed Findings – {s0_label}"
        for run in detail_h1.runs:
            run.text = ""
        if detail_h1.runs:
            detail_h1.runs[0].text = ch3_text
        else:
            from docx.oxml import OxmlElement as _OE
            r = _OE("w:r")
            t = _OE("w:t")
            t.text = ch3_text
            r.append(t)
            detail_h1._p.append(r)

    # Walk backward through changes so we can insert before without index shift.
    # Find all positions where chapter_idx changes (excluding the very first).
    change_positions = []
    prev_idx = finding_chapter_idxs[0] if finding_chapter_idxs else 0
    for i, cidx in enumerate(finding_chapter_idxs):
        if i > 0 and cidx != prev_idx:
            change_positions.append((i, cidx))
        prev_idx = cidx

    # Insert new Heading 1 paragraphs (in reverse order so indices stay valid).
    for h2_pos, sec_idx in reversed(change_positions):
        target_h2 = detail_h2s[h2_pos]
        chapter_num = DETAILED_FINDINGS_CHAPTER + sec_idx
        label = sec_labels.get(sec_idx, f"Section {sec_idx + 1}")
        heading_text = f"{chapter_num}.0\tDetailed Findings – {label}"

        # Clone the style from the original Heading 1 paragraph.
        new_h1_elem = deepcopy(detail_h1._p)
        # Clear all runs and set fresh text.
        for r_el in new_h1_elem.findall('.//' + qn('w:r')):
            new_h1_elem.remove(r_el)
        # Remove inline XML that shouldn't be copied (bookmarks, links)
        for tag in ('w:bookmarkStart', 'w:bookmarkEnd', 'w:hyperlink'):
            for el in new_h1_elem.findall('.//' + qn(tag)):
                parent = el.getparent()
                if parent is not None:
                    parent.remove(el)
        # Add a single run with the new text.
        ns_w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
        r_el = OxmlElement("w:r")
        t_el = OxmlElement("w:t")
        t_el.text = heading_text
        r_el.append(t_el)
        new_h1_elem.append(r_el)

        # Ensure pageBreakBefore=1 on the new heading.
        pPr = new_h1_elem.find(qn("w:pPr"))
        if pPr is None:
            pPr = OxmlElement("w:pPr")
            new_h1_elem.insert(0, pPr)
        for existing in pPr.findall(qn("w:pageBreakBefore")):
            pPr.remove(existing)
        pbb = OxmlElement("w:pageBreakBefore")
        pbb.set(qn("w:val"), "1")
        pPr.insert(0, pbb)

        # Insert before the target Heading 2 paragraph.
        target_h2._p.addprevious(new_h1_elem)

    try:
        doc.save(str(docx_path))
    except Exception:                                       # pragma: no cover
        pass


def _paginate_findings(docx_path: Path) -> None:
    """Page-break behaviour for the Detailed Findings chapter:
      * the FIRST finding flows right after the "Detailed Findings" heading
        (no page break);
      * every SUBSEQUENT finding starts on a fresh page.
    Implemented by toggling `pageBreakBefore` on each finding's Heading-2 title
    paragraph and stripping any manual page-break run inside it.
    """
    try:
        from docx import Document
        from docx.oxml import OxmlElement
    except Exception:                                       # pragma: no cover
        return
    try:
        doc = Document(str(docx_path))
    except Exception:                                       # pragma: no cover
        return

    def _set_pbb(p, on: bool) -> None:
        pPr = p._p.get_or_add_pPr()
        for e in pPr.findall(qn('w:pageBreakBefore')):
            pPr.remove(e)
        el = OxmlElement('w:pageBreakBefore')
        el.set(qn('w:val'), '1' if on else '0')
        pPr.insert(0, el)

    in_detail = False
    idx = 0
    changed = False
    for p in doc.paragraphs:
        name = (p.style.name if p.style else "") or ""
        if name.startswith("Heading 1"):
            in_detail = "detailed findings" in (p.text or "").strip().lower()
            idx = 0
            continue
        if in_detail and name.startswith("Heading 2"):
            idx += 1
            _set_pbb(p, idx > 1)         # 1st finding: no break; rest: new page
            # Strip any manual page-break run carried in the heading itself.
            for br in p._p.findall('.//' + qn('w:br')):
                if br.get(qn('w:type')) == 'page' and br.getparent() is not None:
                    br.getparent().remove(br)
            changed = True
    if changed:
        try:
            doc.save(str(docx_path))
        except Exception:                                   # pragma: no cover
            pass


# ---- PDF conversion via LibreOffice ----

def _patch_toc_pages(docx_path: Path, pdf_path: Path) -> bool:
    """Two-pass page-number fix. Headless LibreOffice `--convert-to` does NOT
    recompute TOC / Table-of-Figures PAGEREF page numbers (they stay at the
    cached "1"). So: read the rendered PDF, find the real page of every
    bookmarked heading / figure caption (its BODY occurrence — not the TOC
    line), and write those numbers into the docx's PAGEREF cached results.
    A re-convert then yields correct page numbers. Returns True if it patched
    anything. Best-effort: any failure returns False and leaves the docx alone.
    """
    try:
        import re as _re
        from lxml import etree
        from docx import Document as _Doc
    except Exception:                                       # pragma: no cover
        return False

    NS_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    def _q(tag): return f"{{{NS_W}}}{tag}"

    # 1. {bookmark anchor -> heading/caption text} from the docx.
    try:
        doc = _Doc(str(docx_path))
    except Exception:
        return False
    # Ordered list of (anchor, text) in DOCUMENT order — order matters for the
    # monotonic page search below.
    ordered: list[tuple[str, str]] = []
    seen_anchor: set[str] = set()
    for p in doc.paragraphs:
        txt = (p.text or "").strip()
        if not txt:
            continue
        for b in p._p.findall(".//" + _q("bookmarkStart")):
            nm = b.get(_q("name"))
            if nm and nm.startswith("_Toc") and nm not in seen_anchor:
                seen_anchor.add(nm)
                ordered.append((nm, txt))
    if not ordered:
        return False

    # 2. {anchor -> page} by locating each text's BODY line in the PDF (a line
    #    that is ~just the heading, NOT a "Title......12" TOC/ToF line).
    try:
        import pdfplumber
        pages: list[list[str]] = []
        with pdfplumber.open(str(pdf_path)) as pdf:
            for pg in pdf.pages:
                pages.append(((pg.extract_text() or "")).split("\n"))
    except Exception:
        return False
    if not pages:
        return False

    _leader = _re.compile(r"\.{2,}\s*\d+\s*$")   # dot-leader + page number

    def _norm(s: str) -> str:
        # Normalise curly quotes / dashes / whitespace so docx text matches the
        # PDF-extracted text regardless of typographic substitution.
        for a, b in (("“", '"'), ("”", '"'), ("‘", "'"),
                     ("’", "'"), ("–", "-"), ("—", "-"),
                     (" ", " ")):
            s = s.replace(a, b)
        return _re.sub(r"\s+", " ", s).strip()

    def _page_of(text: str, start_page: int):
        """First page >= start_page whose BODY (non-TOC) text contains this
        heading. Searching from start_page enforces document order, so a finding
        title that also appears in an earlier summary table / prose mention is
        skipped in favour of its real heading."""
        t = _norm(text)
        if not t:
            return None
        # Long headings can wrap across lines in the body — match a prefix.
        probe = t if len(t) <= 45 else t[:45]
        short = len(t) <= 45
        for pi in range(max(1, start_page), len(pages) + 1):
            for ln in pages[pi - 1]:
                if _leader.search(ln.strip()):       # a TOC / ToF entry line
                    continue
                ls = _norm(ln)
                if probe in ls:
                    # For short headings require the line to be ~just the
                    # heading (avoid matching a prose mention inside a sentence).
                    if short and len(ls) > len(t) + 30:
                        continue
                    return pi
        return None

    # The VibeDocs templates number body pages "chapter-page" (e.g. "3-1") via a
    # STYLEREF+PAGE footer field, with roman front-matter. So the TOC must show
    # that LABEL, not the absolute page index. Read each page's footer label.
    def _page_label(lines: list[str]) -> str:
        for ln in reversed(lines):                  # footer is near the bottom
            s = ln.strip()
            m = _re.search(r"\bPage\s+([0-9]+-[0-9]+|[ivxlcdm]+|[0-9]+)\b", s, _re.IGNORECASE)
            if m:
                return m.group(1)
            m = _re.fullmatch(r"([0-9]+-[0-9]+)", s)   # bare "3-1"
            if m:
                return m.group(1)
        return ""
    page_labels = {pi: _page_label(lines) for pi, lines in enumerate(pages, start=1)}

    # Walk headings/captions in document order, never going backwards a page.
    # `min_page` orders by absolute index; the cached value is the page LABEL.
    anchor_page: dict[str, str] = {}
    min_page = 1
    for anchor, text in ordered:
        pi = _page_of(text, min_page)
        if pi:
            anchor_page[anchor] = page_labels.get(pi) or str(pi)
            min_page = pi
    if not anchor_page:
        return False

    # 3. Patch each PAGEREF field's cached result with the real page.
    try:
        with zipfile.ZipFile(docx_path, "r") as zf:
            xml = zf.read("word/document.xml")
        root = etree.fromstring(xml)
    except Exception:
        return False

    changed = False

    def _patch_para(p_el) -> None:
        nonlocal changed
        state = None            # None | 'instr' | 'result'
        cur_anchor = None
        result_runs: list = []
        # Runs live both directly under <w:p> AND inside <w:hyperlink> (our
        # rebuilt TOC/ToF entries wrap the whole row in a hyperlink), so walk
        # ALL descendant runs in document order.
        for r in p_el.iter(_q("r")):
            fc = r.find(_q("fldChar"))
            it = r.find(_q("instrText"))
            if fc is not None:
                ft = fc.get(_q("fldCharType"))
                if ft == "begin":
                    state, cur_anchor, result_runs = "instr", None, []
                elif ft == "separate" and state == "instr":
                    state = "result"
                elif ft == "end":
                    if (state == "result" and cur_anchor
                            and cur_anchor in anchor_page and result_runs):
                        t0 = result_runs[0].find(_q("t"))
                        if t0 is None:
                            t0 = etree.SubElement(result_runs[0], _q("t"))
                        t0.text = str(anchor_page[cur_anchor])
                        for rr in result_runs[1:]:
                            tt = rr.find(_q("t"))
                            if tt is not None:
                                tt.text = ""
                        changed = True
                    state, cur_anchor, result_runs = None, None, []
            elif it is not None and state == "instr":
                m = _re.search(r"PAGEREF\s+(\S+)", it.text or "")
                if m:
                    cur_anchor = m.group(1)
            elif state == "result":
                result_runs.append(r)

    for p_el in root.iter(_q("p")):
        _patch_para(p_el)

    if not changed:
        return False

    new_xml = etree.tostring(root, xml_declaration=True, encoding="UTF-8",
                             standalone=True)
    tmp = docx_path.with_suffix(".tocpage.tmp.docx")
    try:
        with zipfile.ZipFile(docx_path, "r") as zin, \
             zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                zout.writestr(item, new_xml if item.filename == "word/document.xml"
                              else zin.read(item.filename))
        shutil.move(str(tmp), str(docx_path))
    except Exception:                                       # pragma: no cover
        try: tmp.unlink(missing_ok=True)
        except Exception: pass
        return False
    return True


def convert_to_pdf(docx_path: Path, out_dir: Path | None = None,
                   *, draft_watermark: bool = False) -> Path:
    """Convert .docx to .pdf using headless LibreOffice. Returns the PDF path.

    ``draft_watermark`` is now a NO-OP, kept only for call-site
    signature compatibility. Watermarking moved entirely to the docx
    stage (see `_render_and_save`): the VibeDocs template ships WITH a
    native DRAFT, a draft render leaves it untouched, an approved
    render strips it. LibreOffice renders the template's native VML
    DRAFT faithfully, so the PDF inherits exactly the right state
    (1 for draft, 0 for approved). The old pypdf overlay is GONE —
    it was the second watermark that produced the stacked "DDRAFT"
    artefact. No code path adds a watermark to the PDF anymore, so a
    double-DRAFT is structurally impossible.
    """
    out_dir = Path(out_dir) if out_dir else docx_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    # Snapshot which PDFs already exist so we can detect what LibreOffice
    # produced even if it picks an unexpected output filename (Excel docs
    # with non-ASCII metadata sometimes get mangled stems).
    pre_existing_pdfs = {p.resolve() for p in out_dir.glob("*.pdf")}
    # Each conversion needs a separate profile dir to allow parallel calls
    with tempfile.TemporaryDirectory() as profile:
        # `convert-to pdf:writer_pdf_Export` is more explicit than just
        # `pdf` and avoids a class of "LibreOffice can't pick an exporter"
        # silent failures on Excel sources.
        cmd = [
            "soffice",
            f"-env:UserInstallation=file://{profile}",
            "--headless", "--nologo", "--nodefault",
            "--norestore", "--nolockcheck", "--nofirststartwizard",
            "--convert-to", "pdf",
            "--outdir", str(out_dir),
            str(docx_path),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            import logging as _log_lo
            _log_lo.getLogger(__name__).error(
                "LibreOffice conversion failed (exit %s): %s",
                result.returncode, result.stderr or result.stdout,
            )
            raise RuntimeError(
                f"LibreOffice conversion failed (exit {result.returncode})"
            )
    pdf_path = out_dir / (docx_path.stem + ".pdf")
    if not pdf_path.exists():
        # Fallback: LibreOffice sometimes writes the PDF under a slightly
        # different name (e.g. sanitised stem). Pick the newest PDF in
        # out_dir that wasn't there before and treat it as the output.
        candidates = sorted(
            (p for p in out_dir.glob("*.pdf") if p.resolve() not in pre_existing_pdfs),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if candidates:
            try:
                candidates[0].rename(pdf_path)
            except OSError:
                # Cross-filesystem rename failure — return the candidate as-is.
                pdf_path = candidates[0]
        else:
            raise RuntimeError(
                f"Expected PDF not produced at {pdf_path}. "
                f"LibreOffice stdout: {result.stdout.strip()!r}; "
                f"stderr: {result.stderr.strip()!r}"
            )
    # Two-pass TOC / Table-of-Figures page-number fix. Headless LibreOffice
    # keeps the cached "1" page numbers, so read THIS PDF, write the real pages
    # into the docx's PAGEREF fields, and re-convert. Fully best-effort — any
    # failure keeps the first PDF.
    try:
        if _patch_toc_pages(docx_path, pdf_path):
            with tempfile.TemporaryDirectory() as profile2:
                cmd2 = [
                    "soffice", f"-env:UserInstallation=file://{profile2}",
                    "--headless", "--nologo", "--nodefault",
                    "--norestore", "--nolockcheck", "--nofirststartwizard",
                    "--convert-to", "pdf", "--outdir", str(out_dir),
                    str(docx_path),
                ]
                subprocess.run(cmd2, capture_output=True, text=True, timeout=180)
            _repaved = out_dir / (docx_path.stem + ".pdf")
            if _repaved.exists():
                pdf_path = _repaved
    except Exception as _tpe:                               # pragma: no cover
        import logging as _log_tp
        _log_tp.getLogger(__name__).warning(
            "TOC page-number two-pass skipped: %s", _tpe)

    # NOTE: the pypdf DRAFT-overlay stamp was removed 2026-05-16. Under
    # the new single-source watermark model the docx already carries
    # exactly the right watermark state (template's native DRAFT for a
    # draft; stripped for an approved render), and LibreOffice renders
    # that faithfully into the PDF. Stamping a second overlay here is
    # what produced the stacked double-DRAFT, so there is deliberately
    # no watermark code on the PDF path now. `draft_watermark` is
    # accepted-and-ignored for caller compatibility.
    return pdf_path


def _docx_has_draft_vml_watermark(docx_path: Path) -> bool:
    """Return True if any header part in ``docx_path`` contains a DRAFT
    VML wordart shape — the kind our `_inject_watermark` writes, OR the
    kind Word's built-in Watermark feature writes. Used by
    ``convert_to_pdf`` to avoid double-stamping a PDF whose source
    already has a visible VML watermark.

    Cheap by design — we only read text content of header XML parts
    (no full lxml parse) and scan for two markers:
      * ``DRAFT_WM`` — our renderer's id, so a docx we just stamped is
        a guaranteed hit.
      * ``string="DRAFT"`` (case-insensitive on the value) — Word's
        native textpath wordart.

    Returns False if the docx is missing entirely or no header parts
    exist — caller falls back to pypdf overlay.
    """
    try:
        with zipfile.ZipFile(docx_path, "r") as zf:
            for info in zf.infolist():
                if not (info.filename.startswith("word/header")
                        and info.filename.endswith(".xml")):
                    continue
                # Decode latin-1 so we never raise on stray bytes; the
                # markers we look for are pure ASCII anyway.
                content = zf.read(info.filename).decode("latin-1")
                if "DRAFT_WM" in content:
                    return True
                # Cheap regex-free substring scan for any
                # `string="DRAFT…"` textpath.
                lower = content.lower()
                idx = 0
                while True:
                    idx = lower.find('string="', idx)
                    if idx < 0:
                        break
                    end = lower.find('"', idx + 8)
                    if end < 0:
                        break
                    if "draft" in lower[idx + 8:end]:
                        return True
                    idx = end + 1
    except (FileNotFoundError, zipfile.BadZipFile):
        return False
    return False


def _stamp_pdf_draft_watermark(pdf_path: Path) -> None:
    """Overlay a rotated, semi-transparent 'DRAFT' on every page of the PDF
    using pypdf + a synthesised single-page watermark.

    pypdf's `merge_page(...)` composites the overlay below page content by
    default; we render the watermark large enough to span A4/Letter and
    rotate it -30° so it reads diagonally across each page.
    """
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import (
        NameObject, DictionaryObject, FloatObject, NumberObject,
        ArrayObject, ByteStringObject,
    )
    # Use reportlab to produce a one-page watermark PDF if available;
    # otherwise fall back to a minimal hand-built XObject so we don't
    # require an extra dependency. The hand-built path is enough for a
    # diagonal "DRAFT" — it doesn't need fancy typography.
    overlay_path = pdf_path.with_suffix(".wm.pdf")
    try:
        _build_watermark_pdf(overlay_path, "DRAFT")
    except Exception:
        overlay_path.unlink(missing_ok=True)
        return

    try:
        reader = PdfReader(str(pdf_path))
        wm_reader = PdfReader(str(overlay_path))
        wm_page = wm_reader.pages[0]

        writer = PdfWriter()
        for page in reader.pages:
            # merge_page draws wm_page on top of `page`; we want it visible
            # but not opaque, which the watermark PDF achieves via its own
            # alpha-channel graphics state.
            page.merge_page(wm_page)
            writer.add_page(page)

        out = pdf_path.with_suffix(".stamped.pdf")
        with out.open("wb") as fh:
            writer.write(fh)
        shutil.move(str(out), str(pdf_path))
    finally:
        overlay_path.unlink(missing_ok=True)


def _build_watermark_pdf(out_path: Path, text: str) -> None:
    """Build a single-page PDF containing a rotated, semi-transparent
    `text` overlay. Uses reportlab when available; otherwise emits a
    minimal hand-written PDF using only the standard library."""
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.colors import Color
    except ImportError:
        _build_watermark_pdf_minimal(out_path, text)
        return

    width, height = A4
    c = canvas.Canvas(str(out_path), pagesize=A4)
    c.saveState()
    # ~120pt grey text, 22% alpha, rotated −30° around the page centre.
    c.setFillColor(Color(0.55, 0.55, 0.55, alpha=0.22))
    c.setFont("Helvetica-Bold", 120)
    c.translate(width / 2.0, height / 2.0)
    c.rotate(30)
    c.drawCentredString(0, -40, text)
    c.restoreState()
    c.save()


def _build_watermark_pdf_minimal(out_path: Path, text: str) -> None:
    """Last-resort PDF builder when reportlab isn't installed. Produces a
    syntactically valid PDF with a rotated grey text string at fixed
    coordinates suitable for A4."""
    # PDF coordinates: A4 ~ 595 x 842 points
    content = (
        b"q\n"
        b"0.55 0.55 0.55 RG\n"
        b"0.55 0.55 0.55 rg\n"
        b"BT\n"
        b"/F1 120 Tf\n"
        b"0.866 0.5 -0.5 0.866 150 200 Tm\n"
        b"(" + text.encode("latin-1") + b") Tj\n"
        b"ET\n"
        b"Q\n"
    )
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj\n"
        b"2 0 obj <</Type /Pages /Count 1 /Kids [3 0 R]>> endobj\n"
        b"3 0 obj <</Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources <</Font <</F1 4 0 R>>>> /Contents 5 0 R>> endobj\n"
        b"4 0 obj <</Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold>> endobj\n"
        b"5 0 obj <</Length " + str(len(content)).encode("ascii") + b">>\n"
        b"stream\n" + content + b"endstream endobj\n"
        b"xref\n"
        b"0 6\n"
        b"0000000000 65535 f\n"
        b"0000000009 00000 n\n"
        b"0000000052 00000 n\n"
        b"0000000098 00000 n\n"
        b"0000000183 00000 n\n"
        b"0000000244 00000 n\n"
        b"trailer <</Size 6 /Root 1 0 R>>\n"
        b"startxref\n"
        b"320\n"
        b"%%EOF\n"
    )
    out_path.write_bytes(pdf)


# ---- Version bumping ----

_VERSION_RE = re.compile(r"^(\d+)\.(\d+)$")


def next_version(current: str, kind: str = "minor") -> str:
    """Bump '0.1' to '0.2' (minor) or '0.1' to '1.0' (major). Returns new version string."""
    m = _VERSION_RE.match(current.strip())
    if not m:
        return "0.1"
    major, minor = int(m.group(1)), int(m.group(2))
    if kind == "major":
        return f"{major + 1}.0"
    return f"{major}.{minor + 1}"
