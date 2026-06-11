"""Post-render pass: OLE-embed xlsx attachments inline in the rendered
docx so each grouped finding's Observations section shows a clickable
Excel icon — same look as the VibeDocs template style screenshot.

Why post-render rather than via docxtpl placeholders
---------------------------------------------------
docxtpl ships a `Subdoc` primitive for embedding rich content at a
placeholder, but it doesn't support OLE-embedded Office documents
(the `<o:OLEObject Type="Embed" ProgID="Excel.Sheet.12">` shape).
python-docx itself doesn't support them either. We handle it
ourselves at the OOXML layer:

  1. Take the rendered .docx (a ZIP file).
  2. For each finding-attachment we want to embed:
     a. Drop the .xlsx bytes into `word/embeddings/oleObjectN.xlsx`
        (a new package part).
     b. Drop the Excel-icon PNG into `word/media/imageN.png`.
     c. Add two relationships to `word/_rels/document.xml.rels`:
        one of type `.../oleObject` (Microsoft's modern relation
        type for embedded OOXML packages) pointing at the xlsx,
        and one of type `.../image` pointing at the icon.
     d. Update `[Content_Types].xml` with a Default for `.png`
        (if missing), a Default for `.xlsx` (so the embedded
        spreadsheet content-type resolves), and an Override for
        the embedded part itself.
     e. Find the paragraph in `word/document.xml` whose text
        contains the marker we want to replace (the "Refer to
        the attached file: outdated_software.xlsx" line the
        renderer puts there). Inject a centred paragraph
        carrying the OLE shape XML right after it, plus a
        "Figure N: <label>" caption paragraph.

The result: when the consultant opens the docx in Word they see
the Excel icon at the right place; double-click opens the embedded
spreadsheet in Excel. When LibreOffice converts the docx to PDF
the OLE object is rendered as its icon image — so the PDF preview
shows the icon too, just non-interactive.

If anything goes wrong (parse error, missing marker, etc.) we
fall back gracefully and the docx ships without the icons — the
"Refer to the attached file:" prose stays in place so the reader
still knows the file exists.
"""
from __future__ import annotations

import io
import logging
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

from lxml import etree

logger = logging.getLogger(__name__)


# ============================================================
# XML namespaces — long names used throughout
# ============================================================

_NS = {
    "w":  "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "r":  "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "v":  "urn:schemas-microsoft-com:vml",
    "o":  "urn:schemas-microsoft-com:office:office",
    "ct": "http://schemas.openxmlformats.org/package/2006/content-types",
    "pr": "http://schemas.openxmlformats.org/package/2006/relationships",
}


# Relationship types and content types we'll be adding to the docx
# package. OOXML packages (xlsx/docx/pptx) embedded in a docx MUST
# use the `package` relationship type, NOT `oleObject`. Using `oleObject`
# results in Word showing the icon but treating it as a non-interactive
# static picture because `oleObject` expects a legacy OLE2 compound
# document binary, not a ZIP-based OOXML package.
_REL_TYPE_OLE_PACKAGE = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/package"
)
_REL_TYPE_IMAGE = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image"
)
_CT_XLSX = (
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
)


# ============================================================
# 1. The Excel icon
# ============================================================
#
# Tiny generated PNG. We don't bundle a static asset because we'd
# rather have the icon material live in the codebase as code (PIL
# draws it) — easier to audit, no binary blob in git.

def make_excel_icon_png() -> bytes:
    """Render a small Excel-style icon (96×96 PNG) and return its
    bytes. Green rectangle with a white "X" centred — visually
    similar to the canonical Excel app icon without being an exact
    copy of the trademark.
    """
    try:
        from PIL import Image, ImageDraw
    except ImportError:                                     # pragma: no cover
        # PIL is a hard dependency of the wider app — this should
        # never fire. If it ever does, return a 1×1 transparent
        # PNG so the OLE shape still renders (just blank).
        return (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
            b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
            b"\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\x0f\x00"
            b"\x00\x01\x01\x00\x05\x9d\xf8\x07\xc0\x00\x00\x00\x00"
            b"IEND\xaeB`\x82"
        )

    img = Image.new("RGBA", (96, 96), (255, 255, 255, 0))
    d = ImageDraw.Draw(img)
    # Excel-green rectangle
    d.rectangle((8, 14, 88, 86), fill=(29, 111, 66))
    # White X
    d.line((22, 28, 74, 72), fill="white", width=6)
    d.line((74, 28, 22, 72), fill="white", width=6)
    # Subtle top tab to give it a "document" look
    d.rectangle((8, 6, 60, 18), fill=(29, 111, 66))
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


# ============================================================
# 2. Public entry point
# ============================================================

def embed_xlsx_attachments(docx_path: Path,
                            attachments: list[dict]) -> int:
    """Inject every entry in `attachments` into the rendered docx
    as an OLE-embedded xlsx with an icon + caption.

    Each entry is a dict:
        {
          "marker":   <str: the text that identifies the target
                      paragraph in the docx prose — usually
                      "Refer to the attached file: foo.xlsx">,
          "xlsx_path":<Path: where the xlsx lives on disk>,
          "filename": <str: the visible filename for the caption,
                      e.g. "outdated_software.xlsx">,
          "label":    <str: caption text — "Figure N: …">,
        }

    Returns the number of attachments successfully embedded.
    Failure on ONE attachment doesn't abort the others; it just
    logs a warning and that one stays as plain text in the docx.
    """
    if not attachments:
        return 0

    icon_bytes = make_excel_icon_png()

    embedded_count = 0
    # Use a temp output so a partial failure can't corrupt the
    # original docx. Atomic move at the end.
    with tempfile.NamedTemporaryFile(
            suffix=".docx", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        try:
            with zipfile.ZipFile(docx_path, "r") as src:
                # Read the three XML files we'll mutate up front so
                # we don't keep `src` open while writing `dst`.
                doc_xml      = src.read("word/document.xml")
                rels_xml     = src.read("word/_rels/document.xml.rels")
                ct_xml       = src.read("[Content_Types].xml")
                # Everything else gets copied verbatim later.
                passthrough = {
                    name: src.read(name) for name in src.namelist()
                    if name not in ("word/document.xml",
                                     "word/_rels/document.xml.rels",
                                     "[Content_Types].xml")
                }
        except (zipfile.BadZipFile, KeyError) as e:
            logger.warning("embed_xlsx_attachments: %s", e)
            return 0

        try:
            doc_tree  = etree.fromstring(doc_xml)
            rels_tree = etree.fromstring(rels_xml)
            ct_tree   = etree.fromstring(ct_xml)
        except etree.XMLSyntaxError as e:
            logger.warning(
                "embed_xlsx_attachments: malformed XML in docx: %s", e)
            return 0

        # Track relationship IDs so we mint fresh ones per
        # attachment without colliding with what docxtpl already
        # produced. The max-rId scan is cheap and robust.
        max_rid = _max_existing_rid(rels_tree)
        # Counter for new package parts (we name them sequentially
        # to avoid filename collisions with whatever docxtpl wrote).
        next_idx = _next_part_index(passthrough)
        # Whether we've already added a Default for the .png / .xlsx
        # extensions in Content_Types.xml.
        png_default_added = _has_default_extension(ct_tree, "png")

        new_package_parts: dict[str, bytes] = {}

        for spec in attachments:
            marker = spec.get("marker")
            xlsx_path = spec.get("xlsx_path")
            filename = spec.get("filename", "")
            label = spec.get("label", "")
            if not (marker and xlsx_path and filename):
                continue
            xlsx_path = Path(xlsx_path)
            if not xlsx_path.exists():
                logger.warning(
                    "embed_xlsx_attachments: xlsx missing on disk: %s",
                    xlsx_path,
                )
                continue

            target_p = _find_paragraph_with_text(doc_tree, marker)
            if target_p is None:
                logger.info(
                    "embed_xlsx_attachments: marker %r not found in docx — "
                    "skipping %s", marker, filename,
                )
                continue

            # Read the xlsx bytes once.
            try:
                xlsx_bytes = xlsx_path.read_bytes()
            except OSError as e:
                logger.warning(
                    "embed_xlsx_attachments: could not read %s: %s",
                    xlsx_path, e,
                )
                continue

            # Allocate part names + relationship IDs.
            embed_part_name = f"word/embeddings/oleObject{next_idx}.xlsx"
            icon_part_name  = f"word/media/oleIcon{next_idx}.png"
            rid_embed       = f"rId{max_rid + 1}"
            rid_image       = f"rId{max_rid + 2}"
            max_rid  += 2
            next_idx += 1

            # 1) Pour the binary parts into the new-parts staging
            #    dict so we can write them after the doc XML.
            new_package_parts[embed_part_name] = xlsx_bytes
            new_package_parts[icon_part_name]  = icon_bytes

            # 2) Relationships: one for the OLE blob, one for icon.
            _add_relationship(rels_tree, rid_embed,
                              _REL_TYPE_OLE_PACKAGE,
                              f"embeddings/oleObject{next_idx - 1}.xlsx")
            _add_relationship(rels_tree, rid_image,
                              _REL_TYPE_IMAGE,
                              f"media/oleIcon{next_idx - 1}.png")

            # 3) Content types: Default for png if missing (needed for
            #    icon rendering), Override for the specific embedded xlsx
            #    part. We deliberately do NOT add a Default for ".xlsx" —
            #    a package-level Default applies to ALL parts with that
            #    extension, which can interfere with how Word resolves
            #    other xlsx-typed parts. An Override is scoped to exactly
            #    this one embedded part and is sufficient.
            if not png_default_added:
                _add_default_extension(ct_tree, "png", "image/png")
                png_default_added = True
            _add_override(ct_tree, "/" + embed_part_name, _CT_XLSX)

            # 4) Build + inject the OLE shape paragraphs.
            shape_id = f"_x0000_i{1024 + next_idx}"
            ole_p = _build_ole_paragraph(
                rid_embed=rid_embed, rid_image=rid_image,
                shape_id=shape_id, obj_id=str(1_000_000 + next_idx),
            )
            cap_p = _build_caption_paragraph(label, filename)

            # Insert the caption FIRST then the OLE paragraph, so
            # that after both `addnext()` calls the order is:
            #   target -> ole_p -> cap_p
            target_p.addnext(cap_p)
            target_p.addnext(ole_p)

            # Clear the marker text from the target paragraph — strip
            # all <w:r> run children so "Refer to the attached file: …"
            # no longer appears in the rendered document. Keep <w:pPr>
            # so any paragraph-level spacing/style is preserved.
            w_ns = f"{{{_NS['w']}}}"
            for child in list(target_p):
                if child.tag != f"{w_ns}pPr":
                    target_p.remove(child)

            embedded_count += 1

        if embedded_count == 0:
            # No work to do — clean up + return.
            tmp_path.unlink(missing_ok=True)
            return 0

        # 5) Serialise the three mutated XML files.
        doc_xml_out  = _serialise(doc_tree)
        rels_xml_out = _serialise(rels_tree)
        ct_xml_out   = _serialise(ct_tree)

        # 6) Write the new docx atomically.
        with zipfile.ZipFile(tmp_path, "w",
                              compression=zipfile.ZIP_DEFLATED) as dst:
            dst.writestr("word/document.xml", doc_xml_out)
            dst.writestr("word/_rels/document.xml.rels", rels_xml_out)
            dst.writestr("[Content_Types].xml", ct_xml_out)
            for name, data in passthrough.items():
                dst.writestr(name, data)
            for name, data in new_package_parts.items():
                dst.writestr(name, data)
        shutil.move(str(tmp_path), str(docx_path))
        return embedded_count
    finally:
        if tmp_path.exists():
            try: tmp_path.unlink()
            except OSError: pass


# ============================================================
# 3. Low-level XML helpers
# ============================================================

def _max_existing_rid(rels_tree) -> int:
    """Largest numeric rId in the relationships file. We mint new
    ones above this so we never collide with what docxtpl already
    wrote.
    """
    max_n = 0
    for r in rels_tree.findall(f"{{{_NS['pr']}}}Relationship"):
        rid = r.get("Id") or ""
        m = re.match(r"rId(\d+)$", rid)
        if m:
            max_n = max(max_n, int(m.group(1)))
    return max_n


def _next_part_index(existing_parts: dict) -> int:
    """Lowest sequence number ≥ 1 that doesn't collide with an
    existing `oleObjectN.xlsx` or `oleIconN.png` part name. Keeps
    new package parts at predictable filenames.
    """
    used = set()
    rx = re.compile(r"(?:oleObject|oleIcon)(\d+)\.")
    for name in existing_parts:
        m = rx.search(name)
        if m:
            used.add(int(m.group(1)))
    n = 1
    while n in used:
        n += 1
    return n


def _add_relationship(rels_tree, rid: str, rtype: str, target: str) -> None:
    el = etree.SubElement(
        rels_tree, f"{{{_NS['pr']}}}Relationship",
        Id=rid, Type=rtype, Target=target,
    )
    return el


def _has_default_extension(ct_tree, ext: str) -> bool:
    for d in ct_tree.findall(f"{{{_NS['ct']}}}Default"):
        if (d.get("Extension") or "").lower() == ext.lower():
            return True
    return False


def _add_default_extension(ct_tree, ext: str, content_type: str) -> None:
    etree.SubElement(
        ct_tree, f"{{{_NS['ct']}}}Default",
        Extension=ext, ContentType=content_type,
    )


def _add_override(ct_tree, part_name: str, content_type: str) -> None:
    # Skip if Override already declared for this part — keeps
    # Content_Types.xml uniqueness invariant.
    for o in ct_tree.findall(f"{{{_NS['ct']}}}Override"):
        if (o.get("PartName") or "") == part_name:
            return
    etree.SubElement(
        ct_tree, f"{{{_NS['ct']}}}Override",
        PartName=part_name, ContentType=content_type,
    )


def _find_paragraph_with_text(doc_tree, marker: str):
    """Return the first <w:p> whose concatenated text contains
    `marker`, or None. Comparison is plain substring on the joined
    text of every <w:t> in the paragraph — handles cases where
    Word splits the marker across multiple runs.
    """
    w = _NS["w"]
    for p in doc_tree.iter(f"{{{w}}}p"):
        text = "".join(t.text or "" for t in p.iter(f"{{{w}}}t"))
        if marker in text:
            return p
    return None


def _build_ole_paragraph(*, rid_embed: str, rid_image: str,
                          shape_id: str, obj_id: str):
    """Build a centred paragraph carrying an OLE-embedded Excel
    icon shape. Returns a lxml element ready to insert.

    The exact XML follows the shape Word produces when you
    Insert → Object → Display-as-icon → Excel workbook. Width /
    height are 48 pt — same scale as Word's default icon view.
    """
    # Display size: 96 pt × 96 pt.  dxaOrig / dyaOrig must match the
    # display size in twips (1 pt = 20 twips) so Word does not scale the
    # icon content — a mismatch (e.g. 9144 twips ≈ 457 pt) caused the
    # embedded object icon to appear tiny after the user clicked it.
    _PT = 96
    _TWIPS = _PT * 20  # 1920
    xml = f"""<w:p xmlns:w="{_NS['w']}"
                  xmlns:r="{_NS['r']}"
                  xmlns:v="{_NS['v']}"
                  xmlns:o="{_NS['o']}">
        <w:pPr><w:jc w:val="center"/></w:pPr>
        <w:r>
          <w:object w:dxaOrig="{_TWIPS}" w:dyaOrig="{_TWIPS}">
            <v:shape id="{shape_id}" type="#_x0000_t75"
                     style="width:{_PT}pt;height:{_PT}pt" o:ole="t">
              <v:imagedata r:id="{rid_image}" o:title=""/>
            </v:shape>
            <o:OLEObject Type="Embed" ProgID="Excel.Sheet.12"
                         ShapeID="{shape_id}" DrawAspect="Icon"
                         ObjectID="_{obj_id}" r:id="{rid_embed}">
              <o:FieldCodes/>
            </o:OLEObject>
          </w:object>
        </w:r>
      </w:p>"""
    return etree.fromstring(xml)


def _build_caption_paragraph(label: str, filename: str):
    """Italic, centred caption paragraph that names the figure +
    repeats the embedded filename. Lives directly under the icon.
    """
    # XML-escape the caption strings — `label` is admin-editable
    # text so &/</> need to survive into the doc as literals.
    from xml.sax.saxutils import escape as _xml_escape
    safe_label = _xml_escape(label or "")
    safe_file  = _xml_escape(filename or "")
    xml = f"""<w:p xmlns:w="{_NS['w']}">
        <w:pPr>
          <w:jc w:val="center"/>
        </w:pPr>
        <w:r>
          <w:rPr>
            <w:i/>
            <w:color w:val="595959"/>
            <w:sz w:val="18"/>
          </w:rPr>
          <w:t xml:space="preserve">{safe_label} (</w:t>
        </w:r>
        <w:r>
          <w:rPr>
            <w:i/>
            <w:color w:val="595959"/>
            <w:sz w:val="18"/>
            <w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>
          </w:rPr>
          <w:t xml:space="preserve">{safe_file}</w:t>
        </w:r>
        <w:r>
          <w:rPr>
            <w:i/>
            <w:color w:val="595959"/>
            <w:sz w:val="18"/>
          </w:rPr>
          <w:t xml:space="preserve">)</w:t>
        </w:r>
      </w:p>"""
    return etree.fromstring(xml)


def _serialise(tree) -> bytes:
    """Serialise an lxml tree back to bytes with the right XML
    declaration Word expects (standalone='yes', UTF-8)."""
    return etree.tostring(
        tree, xml_declaration=True, encoding="UTF-8", standalone=True,
    )


# ============================================================
# PDF file-attachment post-pass
# ============================================================
#
# Why this exists
# ---------------
# `embed_xlsx_attachments` injects OLE-embedded xlsx into the DOCX so
# Word renders a clickable Excel icon inside the document. That OLE
# object is a Word/Office feature — when LibreOffice converts the
# DOCX to PDF it can render the *icon image* (so the layout looks
# right) but it cannot carry the embedded spreadsheet into the PDF.
# PDF has its own mechanism for this called "embedded files" / file
# attachments (PDF spec §7.11). They show up in Adobe Reader's
# attachments panel and in browser PDF viewers' download panel,
# and can be extracted with `pdfdetach`, pikepdf, pypdf, etc.
#
# This function takes the already-converted PDF and attaches every
# xlsx so the final deliverable carries the workbook *inside* the
# PDF — no "Refer to the attached file" prose pointing at a missing
# file when the consultant emails just the PDF.
#
# pypdf 4.x ships `PdfWriter.add_attachment(filename, data)` which
# does exactly this; we read the PDF, clone-write through a writer,
# call add_attachment for each xlsx, and overwrite the PDF in place.

def embed_pdf_attachments(pdf_path: Path,
                           attachments: list[dict]) -> int:
    """Attach every xlsx in ``attachments`` to the PDF at ``pdf_path``
    as a PDF embedded-file (PDF spec §7.11).

    Each entry is the same dict shape used by
    ``embed_xlsx_attachments``:

        {
          "marker":   ... (ignored here — not needed for PDF),
          "xlsx_path":<Path: where the xlsx lives on disk>,
          "filename": <str: visible filename in the attachments panel>,
          "label":    <str: caption — used as the attachment description>,
        }

    Returns the number of attachments successfully embedded. Failure
    on ONE attachment doesn't abort the others; it logs a warning
    and that attachment is skipped — the PDF still gets written with
    whatever succeeded.

    The PDF is overwritten in place. A temp file is used as a staging
    area so a mid-write crash can't corrupt the original.
    """
    if not attachments:
        return 0

    pdf_path = Path(pdf_path)
    if not pdf_path.exists():
        logger.warning("embed_pdf_attachments: pdf missing at %s", pdf_path)
        return 0

    try:
        from pypdf import PdfReader, PdfWriter
    except ImportError:                                  # pragma: no cover
        logger.warning(
            "embed_pdf_attachments: pypdf not installed — "
            "PDF deliverable will not carry the xlsx attachments"
        )
        return 0

    try:
        reader = PdfReader(str(pdf_path))
    except Exception as e:                                # pragma: no cover
        logger.warning(
            "embed_pdf_attachments: cannot read pdf %s: %s", pdf_path, e
        )
        return 0

    writer = PdfWriter(clone_from=reader)

    embedded = 0
    seen_names: set[str] = set()
    # Order in which we successfully embedded files — used below to
    # pair each embedded file with the right on-page anchor (caption /
    # "Refer to the attached file" prose) so we can drop a clickable
    # FileAttachment annotation INSIDE the relevant finding chapter,
    # not just in the document-level attachments panel.
    embed_order: list[dict] = []
    for spec in attachments:
        xlsx_path = spec.get("xlsx_path")
        filename = spec.get("filename") or ""
        if not (xlsx_path and filename):
            continue
        xlsx_path = Path(xlsx_path)
        if not xlsx_path.exists():
            logger.warning(
                "embed_pdf_attachments: xlsx missing on disk: %s", xlsx_path,
            )
            continue
        # Some readers (and the PDF /Names tree) misbehave with
        # duplicate filenames. Disambiguate by suffixing _2, _3 etc.
        attach_name = filename
        suffix = 2
        while attach_name in seen_names:
            stem, dot, ext = filename.rpartition(".")
            attach_name = (f"{stem}_{suffix}.{ext}" if dot
                           else f"{filename}_{suffix}")
            suffix += 1
        seen_names.add(attach_name)

        try:
            data = xlsx_path.read_bytes()
            writer.add_attachment(attach_name, data)
            embedded += 1
            embed_order.append({
                "attach_name": attach_name,
                "filename": filename,
                "label": spec.get("label") or filename,
            })
        except Exception as e:                            # pragma: no cover
            logger.warning(
                "embed_pdf_attachments: failed to attach %s: %s",
                filename, e,
            )
            continue

    if embedded == 0:
        return 0

    # ---- Inline clickable-icon post-pass (PDF annotations) ----
    # The document-level attachments above show up only in the viewer's
    # side panel. To reproduce the Word experience — a clickable Excel
    # icon sitting IN the finding's chapter — we additionally drop a
    # FileAttachment annotation onto the page, positioned over the icon
    # that LibreOffice rendered from the DOCX's OLE object (or, if that
    # embed failed, over the "Refer to the attached file" prose). The
    # annotation carries a vector Excel-icon appearance so it both looks
    # right and opens the workbook on click. Entirely best-effort: any
    # failure leaves the proven panel-level attachments untouched.
    try:
        _add_inline_file_annotations(writer, pdf_path, embed_order)
    except Exception as e:                                # pragma: no cover
        logger.warning(
            "embed_pdf_attachments: inline icon annotations failed "
            "(non-fatal, panel attachments still present): %s", e,
        )

    # Atomic-ish write: stage to a temp path, then replace the original.
    # A mid-write crash can't corrupt the existing PDF.
    with tempfile.NamedTemporaryFile(
            suffix=".pdf", delete=False, dir=str(pdf_path.parent)) as tmp:
        tmp_path = Path(tmp.name)
    try:
        with open(tmp_path, "wb") as fh:
            writer.write(fh)
        # On Windows the destination must not be locked; replace handles it.
        shutil.move(str(tmp_path), str(pdf_path))
    except Exception as e:                                # pragma: no cover
        logger.warning(
            "embed_pdf_attachments: failed to overwrite %s: %s", pdf_path, e,
        )
        try:
            tmp_path.unlink()
        except OSError:
            pass
        return 0

    return embedded


# ============================================================
# Inline FileAttachment annotations (clickable icon in-chapter)
# ============================================================
#
# Why annotations rather than only the /Names embedded-files tree
# ---------------------------------------------------------------
# `PdfWriter.add_attachment` registers each xlsx in the document
# catalog's /Names/EmbeddedFiles tree. That makes the file extractable
# (pdfdetach, browser "attachments" panel) but it has NO position on
# any page — viewers surface it only in a side panel. The consultant's
# expectation, matching the Word doc, is a clickable Excel icon sitting
# in the relevant finding's chapter. The PDF feature for that is a
# FileAttachment annotation (PDF 32000-1 §12.5.6.15): it lives on a
# page at a /Rect, references a file specification, and opens the file
# on click. We give it a custom appearance stream that draws an Excel-
# style icon so it both looks right and is interactive.

# Excel-green body, drawn in a 96×96 appearance-stream coordinate box
# (origin bottom-left, y up). Mirrors `make_excel_icon_png`.
_EXCEL_ICON_AP_CONTENT = (
    b"0.114 0.435 0.259 rg "          # Excel green fill
    b"8 10 80 72 re f "               # body rectangle
    b"8 78 52 12 re f "               # top "tab"
    b"6 w 1 1 1 RG "                  # white, 6pt stroke
    b"22 68 m 74 24 l S "            # "\" stroke of the X
    b"74 68 m 22 24 l S"             # "/" stroke of the X
)


def _add_inline_file_annotations(writer, pdf_path: Path,
                                 embed_order: list[dict]) -> int:
    """Place a clickable FileAttachment annotation on the page for each
    successfully embedded xlsx, anchored to the caption / prose that
    names it. Returns the number of annotations added.

    `embed_order` is the list (in embed order) of
    ``{attach_name, filename, label}`` dicts built by the caller. Each
    entry is matched to its embedded file-spec (by attach_name) and to
    an on-page anchor (located with pdfplumber by the visible filename).
    """
    if not embed_order:
        return 0

    try:
        import pdfplumber
    except ImportError:                                   # pragma: no cover
        logger.info(
            "embed_pdf_attachments: pdfplumber not installed — skipping "
            "inline icon annotations (panel attachments still present)"
        )
        return 0

    from pypdf.generic import (
        ArrayObject, DecodedStreamObject, DictionaryObject,
        NameObject, NumberObject, FloatObject, TextStringObject,
    )

    # Map attach_name -> file-specification object (built by
    # add_attachment in the catalog /Names/EmbeddedFiles tree).
    filespecs = _embedded_filespecs_by_name(writer)
    if not filespecs:
        return 0

    # Locate every anchor up front (pdfplumber owns the file handle;
    # do all reads before we mutate + rewrite the PDF).
    anchors: list[tuple[int, tuple]] = []
    with pdfplumber.open(str(pdf_path)) as pdf:
        consumed: set[tuple] = set()
        for entry in embed_order:
            anchor = _locate_icon_rect(pdf, entry["filename"], consumed)
            anchors.append(anchor)   # (page_index, rect) or None

    def _add_object(obj):
        # Public name varies across pypdf 4.x point releases; both the
        # private and (newer) public spelling exist — prefer whichever.
        fn = getattr(writer, "_add_object", None) or getattr(
            writer, "add_object", None)
        return fn(obj)

    added = 0
    for entry, anchor in zip(embed_order, anchors):
        if anchor is None:
            continue
        page_index, (llx, lly, urx, ury) = anchor
        try:
            page = writer.pages[page_index]
        except (IndexError, KeyError):
            continue
        filespec = filespecs.get(entry["attach_name"])
        if filespec is None:
            continue

        # Appearance stream: a Form XObject drawing the Excel icon,
        # mapped from its 96×96 BBox onto the annotation /Rect.
        ap = DecodedStreamObject()
        ap.set_data(_EXCEL_ICON_AP_CONTENT)
        ap[NameObject("/Type")] = NameObject("/XObject")
        ap[NameObject("/Subtype")] = NameObject("/Form")
        ap[NameObject("/FormType")] = NumberObject(1)
        ap[NameObject("/BBox")] = ArrayObject(
            [FloatObject(0), FloatObject(0), FloatObject(96), FloatObject(96)]
        )
        ap[NameObject("/Resources")] = DictionaryObject()
        ap_ref = _add_object(ap)

        annot = DictionaryObject()
        annot[NameObject("/Type")] = NameObject("/Annot")
        annot[NameObject("/Subtype")] = NameObject("/FileAttachment")
        annot[NameObject("/FS")] = filespec
        annot[NameObject("/Rect")] = ArrayObject([
            FloatObject(llx), FloatObject(lly),
            FloatObject(urx), FloatObject(ury),
        ])
        # Standard icon name as a fallback for viewers that ignore /AP.
        annot[NameObject("/Name")] = NameObject("/Paperclip")
        annot[NameObject("/Contents")] = TextStringObject(
            entry.get("label") or entry["filename"]
        )
        # /F = 4 -> Print bit set, so the icon appears in printed output.
        annot[NameObject("/F")] = NumberObject(4)
        ap_dict = DictionaryObject()
        ap_dict[NameObject("/N")] = ap_ref
        annot[NameObject("/AP")] = ap_dict
        annot_ref = _add_object(annot)

        annots = page.get("/Annots")
        if annots is None:
            page[NameObject("/Annots")] = ArrayObject([annot_ref])
        else:
            annots.append(annot_ref)
        added += 1

    if added:
        logger.info(
            "embed_pdf_attachments: placed %d inline clickable icon(s)", added
        )
    return added


def _embedded_filespecs_by_name(writer) -> dict:
    """Return ``{attach_name: filespec_object}`` for every file embedded
    in the writer's catalog /Names/EmbeddedFiles tree. Empty dict if the
    tree is absent or shaped unexpectedly.
    """
    out: dict = {}
    try:
        root = writer._root_object
        names_root = root["/Names"]
        ef = names_root["/EmbeddedFiles"]
        arr = ef["/Names"]
    except (KeyError, TypeError, AttributeError):
        return out
    # The /Names array alternates [name_string, filespec, name, fs, ...].
    try:
        items = list(arr)
    except TypeError:
        return out
    for i in range(0, len(items) - 1, 2):
        try:
            name = str(items[i].get_object())
            spec = items[i + 1]
        except AttributeError:
            continue
        out[name] = spec
    return out


def _locate_icon_rect(pdf, filename: str, consumed: set):
    """Find where to place the clickable icon for ``filename``.

    Scans pages for the visible filename (it appears in the OLE-embed
    caption — "Figure N: … (filename.xlsx)" — or, if that embed failed,
    in the "Refer to the attached file: filename" prose). Returns
    ``(page_index, (llx, lly, urx, ury))`` in PDF user space (origin
    bottom-left), or ``None`` if no anchor is found.

    `consumed` tracks anchor positions already claimed by an earlier
    attachment so duplicate filenames map to successive occurrences
    rather than all landing on the first one.
    """
    for page_index, page in enumerate(pdf.pages):
        page_h = page.height
        try:
            words = page.extract_words(use_text_flow=False)
        except Exception:                                  # pragma: no cover
            continue

        # The word carrying the filename (caption renders it as a single
        # "(filename)" token; prose renders it as a bare "filename").
        cap_word = None
        for w in words:
            if filename in (w.get("text") or ""):
                key = (page_index, round(w["x0"], 1), round(w["top"], 1))
                if key in consumed:
                    continue
                cap_word = w
                cap_key = key
                break
        if cap_word is None:
            continue
        consumed.add(cap_key)

        cap_top = cap_word["top"]
        # Centre on the whole caption LINE (icon is centre-justified
        # above it), not just the filename token.
        line = [w for w in words if abs(w["top"] - cap_top) <= 3]
        line_x0 = min(w["x0"] for w in line)
        line_x1 = max(w["x1"] for w in line)
        cx = (line_x0 + line_x1) / 2.0

        # Prefer the actual icon image LibreOffice rendered just above
        # the caption: nearest image whose bottom is at/above the
        # caption and which overlaps the caption centre horizontally.
        best = None
        for im in page.images:
            iw = im["x1"] - im["x0"]
            ih = im["bottom"] - im["top"]
            if iw <= 0 or ih <= 0:
                continue
            if im["bottom"] > cap_top + 6:        # not above the caption
                continue
            if cap_top - im["top"] > 220:         # too far above
                continue
            if not (im["x0"] - 24 <= cx <= im["x1"] + 24):
                continue
            ratio = iw / ih
            score = abs(ratio - 1.0) + (cap_top - im["bottom"]) / 100.0
            if best is None or score < best[0]:
                best = (score, im)

        if best is not None:
            im = best[1]
            llx, urx = im["x0"], im["x1"]
            lly = page_h - im["bottom"]
            ury = page_h - im["top"]
        else:
            # No rendered icon found — synthesise a 96×96 box centred
            # just above the caption/prose line.
            half = 48.0
            base = page_h - cap_top          # caption top, y-up
            llx, urx = cx - half, cx + half
            lly, ury = base + 2.0, base + 98.0

        return page_index, (llx, lly, urx, ury)

    return None
