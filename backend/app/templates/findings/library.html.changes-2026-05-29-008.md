# Change note: Rich-text (Quill) editors in Edit Library Finding modal
**Date:** 2026-05-29
See session log session-2026-05-29-007 for the original Edit modal implementation.

## Change
Replaced the four plain `<textarea>` fields in the Edit Library Finding modal with
Quill rich-text editors (same editor used in the report finding editor):
- Description
- Impact
- Remediation
- References

## Implementation
- Quill 1.3.7 is lazy-loaded from CDN only when the edit modal is first opened (no
  impact on library page load for users who never edit).
- `_loadQuill()` — returns a Promise that resolves once Quill CSS + JS are loaded.
- `_mountOrUpdateEditor(taId, htmlContent)` — on first call, inserts a `.ef-rich-host`
  div before the textarea and mounts a Quill Snow instance on it; hides the raw textarea.
  On subsequent calls (modal re-opened for a different finding), updates content via
  `q.clipboard.dangerouslyPasteHTML()` or `q.setText()`.
- Quill mirrors its content back to the hidden textarea's `.value` on every text-change
  event, so `saveFinding()` reads the correct HTML with no changes.
- Toolbar: Bold, Italic, Underline, Strike, Ordered List, Bullet List, Blockquote,
  Code Block, Link, Clean.
- Fallback: if Quill CDN fails to load, the raw textarea is shown instead (graceful
  degradation).
- CSS for `.ef-rich-host` added inline in the page's `<style>` block; adapts to all
  five app themes (dark/light/midnight/dracula/solarized/forest) via CSS variables.
