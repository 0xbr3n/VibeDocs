"""VA-Automater: Nessus VA scan workflow toolkit.

Modular library for processing recurring Nessus vulnerability assessments:
- Plugin-ID-first finding identity with hierarchical fallback matching
- Multi-source risk-acceptance ingestion (Excel, CSV; PDF planned)
- Weighted multi-field categorization with persistent plugin_id -> category map
- CVSS 3.1 and CVSS 4.0 bulk reassessment
- Image-safe Excel tracker write-back (Windows COM)

This is a library. Run the CLI via `python run.py` from the project root,
or import individual modules for scripted/UI use.
"""

__version__ = "0.3.0"
