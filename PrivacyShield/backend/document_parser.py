"""
PrivacyShield - Universal Enterprise Document & Image Text Extractor
Supports:
- PDF: .pdf
- Word: .doc, .docx
- Excel: .xls, .xlsx
- PowerPoint: .ppt, .pptx
- Text: .txt
- CSV: .csv
- JSON: .json
- XML: .xml
- Images: .jpg, .jpeg, .png, .webp, .bmp, .tiff
"""

import os
import io
import re
import csv
import json
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Any, Tuple

logger = logging.getLogger("PrivacyShield.DocumentParser")
logger.setLevel(logging.INFO)

SUPPORTED_EXTENSIONS = {
    # PDF
    "pdf": "PDF Document",
    # Word
    "docx": "Word Document (DOCX)",
    "doc": "Word Document (DOC)",
    # Excel
    "xlsx": "Excel Spreadsheet (XLSX)",
    "xls": "Excel Spreadsheet (XLS)",
    # PowerPoint
    "pptx": "PowerPoint Presentation (PPTX)",
    "ppt": "PowerPoint Presentation (PPT)",
    # Text & Structured
    "txt": "Plain Text Document",
    "csv": "Comma-Separated Values (CSV)",
    "json": "JSON Data Document",
    "xml": "XML Data Document",
    # Images
    "jpg": "JPEG Image",
    "jpeg": "JPEG Image",
    "png": "PNG Image",
    "webp": "WebP Image",
    "bmp": "Bitmap Image (BMP)",
    "tiff": "TIFF Image",
    "tif": "TIFF Image",
}

class DocumentParser:
    """Universal parser for extracting plain text from office documents, spreadsheets, data files, and images."""

    def __init__(self):
        self._ocr = None

    def _get_ocr(self):
        if self._ocr is None:
            try:
                from rapidocr_onnxruntime import RapidOCR
                self._ocr = RapidOCR()
            except Exception as e:
                logger.warning(f"RapidOCR initialization notice: {e}")
                self._ocr = False
        return self._ocr

    def parse(self, filename: str, content_bytes: bytes) -> Dict[str, Any]:
        """
        Parses binary or text content based on file extension and returns extracted text.
        """
        if not filename:
            raise ValueError("Filename is required.")

        ext = filename.lower().split(".")[-1] if "." in filename else ""
        if ext not in SUPPORTED_EXTENSIONS:
            allowed = ", ".join([f".{e}" for e in sorted(SUPPORTED_EXTENSIONS.keys())])
            raise ValueError(
                f"Unsupported file format '.{ext}'. Supported formats are: {allowed}"
            )

        format_label = SUPPORTED_EXTENSIONS[ext]
        size_bytes = len(content_bytes)
        size_formatted = self._format_size(size_bytes)

        extracted_text = ""

        # 1. Plain Text
        if ext == "txt":
            extracted_text = self._parse_text(content_bytes)

        # 2. CSV
        elif ext == "csv":
            extracted_text = self._parse_csv(content_bytes)

        # 3. JSON
        elif ext == "json":
            extracted_text = self._parse_json(content_bytes)

        # 4. XML
        elif ext == "xml":
            extracted_text = self._parse_xml(content_bytes)

        # 5. PDF
        elif ext == "pdf":
            extracted_text = self._parse_pdf(content_bytes)

        # 6. Word (DOCX / DOC)
        elif ext in ("docx", "doc"):
            extracted_text = self._parse_docx(content_bytes, ext)

        # 7. Excel (XLSX / XLS)
        elif ext in ("xlsx", "xls"):
            extracted_text = self._parse_excel(content_bytes, ext)

        # 8. PowerPoint (PPTX / PPT)
        elif ext in ("pptx", "ppt"):
            extracted_text = self._parse_powerpoint(content_bytes, ext)

        # 9. Images (JPG, JPEG, PNG, WEBP, BMP, TIFF)
        elif ext in ("jpg", "jpeg", "png", "webp", "bmp", "tiff", "tif"):
            extracted_text = self._parse_image(content_bytes, filename)

        extracted_text = extracted_text.strip()
        if not extracted_text:
            extracted_text = f"[No readable text content found in uploaded {format_label} '{filename}']"

        return {
            "success": True,
            "filename": filename,
            "extension": ext,
            "format": format_label,
            "size_bytes": size_bytes,
            "size_formatted": size_formatted,
            "extracted_characters": len(extracted_text),
            "text": extracted_text
        }

    def _format_size(self, size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        else:
            return f"{size_bytes / (1024 * 1024):.1f} MB"

    def _parse_text(self, b: bytes) -> str:
        for enc in ("utf-8", "utf-8-sig", "latin-1", "cp1252"):
            try:
                return b.decode(enc)
            except UnicodeDecodeError:
                continue
        return b.decode("utf-8", errors="replace")

    def _parse_csv(self, b: bytes) -> str:
        text = self._parse_text(b)
        reader = csv.reader(io.StringIO(text))
        rows = []
        for row in reader:
            if any(cell.strip() for cell in row):
                rows.append(", ".join([cell.strip() for cell in row if cell.strip()]))
        return "\n".join(rows)

    def _parse_json(self, b: bytes) -> str:
        text = self._parse_text(b)
        try:
            parsed = json.loads(text)
            return json.dumps(parsed, indent=2, ensure_ascii=False)
        except Exception:
            return text

    def _parse_xml(self, b: bytes) -> str:
        text = self._parse_text(b)
        try:
            root = ET.fromstring(text)
            lines = []
            for elem in root.iter():
                t = (elem.text or "").strip()
                if t:
                    lines.append(f"{elem.tag}: {t}")
            return "\n".join(lines) if lines else text
        except Exception:
            cleaned = re.sub(r"<[^>]+>", " ", text)
            return re.sub(r"\s+", " ", cleaned).strip()

    def _parse_pdf(self, b: bytes) -> str:
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(b))
        pages_text = []
        for idx, page in enumerate(reader.pages):
            txt = page.extract_text()
            if txt and txt.strip():
                pages_text.append(txt.strip())
        return "\n\n".join(pages_text)

    def _parse_docx(self, b: bytes, ext: str) -> str:
        if ext == "docx":
            try:
                import docx
                doc = docx.Document(io.BytesIO(b))
                parts = []
                for p in doc.paragraphs:
                    if p.text.strip():
                        parts.append(p.text.strip())
                for table in doc.tables:
                    for row in table.rows:
                        vals = [c.text.strip() for c in row.cells if c.text.strip()]
                        if vals:
                            parts.append(" | ".join(vals))
                return "\n".join(parts)
            except Exception as e:
                logger.warning(f"python-docx error on {ext}: {e}")

        # Fallback binary text extractor for legacy .doc or unstandard docx
        strings = re.findall(rb"[\x20-\x7E\r\n\t]{4,}", b)
        clean_lines = []
        for s in strings:
            try:
                decoded = s.decode("ascii", errors="ignore").strip()
                if len(decoded) > 3 and not decoded.startswith(("<?xml", "word/", "docProps/")):
                    clean_lines.append(decoded)
            except Exception:
                continue
        return "\n".join(clean_lines)

    def _parse_excel(self, b: bytes, ext: str) -> str:
        try:
            import openpyxl
            wb = openpyxl.load_workbook(io.BytesIO(b), data_only=True)
            lines = []
            for sheet in wb.worksheets:
                lines.append(f"--- Sheet: {sheet.title} ---")
                for row in sheet.iter_rows(values_only=True):
                    vals = [str(v).strip() for v in row if v is not None and str(v).strip()]
                    if vals:
                        lines.append(", ".join(vals))
            return "\n".join(lines)
        except Exception as e:
            logger.warning(f"openpyxl failed: {e}")
            strings = re.findall(rb"[\x20-\x7E\r\n\t]{4,}", b)
            return "\n".join([s.decode("ascii", errors="ignore").strip() for s in strings if len(s) > 4])

    def _parse_powerpoint(self, b: bytes, ext: str) -> str:
        try:
            import pptx
            prs = pptx.Presentation(io.BytesIO(b))
            lines = []
            for idx, slide in enumerate(prs.slides):
                slide_lines = []
                for shape in slide.shapes:
                    if shape.has_text_frame:
                        for p in shape.text_frame.paragraphs:
                            if p.text.strip():
                                slide_lines.append(p.text.strip())
                if slide_lines:
                    lines.append(f"--- Slide {idx + 1} ---")
                    lines.extend(slide_lines)
            return "\n".join(lines)
        except Exception as e:
            logger.warning(f"python-pptx failed: {e}")
            strings = re.findall(rb"[\x20-\x7E\r\n\t]{4,}", b)
            return "\n".join([s.decode("ascii", errors="ignore").strip() for s in strings if len(s) > 4])

    def _parse_image(self, b: bytes, filename: str) -> str:
        ocr = self._get_ocr()
        ocr_lines = []
        if ocr:
            try:
                res, _ = ocr(b)
                if res:
                    for line in res:
                        if len(line) >= 2 and line[1].strip():
                            ocr_lines.append(line[1].strip())
            except Exception as e:
                logger.warning(f"RapidOCR error on image {filename}: {e}")

        if ocr_lines:
            return "\n".join(ocr_lines)

        try:
            from PIL import Image
            img = Image.open(io.BytesIO(b))
            return f"Image Document: {filename}\nFormat: {img.format}\nDimensions: {img.size[0]}x{img.size[1]} px\nColor Mode: {img.mode}"
        except Exception:
            return f"Image file {filename} ({len(b)} bytes)"
