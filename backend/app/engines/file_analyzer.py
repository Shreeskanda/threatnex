import os
import re
import zipfile
import logging
from typing import List, Tuple, Dict, Any
from app.schemas.scan import Finding, SeverityLevel
from app.detectors.phishing import PhishingDetector
from app.detectors.content_analysis import ContentAnalyzer
from app.detectors.html_inspector import HTMLInspector

logger = logging.getLogger(__name__)

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", 
    ".ps1", ".hta", ".iso", ".lnk", ".dll", ".sys", ".cpl", ".msi"
}

SUSPICIOUS_MACRO_KEYWORDS = [
    "enable macro", "enable content", "enable editing", "yellow bar",
    "security warning", "macros have been disabled", "click enable",
    "protected view", "device compatibility", "enable active content"
]


class FileAnalyzer:
    def __init__(self):
        self.phishing_detector = PhishingDetector()
        self.content_analyzer = ContentAnalyzer()
        self.html_inspector = HTMLInspector()

    def analyze(self, file_path: str, mime_type: str, original_filename: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        metadata: Dict[str, Any] = {
            "filename": original_filename,
            "mime_type": mime_type,
            "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            "extracted_urls": [],
            "extracted_text_preview": ""
        }

        ext = os.path.splitext(original_filename.lower())[1]

        # Route by extension / MIME type
        if ext == ".pdf" or "pdf" in mime_type:
            f, m = self._analyze_pdf(file_path)
            findings.extend(f)
            metadata.update(m)
        elif ext in [".docx", ".doc", ".docm"] or "word" in mime_type:
            f, m = self._analyze_docx(file_path, ext)
            findings.extend(f)
            metadata.update(m)
        elif ext in [".pptx", ".ppt", ".pptm"] or "presentation" in mime_type:
            f, m = self._analyze_pptx(file_path, ext)
            findings.extend(f)
            metadata.update(m)
        elif ext == ".csv" or "csv" in mime_type:
            f, m = self._analyze_csv(file_path)
            findings.extend(f)
            metadata.update(m)
        elif ext in [".txt", ".log"] or "text/plain" in mime_type:
            f, m = self._analyze_text(file_path)
            findings.extend(f)
            metadata.update(m)
        elif ext in [".html", ".htm"] or "html" in mime_type:
            f, m = self._analyze_html(file_path)
            findings.extend(f)
            metadata.update(m)
        elif ext in [".zip", ".rar", ".7z", ".tar", ".gz"] or "zip" in mime_type:
            f, m = self._analyze_archive(file_path)
            findings.extend(f)
            metadata.update(m)
        else:
            findings.append(Finding(
                title="Generic File Inspected",
                description=f"File extension {ext} analyzed with general binary safety checks.",
                severity=SeverityLevel.info,
                evidence=f"Extension: {ext}, Size: {metadata['file_size']} bytes",
                category="File Info"
            ))

        return findings, metadata

    def _analyze_pdf(self, file_path: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        meta: Dict[str, Any] = {"pdf_pages": 0, "has_javascript": False, "links": []}
        all_text = []

        try:
            import pypdf
            reader = pypdf.PdfReader(file_path)
            meta["pdf_pages"] = len(reader.pages)
            meta["pdf_metadata"] = {k: str(v) for k, v in (reader.metadata or {}).items() if k}

            # Check for embedded javascript in PDF catalog
            try:
                catalog = reader.trailer.get("/Root", {})
                if "/Names" in catalog and "/JavaScript" in catalog["/Names"]:
                    meta["has_javascript"] = True
                    findings.append(Finding(
                        title="Embedded JavaScript in PDF",
                        description="PDF contains embedded JavaScript actions, commonly used by exploit kits to trigger heap-sprays or drop malware.",
                        severity=SeverityLevel.critical,
                        evidence="/Root/Names/JavaScript found in PDF catalog",
                        category="Malicious Document"
                    ))
                if "/OpenAction" in catalog or "/AA" in catalog:
                    findings.append(Finding(
                        title="Automatic Execution Action in PDF",
                        description="Document contains an OpenAction/Additional Action that executes automatically when the document is opened.",
                        severity=SeverityLevel.high,
                        evidence="OpenAction trigger detected",
                        category="Malicious Document"
                    ))
            except Exception as e:
                logger.debug(f"Catalog inspection exception: {e}")

            # Extract text & links from pages
            extracted_urls = []
            for page_idx, page in enumerate(reader.pages):
                text = page.extract_text() or ""
                if text:
                    all_text.append(text)

                # Inspect annotations / links
                if "/Annots" in page:
                    annots = page["/Annots"]
                    if isinstance(annots, list):
                        for a in annots:
                            obj = a.get_object() if hasattr(a, "get_object") else a
                            if isinstance(obj, dict) and obj.get("/Subtype") == "/Link":
                                action = obj.get("/A")
                                if action and "/URI" in action:
                                    uri = str(action["/URI"])
                                    extracted_urls.append(uri)

            meta["extracted_urls"] = extracted_urls
            full_text = "\n".join(all_text)
            meta["extracted_text_preview"] = full_text[:500]

            # Analyze extracted URLs
            for url in set(extracted_urls):
                url_findings = self.phishing_detector.check_url(url)
                findings.extend(url_findings)

            # Analyze extracted text for phishing / scam
            if full_text:
                text_findings = self.content_analyzer.analyze_text(full_text)
                findings.extend(text_findings)

        except Exception as e:
            findings.append(Finding(
                title="Corrupted or Encrypted PDF",
                description=f"Error reading PDF structure: {str(e)}",
                severity=SeverityLevel.medium,
                evidence=str(e),
                category="Document Integrity"
            ))

        return findings, meta

    def _analyze_docx(self, file_path: str, ext: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        meta: Dict[str, Any] = {"extracted_urls": []}
        all_text = []

        if ext == ".docm":
            findings.append(Finding(
                title="Macro-Enabled Word Document (.docm)",
                description="This document contains active VBA macros which can execute arbitrary code upon opening.",
                severity=SeverityLevel.high,
                evidence="File extension: .docm",
                category="Macro Threat"
            ))

        try:
            import docx
            doc = docx.Document(file_path)
            for p in doc.paragraphs:
                if p.text:
                    all_text.append(p.text)
            for table in doc.tables:
                for row in table.rows:
                    for cell in row.cells:
                        if cell.text:
                            all_text.append(cell.text)

            full_text = "\n".join(all_text)
            meta["extracted_text_preview"] = full_text[:500]

            # Check for social engineering instructions to enable macros
            lower_text = full_text.lower()
            for phrase in SUSPICIOUS_MACRO_KEYWORDS:
                if phrase in lower_text:
                    findings.append(Finding(
                        title="Macro Activation Social Engineering",
                        description=f"Document contains instructions urging the user to enable macros/editing ('{phrase}'), a common tactic to bypass Office sandbox protection.",
                        severity=SeverityLevel.critical,
                        evidence=f"Matched text: '{phrase}'",
                        category="Social Engineering"
                    ))
                    break

            # Text content analysis
            if full_text:
                text_findings = self.content_analyzer.analyze_text(full_text)
                findings.extend(text_findings)

        except Exception as e:
            # Fallback to raw string extraction
            try:
                with open(file_path, "rb") as f:
                    content = f.read().decode("latin-1", errors="ignore")
                    for phrase in SUSPICIOUS_MACRO_KEYWORDS:
                        if phrase in content.lower():
                            findings.append(Finding(
                                title="Macro Activation Keywords Found",
                                description="Document binary contains macro activation instructions.",
                                severity=SeverityLevel.high,
                                evidence=phrase,
                                category="Social Engineering"
                            ))
                            break
            except Exception:
                pass

        return findings, meta

    def _analyze_pptx(self, file_path: str, ext: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        meta: Dict[str, Any] = {"slides_count": 0, "extracted_urls": []}
        all_text = []

        if ext == ".pptm":
            findings.append(Finding(
                title="Macro-Enabled Presentation (.pptm)",
                description="Presentation contains VBA macros capable of executing commands.",
                severity=SeverityLevel.high,
                evidence="File extension: .pptm",
                category="Macro Threat"
            ))

        try:
            from pptx import Presentation
            prs = Presentation(file_path)
            meta["slides_count"] = len(prs.slides)

            for slide in prs.slides:
                for shape in slide.shapes:
                    if hasattr(shape, "text") and shape.text:
                        all_text.append(shape.text)
                if slide.has_notes_slide and slide.notes_slide.notes_text_frame:
                    all_text.append(slide.notes_slide.notes_text_frame.text)

            full_text = "\n".join(all_text)
            meta["extracted_text_preview"] = full_text[:500]

            if full_text:
                text_findings = self.content_analyzer.analyze_text(full_text)
                findings.extend(text_findings)

        except Exception as e:
            logger.debug(f"PPTX analysis error: {e}")

        return findings, meta

    def _analyze_csv(self, file_path: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        meta: Dict[str, Any] = {}

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            meta["extracted_text_preview"] = content[:500]
            # ContentAnalyzer has specialized analyze_csv_content
            csv_findings = self.content_analyzer.analyze_csv_content(content)
            findings.extend(csv_findings)

        except Exception as e:
            findings.append(Finding(
                title="CSV Read Error",
                description=f"Error reading CSV content: {str(e)}",
                severity=SeverityLevel.low,
                evidence=str(e),
                category="File Error"
            ))

        return findings, meta

    def _analyze_text(self, file_path: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        meta: Dict[str, Any] = {}

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            meta["extracted_text_preview"] = content[:500]
            text_findings = self.content_analyzer.analyze_text(content)
            findings.extend(text_findings)

            # URL extraction from text
            url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
            urls = re.findall(url_pattern, content)
            meta["extracted_urls"] = urls[:20]
            for u in urls[:10]:
                u_find = self.phishing_detector.check_url(u)
                findings.extend(u_find)

        except Exception as e:
            logger.debug(f"Text read error: {e}")

        return findings, meta

    def _analyze_html(self, file_path: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        meta: Dict[str, Any] = {}

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            meta["extracted_text_preview"] = content[:500]
            html_findings = self.html_inspector.inspect(content, "file://local_analysis")
            findings.extend(html_findings)

        except Exception as e:
            logger.debug(f"HTML analysis error: {e}")

        return findings, meta

    def _analyze_archive(self, file_path: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        meta: Dict[str, Any] = {"file_count": 0, "files": []}

        try:
            if not zipfile.is_zipfile(file_path):
                findings.append(Finding(
                    title="Non-Standard Archive",
                    description="The archive file format could not be verified with standard ZIP safety parser.",
                    severity=SeverityLevel.medium,
                    evidence="Unsupported or corrupted archive header",
                    category="Archive Inspection"
                ))
                return findings, meta

            with zipfile.ZipFile(file_path, 'r') as zf:
                infolist = zf.infolist()
                meta["file_count"] = len(infolist)
                total_uncompressed = sum(info.file_size for info in infolist)
                compressed_size = os.path.getsize(file_path)

                # 1. Zip bomb detection
                if compressed_size > 0 and (total_uncompressed / compressed_size) > 100 and total_uncompressed > 50 * 1024 * 1024:
                    findings.append(Finding(
                        title="Potential Decompression Bomb (Zip Bomb)",
                        description=f"Archive compression ratio exceeds 100:1 (Uncompressed: {total_uncompressed // (1024*1024)}MB). This may cause Denial of Service.",
                        severity=SeverityLevel.critical,
                        evidence=f"Ratio: {total_uncompressed/compressed_size:.1f}x",
                        category="Archive Bomb"
                    ))

                # 2. Path traversal (Zip Slip) & dangerous executable extensions
                dangerous_files = []
                traversal_files = []
                sample_files = []

                for info in infolist[:100]:  # Limit inspection to 100 entries
                    fname = info.filename
                    sample_files.append(fname)

                    # Path traversal
                    if ".." in fname or fname.startswith("/") or fname.startswith("\\"):
                        traversal_files.append(fname)

                    # Dangerous executable in archive
                    ext = os.path.splitext(fname.lower())[1]
                    if ext in DANGEROUS_EXTENSIONS:
                        dangerous_files.append(fname)

                meta["files"] = sample_files[:30]

                if traversal_files:
                    findings.append(Finding(
                        title="Path Traversal Attempt (Zip Slip)",
                        description="Archive contains filenames with directory traversal patterns ('../') aimed at writing files outside extraction directory.",
                        severity=SeverityLevel.critical,
                        evidence=f"Suspicious paths: {', '.join(traversal_files[:3])}",
                        category="Path Traversal"
                    ))

                if dangerous_files:
                    findings.append(Finding(
                        title="Executable/Script Inside Archive",
                        description=f"Archive contains executable or script payload ({len(dangerous_files)} found). Often used in phishing dropper campaigns.",
                        severity=SeverityLevel.critical,
                        evidence=f"Found: {', '.join(dangerous_files[:5])}",
                        category="Malware Payload"
                    ))

        except Exception as e:
            findings.append(Finding(
                title="Archive Inspection Failed",
                description=f"Could not safely parse archive entries: {str(e)}",
                severity=SeverityLevel.medium,
                evidence=str(e),
                category="Archive Error"
            ))

        return findings, meta
