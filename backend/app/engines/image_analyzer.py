import os
import re
import logging
from typing import List, Tuple, Dict, Any, Optional
from PIL import Image

from app.schemas.scan import Finding, SeverityLevel
from app.detectors.phishing import PhishingDetector
from app.detectors.content_analysis import ContentAnalyzer

logger = logging.getLogger(__name__)

# Try OpenCV for QR detection (built into cv2)
try:
    import cv2
    import numpy as np
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

# Try pytesseract
try:
    import pytesseract
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False


class ImageAnalyzer:
    def __init__(self):
        self.phishing_detector = PhishingDetector()
        self.content_analyzer = ContentAnalyzer()

    def analyze(self, image_path: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        metadata: Dict[str, Any] = {
            "image_format": None,
            "dimensions": None,
            "has_qr_code": False,
            "decoded_qr_data": None,
            "ocr_text": "",
            "extracted_urls": []
        }

        # 1. Pillow Image Metadata
        try:
            with Image.open(image_path) as img:
                metadata["image_format"] = img.format
                metadata["dimensions"] = f"{img.width}x{img.height}"
                metadata["mode"] = img.mode

                # Steganography / file anomaly heuristic
                file_size = os.path.getsize(image_path)
                expected_max = img.width * img.height * 4
                if file_size > expected_max * 2 and file_size > 10 * 1024 * 1024:
                    findings.append(Finding(
                        title="Unusual File Size Anomaly",
                        description="The image file size is unusually large compared to its resolution, which may indicate appended malicious payload or steganography.",
                        severity=SeverityLevel.medium,
                        evidence=f"Size: {file_size} bytes, Res: {img.width}x{img.height}",
                        category="Anomaly Detection"
                    ))
        except Exception as e:
            findings.append(Finding(
                title="Corrupted or Invalid Image",
                description=f"Could not open file as standard image: {str(e)}",
                severity=SeverityLevel.high,
                evidence=str(e),
                category="Image Integrity"
            ))
            return findings, metadata

        # 2. QR Code Detection (OpenCV QRCodeDetector + pyzbar fallback)
        qr_data = self._detect_qr(image_path)
        if qr_data:
            metadata["has_qr_code"] = True
            metadata["decoded_qr_data"] = qr_data
            findings.append(Finding(
                title="QR Code Detected in Image",
                description="Image contains a scannable QR code. Malicious actors use Quishing (QR Phishing) to bypass email security filters and direct users to fraudulent sites or rogue UPI payment requests.",
                severity=SeverityLevel.info,
                evidence=f"Payload: {qr_data}",
                category="QR Threat"
            ))

            # If QR contains URL, inspect the URL
            if qr_data.startswith("http://") or qr_data.startswith("https://"):
                url_findings = self.phishing_detector.check_url(qr_data)
                findings.extend(url_findings)

            # If QR contains UPI payment URI
            if "upi://pay" in qr_data.lower():
                findings.append(Finding(
                    title="UPI Payment Intent QR Code",
                    description="Decoded QR is a direct UPI payment request. Verify recipient VPA before proceeding with any authentication.",
                    severity=SeverityLevel.medium,
                    evidence=qr_data[:80],
                    category="Financial Action"
                ))

        # 3. Optical Character Recognition (OCR)
        ocr_text = self._extract_ocr_text(image_path)
        if ocr_text:
            metadata["ocr_text"] = ocr_text
            metadata["extracted_text_preview"] = ocr_text[:300]

            # Text content analysis for scams / urgency / credentials
            text_findings = self.content_analyzer.analyze_text(ocr_text)
            findings.extend(text_findings)

            # URL extraction from OCR text
            url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
            found_urls = re.findall(url_pattern, ocr_text)
            metadata["extracted_urls"] = found_urls[:10]
            for u in found_urls[:5]:
                u_find = self.phishing_detector.check_url(u)
                findings.extend(u_find)

            # Check for screenshot phishing / fake alerts
            lower_ocr = ocr_text.lower()
            if any(term in lower_ocr for term in ["arrest warrant", "cbi officer", "cyber crime cell", "digital arrest", "police notice"]):
                findings.append(Finding(
                    title="Digital Arrest / Law Enforcement Impersonation Document",
                    description="Image text contains intimidation language impersonating law enforcement, police, or investigative agencies commonly observed in Digital Arrest extortion schemes.",
                    severity=SeverityLevel.critical,
                    evidence=ocr_text[:120],
                    category="Digital Arrest Threat"
                ))

            if any(term in lower_ocr for term in ["enter otp", "share otp", "bank account suspended", "kyc verification pending"]):
                findings.append(Finding(
                    title="Phishing Notice Screenshot Detected",
                    description="Image contains fraudulent urgency notices regarding account suspension or OTP requests.",
                    severity=SeverityLevel.high,
                    evidence=ocr_text[:100],
                    category="Social Engineering"
                ))

        return findings, metadata

    def _detect_qr(self, image_path: str) -> Optional[str]:
        # Try OpenCV QRCodeDetector
        if CV2_AVAILABLE:
            try:
                img = cv2.imread(image_path)
                if img is not None:
                    detector = cv2.QRCodeDetector()
                    data, bbox, _ = detector.detectAndDecode(img)
                    if data:
                        return data.strip()
            except Exception as e:
                logger.debug(f"OpenCV QR decode error: {e}")

        # Try pyzbar if available
        try:
            from pyzbar.pyzbar import decode
            with Image.open(image_path) as img:
                decoded = decode(img)
                if decoded:
                    return decoded[0].data.decode("utf-8", errors="ignore").strip()
        except Exception:
            pass

        return None

    def _extract_ocr_text(self, image_path: str) -> str:
        if not TESSERACT_AVAILABLE:
            return ""

        try:
            with Image.open(image_path) as img:
                # Convert to RGB if needed
                if img.mode != "RGB":
                    img = img.convert("RGB")
                text = pytesseract.image_to_string(img)
                return text.strip()
        except Exception as e:
            # Tesseract binary might not be on system PATH in Windows; log and degrade gracefully
            logger.debug(f"Pytesseract execution note (fallback active): {e}")
            return ""
