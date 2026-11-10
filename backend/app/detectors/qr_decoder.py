from typing import Optional
import logging

logger = logging.getLogger(__name__)

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from pyzbar import pyzbar
    HAS_PYZBAR = True
except ImportError:
    HAS_PYZBAR = False


class QRDecoder:

    def decode_from_image(self, image_path: str) -> Optional[str]:
        """Decode QR code from an image file path. Returns decoded content or None."""
        if not HAS_PIL:
            logger.warning("Pillow not installed; cannot decode QR from file.")
            return None
        try:
            img = Image.open(image_path)
            return self.decode_from_pil(img)
        except Exception as e:
            logger.error(f"QR decode from file failed: {e}")
            return None

    def decode_from_pil(self, image) -> Optional[str]:
        """Decode QR code from a PIL Image object. Returns decoded content or None."""
        if not HAS_PIL:
            return None

        # Try pyzbar first (most reliable)
        if HAS_PYZBAR:
            try:
                decoded_objects = pyzbar.decode(image)
                for obj in decoded_objects:
                    if obj.type in ("QRCODE", "CODE128", "CODE39", "EAN13", "EAN8", "UPCA"):
                        data = obj.data.decode("utf-8", errors="replace")
                        if data:
                            return data
            except Exception as e:
                logger.warning(f"pyzbar decode failed: {e}")

        # Fallback: try with enhanced image preprocessing
        if HAS_PYZBAR and HAS_PIL:
            try:
                from PIL import ImageEnhance, ImageFilter
                # Try grayscale + contrast enhancement
                gray = image.convert("L")
                enhanced = ImageEnhance.Contrast(gray).enhance(2.0)
                decoded_objects = pyzbar.decode(enhanced)
                for obj in decoded_objects:
                    data = obj.data.decode("utf-8", errors="replace")
                    if data:
                        return data
            except Exception as e:
                logger.warning(f"Enhanced QR decode failed: {e}")

        return None
