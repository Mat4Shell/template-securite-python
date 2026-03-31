import base64

from src.tp4.utils.config import logger


class Decoder:
    """
    Class responsible for decoding challenges sent by the server.

    The server may send data encoded in one or more layers of base64.
    This class handles detection and decoding of these layers.
    """

    MAX_LAYERS = 10

    def __init__(self, raw: bytes) -> None:
        """
        Initialize the decoder with raw bytes received from the server.

        Args:
            raw: Raw bytes received from the server
        """

        self.raw = raw
        self.decoded: str = ""

    def decode(self) -> str:
        """
        Attempt to decode the raw data received from the server.

        Tries multiple base64 decoding layers until the data is fully decoded.
        Falls back to raw UTF-8 if no base64 encoding is detected.

        Returns:
            The fully decoded string value
        """

        data = self.raw.strip()

        logger.debug(f"Raw data received: {data[:80]}...")

        decoded = self._decode_base64_layers(data)
        self.decoded = decoded

        logger.info(f"Decoded value: {self.decoded}")
        return self.decoded

    def _decode_base64_layers(self, data: bytes) -> str:
        """
        Recursively decode base64 layers until plaintext is reached.

        Args:
            data: Bytes to decode

        Returns:
            Decoded plaintext string
        """

        current = data

        for layer in range(self.MAX_LAYERS):
            if not self._is_base64(current):
                logger.debug(f"Stopped decoding after {layer} layer(s)")
                break

            try:
                current = base64.b64decode(current)
                logger.debug(f"Layer {layer + 1} decoded: {current[:40]}")
            except Exception as e:
                logger.warning(f"Failed to decode layer {layer + 1}: {e}")
                break

        try:
            return current.decode("utf-8").strip()
        except UnicodeDecodeError:
            return current.decode("latin-1").strip()

    @staticmethod
    def _is_base64(data: bytes) -> bool:
        """
        Check whether the given bytes look like valid base64-encoded data.

        Args:
            data: Bytes to check

        Returns:
            True if the data appears to be base64-encoded
        """

        try:
            stripped = data.strip()
            if not all(c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r " for c in stripped):
                return False
            base64.b64decode(stripped)
            return True
        except Exception:
            return False

    def get_decoded(self) -> str:
        """
        Return the last decoded value.

        Returns:
            The decoded string
        """

        return self.decoded