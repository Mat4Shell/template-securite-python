from pwn import remote, context

from src.tp4.utils.config import logger
from src.tp4.utils.decoder import Decoder

context.log_level = "error"


class Session:
    """
    Class managing the TCP session with the challenge server.

    Connects to the server, receives encoded challenges,
    decodes them and sends back the answer until the flag is obtained.

    Attributes:
        host (str): Server hostname or IP
        port (int): Server port
        flag (str): The flag obtained after completing all rounds
        _conn: The pwntools remote connection object
    """

    def __init__(self, host: str, port: int) -> None:
        """
        Initialize a new session.

        Args:
            host: Server IP or hostname
            port: Server port number
        """

        self.host = host
        self.port = port
        self.flag: str = ""
        self._conn = None

    def connect(self) -> None:
        """
        Establish a TCP connection to the server.
        """

        logger.info(f"Connecting to {self.host}:{self.port}...")
        self._conn = remote(self.host, self.port)
        logger.info("Connected!")

    def close(self) -> None:
        """
        Close the TCP connection.
        """

        if self._conn:
            self._conn.close()
            logger.info("Connection closed.")

    def receive_challenge(self) -> bytes:
        """
        Receive the challenge data sent by the server.

        The server may send a prompt/question before the encoded data,
        so we read all available lines until the actual challenge arrives.

        Returns:
            Raw bytes of the challenge
        """

        try:
            data = self._conn.recvline(timeout=5)
            logger.debug(f"Received line: {data}")
            return data
        except EOFError:
            logger.warning("Server closed connection (EOFError on receive)")
            return b""

    def send_response(self, response: str) -> None:
        """
        Send the decoded response back to the server.

        Args:
            response: The decoded plaintext to send
        """

        logger.debug(f"Sending response: {response}")
        self._conn.sendline(response.encode("utf-8"))

    def run(self) -> bool:
        """
        Main challenge loop: receive every line → decode if base64 → respond.

        Every line received from the server is classified:
        - Looks like a flag → save and return True
        - Looks like base64 → decode and send answer
        - Anything else → log it and wait for the next line

        Returns:
            True if the flag was found, False otherwise
        """

        try:
            round_count = 0

            while True:
                try:
                    raw = self._conn.recvline(timeout=10)
                except EOFError:
                    try:
                        remaining = self._conn.recvall(timeout=3)
                        if remaining:
                            remaining_str = remaining.decode("utf-8", errors="ignore").strip()
                            logger.info(f"[SERVER] {remaining_str}")
                            if self._looks_like_flag(remaining_str):
                                self.flag = remaining_str
                                return True
                    except Exception:
                        pass
                    logger.warning("Connection closed by server")
                    break

                if not raw or raw == b"\n" or raw == b"\r\n":
                    continue

                line = raw.decode("utf-8", errors="ignore").strip()
                logger.info(f"[SERVER] {line}")

                if self._looks_like_flag(line):
                    self.flag = line
                    logger.info(f"Flag obtained: {self.flag}")
                    return True

                if Decoder._is_base64(raw.strip()):
                    round_count += 1
                    logger.info(f"--- Round {round_count} — decoding challenge ---")

                    decoder = Decoder(raw)
                    answer = decoder.decode()
                    logger.info(f"Answer: {answer}")

                    self.send_response(answer)
                else:
                    logger.info(f"(non-base64 line, waiting for next...)")

        except Exception as e:
            logger.error(f"Session error: {e}")
            return False

        return False

    def get_flag(self) -> str:
        """
        Return the captured flag.

        Returns:
            The flag string
        """

        return self.flag


    @staticmethod
    def _looks_like_flag(text: str) -> bool:
        """
        Heuristic check whether a string looks like a CTF flag.

        Args:
            text: String to check

        Returns:
            True if the string matches common flag patterns
        """

        text_lower = text.lower()
        flag_patterns = [
            "flag{",
            "esgi{",
            "ctf{",
            "flag :",
            "bravo",
            "congrat",
            "well done",
            "you win",
            "flag:",
        ]
        return any(pattern in text_lower for pattern in flag_patterns)