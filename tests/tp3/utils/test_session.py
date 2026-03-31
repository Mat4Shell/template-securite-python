import re
from io import BytesIO
from unittest.mock import MagicMock, patch, call

import pytest
import requests
from PIL import Image

from src.tp3.utils.captcha import (
    Captcha,
    CaptchaEmpty,
    CaptchaLeak,
    CaptchaOCR,
)
from src.tp3.utils.session import Session


def _make_png(color=(22, 86, 165)) -> bytes:
    """
    Crée un PNG minimal en mémoire pour les tests.
    """
    buf = BytesIO()
    Image.new("RGB", (75, 24), color=color).save(buf, format="PNG")
    buf.seek(0)
    return buf.read()


def _mock_response(text: str, status_code: int = 200) -> MagicMock:
    r = MagicMock(spec=requests.Response)
    r.text = text
    r.status_code = status_code
    r.content = b""
    r.raise_for_status = MagicMock()
    return r

class TestCaptchaBase:
    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            Captcha("http://example.com/captcha1/")

    def test_base_url_derived_correctly(self):
        cap = CaptchaOCR("http://31.220.95.27:9002/captcha1/")
        assert cap._base_url == "http://31.220.95.27:9002"

    def test_captcha_url_derived_correctly(self):
        cap = CaptchaOCR("http://31.220.95.27:9002/captcha1/")
        assert cap._captcha_url == "http://31.220.95.27:9002/captcha.php"

class TestCaptchaOCR:
    def test_init(self):
        cap = CaptchaOCR("http://example.com/captcha1/")
        assert cap.url == "http://example.com/captcha1/"
        assert cap.value == ""
        assert cap._image is None

    def test_capture_downloads_image(self):
        cap = CaptchaOCR("http://example.com/captcha1/")
        mock_resp = _mock_response("")
        mock_resp.content = _make_png()
        with patch.object(cap._session, "get", return_value=mock_resp):
            cap.capture()
        assert isinstance(cap._image, Image.Image)

    def test_solve_raises_without_capture(self):
        cap = CaptchaOCR("http://example.com/captcha1/")
        with pytest.raises(RuntimeError, match="capture\\(\\) doit être appelé"):
            cap.solve()

    def test_solve_sets_value_when_ocr_returns_6_digits(self):
        cap = CaptchaOCR("http://example.com/captcha1/")
        cap._image = Image.new("RGB", (75, 24))
        with patch("src.tp3.utils.captcha.pytesseract.image_to_string", return_value="123456\n"):
            cap.solve()
        assert cap.value == "123456"

    def test_solve_retries_when_ocr_wrong_length(self):
        cap = CaptchaOCR("http://example.com/captcha1/")
        cap._image = Image.new("RGB", (75, 24))
        mock_resp = _mock_response("")
        mock_resp.content = _make_png()

        ocr_results = iter(["12345", "1234567", "654321"])

        with (
            patch.object(cap._session, "get", return_value=mock_resp),
            patch(
                "src.tp3.utils.captcha.pytesseract.image_to_string",
                side_effect=lambda *a, **kw: next(ocr_results) + "\n",
            ),
        ):
            cap.solve()

        assert cap.value == "654321"

    def test_solve_raises_after_max_retries(self):
        cap = CaptchaOCR("http://example.com/captcha1/")
        cap._image = Image.new("RGB", (75, 24))
        mock_resp = _mock_response("")
        mock_resp.content = _make_png()

        with (
            patch.object(cap._session, "get", return_value=mock_resp),
            patch(
                "src.tp3.utils.captcha.pytesseract.image_to_string",
                return_value="12345\n",
            ),
            pytest.raises(RuntimeError, match="Impossible de lire"),
        ):
            cap.solve()

    def test_get_value(self):
        cap = CaptchaOCR("http://example.com/captcha1/")
        cap.value = "987654"
        assert cap.get_value() == "987654"

class TestCaptchaLeak:
    def test_init(self):
        cap = CaptchaLeak("http://example.com/captcha2/")
        assert cap.value == ""
        assert cap._leak_response == ""

    def test_capture_posts_empty_captcha(self):
        cap = CaptchaLeak("http://example.com/captcha2/")
        mock_resp = _mock_response("...3a9f12</div>...")
        with patch.object(cap._session, "post", return_value=mock_resp) as mock_post:
            cap.capture()
        mock_post.assert_called_once_with(
            "http://example.com/captcha2/",
            data={"flag": "", "captcha": "", "submit": "Submit"},
        )
        assert cap._leak_response == "...3a9f12</div>..."

    def test_solve_extracts_hex_value(self):
        cap = CaptchaLeak("http://example.com/captcha2/")
        cap._leak_response = '<div>\n  6a258d</div>\n'
        cap.solve()
        assert cap.value == "6a258d"

    def test_solve_raises_when_no_hex_found(self):
        cap = CaptchaLeak("http://example.com/captcha2/")
        cap._leak_response = "<div>nothing here</div>"
        with pytest.raises(RuntimeError, match="Impossible d'extraire"):
            cap.solve()

class TestCaptchaEmpty:
    def test_capture_does_nothing(self):
        cap = CaptchaEmpty("http://example.com/captcha4/")
        cap.capture()  # Ne doit pas lever d'exception

    def test_solve_sets_empty_value(self):
        cap = CaptchaEmpty("http://example.com/captcha4/")
        cap.solve()
        assert cap.value == ""

    def test_get_value_returns_empty(self):
        cap = CaptchaEmpty("http://example.com/captcha4/")
        cap.solve()
        assert cap.get_value() == ""

class TestSessionInit:
    def test_init_defaults(self):
        with patch("src.tp3.utils.session.requests.Session") as MockSession:
            MockSession.return_value.get = MagicMock()
            session = Session("http://example.com/captcha1/", CaptchaOCR, 1000, 2000)

        assert session.url == "http://example.com/captcha1/"
        assert session._flag_min == 1000
        assert session._flag_max == 2000
        assert session._current_flag == 1000
        assert session.valid_flag == ""

    def test_extra_headers_applied_to_http_session(self):
        with patch("src.tp3.utils.session.requests.Session") as MockSession:
            mock_http = MagicMock()
            MockSession.return_value = mock_http
            Session(
                "http://example.com/captcha4/",
                CaptchaEmpty,
                7000,
                8000,
                extra_headers={"Magic-Word": "magic"},
            )
        mock_http.headers.update.assert_called_once_with({"Magic-Word": "magic"})

    def test_no_extra_headers_by_default(self):
        with patch("src.tp3.utils.session.requests.Session") as MockSession:
            mock_http = MagicMock()
            MockSession.return_value = mock_http
            Session("http://example.com/captcha1/", CaptchaOCR, 1000, 2000)
        mock_http.headers.update.assert_not_called()

    def test_initial_get_called(self):
        with patch("src.tp3.utils.session.requests.Session") as MockSession:
            mock_http = MagicMock()
            MockSession.return_value = mock_http
            Session("http://example.com/captcha1/", CaptchaOCR, 1000, 2000)
        mock_http.get.assert_called_once_with("http://example.com/captcha1/")

class TestSessionPrepareRequest:
    def _make_session(self, captcha_class=CaptchaOCR, flag_min=1000, flag_max=2000, **kwargs):
        with patch("src.tp3.utils.session.requests.Session") as MockSession:
            mock_http = MagicMock()
            mock_http.get = MagicMock()
            mock_http.headers = MagicMock()
            MockSession.return_value = mock_http
            session = Session(
                "http://example.com/captcha1/",
                captcha_class,
                flag_min,
                flag_max,
                **kwargs,
            )
        return session

    def test_prepare_increments_flag(self):
        session = self._make_session()
        mock_captcha = MagicMock()
        mock_captcha.get_value.return_value = "123456"
        with patch("src.tp3.utils.captcha.CaptchaOCR", return_value=mock_captcha):
            with patch.object(session, "_captcha_class", return_value=mock_captcha):
                session.prepare_request()
                session.prepare_request()
        assert session.flag_value == "1001"
        assert session._current_flag == 1002

    def test_prepare_raises_when_exhausted(self):
        session = self._make_session(flag_min=2001, flag_max=2000)
        with pytest.raises(RuntimeError, match="Brute-force exhausté"):
            session.prepare_request()

    def test_prepare_uses_reveal_class_after_revelation(self):
        session = self._make_session(
            captcha_class=CaptchaEmpty,
            reveal_captcha_class=CaptchaOCR,
        )
        session._captcha_revealed = True

        mock_captcha = MagicMock()
        mock_captcha.get_value.return_value = "654321"
        with patch.object(session, "_reveal_captcha_class", return_value=mock_captcha):
            session.prepare_request()
        assert session.captcha_value == "654321"


class TestSessionSubmitRequest:
    def _make_session(self):
        with patch("src.tp3.utils.session.requests.Session") as MockSession:
            MockSession.return_value.get = MagicMock()
            MockSession.return_value.headers = MagicMock()
            session = Session("http://example.com/captcha1/", CaptchaOCR, 1000, 2000)
        return session

    def test_submit_includes_captcha_when_not_empty(self):
        session = self._make_session()
        session.flag_value = "1500"
        session.captcha_value = "123456"
        mock_resp = _mock_response("")
        session._http_session.post = MagicMock(return_value=mock_resp)

        session.submit_request()

        session._http_session.post.assert_called_once_with(
            "http://example.com/captcha1/",
            data={"flag": "1500", "captcha": "123456", "submit": "Submit"},
        )

    def test_submit_omits_captcha_when_empty(self):
        session = self._make_session()
        session.flag_value = "7000"
        session.captcha_value = ""  # CaptchaEmpty
        mock_resp = _mock_response("")
        session._http_session.post = MagicMock(return_value=mock_resp)

        session.submit_request()

        session._http_session.post.assert_called_once_with(
            "http://example.com/captcha1/",
            data={"flag": "7000", "submit": "Submit"},
        )

class TestSessionProcessResponse:
    def _session_with_response(self, response_text: str, **kwargs) -> Session:
        with patch("src.tp3.utils.session.requests.Session") as MockSession:
            MockSession.return_value.get = MagicMock()
            MockSession.return_value.headers = MagicMock()
            session = Session(
                "http://example.com/captcha1/",
                CaptchaOCR,
                1000,
                2000,
                **kwargs,
            )
        session._last_response = _mock_response(response_text)
        session._current_flag = 1005
        session.flag_value = "1004"
        session.captcha_value = "123456"
        return session

    def test_returns_false_when_no_response(self):
        with patch("src.tp3.utils.session.requests.Session") as MockSession:
            MockSession.return_value.get = MagicMock()
            MockSession.return_value.headers = MagicMock()
            session = Session("http://x.com/", CaptchaOCR, 1000, 2000)
        assert session.process_response() is False

    def test_returns_false_on_incorrect_flag(self):
        session = self._session_with_response(
            '<p class="alert-danger col-md-2">Incorrect flag.</p>'
        )
        assert session.process_response() is False

    def test_returns_false_and_decrements_on_invalid_captcha(self):
        session = self._session_with_response(
            '<p class="alert-danger col-md-2">Invalid captcha</p>'
        )
        result = session.process_response()
        assert result is False
        assert session._current_flag == 1004

    def test_returns_false_and_decrements_on_where_is_captcha(self):
        session = self._session_with_response(
            '<p class="alert-danger">where is the captcha?!</p>'
        )
        result = session.process_response()
        assert result is False
        assert session._current_flag == 1004

    def test_returns_true_on_alert_success(self):
        session = self._session_with_response(
            '<p class="alert-success">Bravo !</p>'
        )
        assert session.process_response() is True
        assert session.valid_flag == "1004"

    def test_returns_true_on_ok_comment(self):
        session = self._session_with_response("...form...</div>\n<!-- Ok --></div>")
        assert session.process_response() is True
        assert session.valid_flag == "1004"

    def test_captcha_revealed_triggers_state_change(self):
        """
        Challenge 4 : quand captcha.php apparaît, on bascule en mode OCR.
        """
        session = self._session_with_response(
            '<img src="../captcha.php"/><p class="alert-danger">Incorrect flag.</p>',
            reveal_captcha_class=CaptchaOCR,
        )
        session._captcha_revealed = False

        result = session.process_response()

        assert result is False
        assert session._captcha_revealed is True
        assert session._current_flag == 1004

    def test_captcha_reveal_ignored_when_already_revealed(self):
        """Une fois révélé, le captcha.php dans la réponse ne redéclenche pas la transition."""
        session = self._session_with_response(
            '<img src="../captcha.php"/><p class="alert-danger">Incorrect flag.</p>',
            reveal_captcha_class=CaptchaOCR,
        )
        session._captcha_revealed = True

        result = session.process_response()

        assert result is False
        assert session._current_flag == 1005

    def test_get_flag(self):
        with patch("src.tp3.utils.session.requests.Session") as MockSession:
            MockSession.return_value.get = MagicMock()
            MockSession.return_value.headers = MagicMock()
            session = Session("http://x.com/", CaptchaOCR, 1000, 2000)
        session.valid_flag = "1337"
        assert session.get_flag() == "1337"