import base64
from unittest.mock import MagicMock, patch

from src.tp4.utils.session import Session


def test_session_init():
    host = "31.220.95.27"
    port = 9002

    session = Session(host, port)

    assert session.host == host
    assert session.port == port
    assert session.flag == ""
    assert session._conn is None


def test_get_flag_empty():
    session = Session("127.0.0.1", 9003)

    result = session.get_flag()

    assert result == ""


def test_get_flag_after_set():
    session = Session("127.0.0.1", 9003)
    session.flag = "FLAG{test_flag}"

    result = session.get_flag()

    assert result == "FLAG{test_flag}"


def test_close_without_connection():

    session = Session("127.0.0.1", 9003)

    session.close()


def test_close_with_mock_connection():
    session = Session("127.0.0.1", 9003)
    mock_conn = MagicMock()
    session._conn = mock_conn

    session.close()

    mock_conn.close.assert_called_once()


def test_send_response():
    session = Session("127.0.0.1", 9003)
    mock_conn = MagicMock()
    session._conn = mock_conn

    session.send_response("42")

    mock_conn.sendline.assert_called_once_with(b"42")


def test_receive_challenge():
    session = Session("127.0.0.1", 9003)
    mock_conn = MagicMock()
    encoded = base64.b64encode(b"hello") + b"\n"
    mock_conn.recvline.return_value = encoded
    session._conn = mock_conn

    result = session.receive_challenge()

    assert result == encoded


def test_looks_like_flag_with_flag_prefix():
    assert Session._looks_like_flag("flag{super_secret_123}") is True
    assert Session._looks_like_flag("FLAG{UPPERCASE}") is True
    assert Session._looks_like_flag("esgi{the_answer}") is True
    assert Session._looks_like_flag("ctf{challenge}") is True


def test_looks_like_flag_with_congrats():
    assert Session._looks_like_flag("Congratulations! You won!") is True
    assert Session._looks_like_flag("Bravo, you got it!") is True
    assert Session._looks_like_flag("Well done!") is True


def test_looks_like_flag_with_normal_data():
    assert Session._looks_like_flag("SGVsbG8gV29ybGQ=") is False
    assert Session._looks_like_flag("42") is False
    assert Session._looks_like_flag("hello world") is False


def test_connect():
    session = Session("127.0.0.1", 9003)

    with patch("src.tp4.utils.session.remote") as mock_remote:
        mock_conn = MagicMock()
        mock_remote.return_value = mock_conn
        session.connect()

    mock_remote.assert_called_once_with("127.0.0.1", 9003)
    assert session._conn == mock_conn