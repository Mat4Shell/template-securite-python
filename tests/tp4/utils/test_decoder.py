import base64

from src.tp4.utils.decoder import Decoder


def test_decoder_init():
    raw = b"SGVsbG8gV29ybGQ="

    decoder = Decoder(raw)

    assert decoder.raw == raw
    assert decoder.decoded == ""


def test_decode_single_base64_layer():
    encoded = base64.b64encode(b"hello").strip()
    decoder = Decoder(encoded)

    result = decoder.decode()

    assert result == "hello"


def test_decode_double_base64_layer():
    inner = base64.b64encode(b"secret")
    outer = base64.b64encode(inner)
    decoder = Decoder(outer)

    result = decoder.decode()

    assert result == "secret"


def test_decode_triple_base64_layer():
    layer1 = base64.b64encode(b"deep_value")
    layer2 = base64.b64encode(layer1)
    layer3 = base64.b64encode(layer2)
    decoder = Decoder(layer3)

    result = decoder.decode()

    assert result == "deep_value"


def test_decode_plain_text_not_base64():
    raw = b"not encoded at all !"
    decoder = Decoder(raw)

    result = decoder.decode()

    assert result == "not encoded at all !"


def test_get_decoded_before_decode():
    decoder = Decoder(b"test")

    assert decoder.get_decoded() == ""


def test_get_decoded_after_decode():
    encoded = base64.b64encode(b"42")
    decoder = Decoder(encoded)
    decoder.decode()

    result = decoder.get_decoded()

    assert result == "42"


def test_is_base64_valid():
    valid = base64.b64encode(b"test data")

    result = Decoder._is_base64(valid)

    assert result is True


def test_is_base64_invalid():
    invalid = b"This is not base64!!!"

    result = Decoder._is_base64(invalid)

    assert result is False


def test_is_base64_empty():
    assert Decoder._is_base64(b"") is True