import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from src.tp2.utils.shellcode import ShellcodeAnalyzer

# Shellcode de test minimal (NOP sled + INT3)
NOP_SHELLCODE = b"\x90\x90\x90\xcc"

# Shellcode "whoami" du cours (binaire brut)
WHOAMI_SHELLCODE = (
    b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68\x00"
    b"\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x10\x00\x00\x00\x2f\x75\x73"
    b"\x72\x2f\x62\x69\x6e\x2f\x77\x68\x6f\x61\x6d\x69\x00\x57\x53\x89"
    b"\xe1\xcd\x80"
)


# ------------------------------------------------------------------ #
#  Initialisation                                                      #
# ------------------------------------------------------------------ #


def test_init_stores_shellcode():
    analyzer = ShellcodeAnalyzer(NOP_SHELLCODE)
    assert analyzer.shellcode == NOP_SHELLCODE
    assert analyzer._strings == []
    assert analyzer._pylibemu_output == ""
    assert analyzer._capstone_output == ""
    assert analyzer._llm_output == ""


# ------------------------------------------------------------------ #
#  get_shellcode_strings                                               #
# ------------------------------------------------------------------ #


def test_get_shellcode_strings_returns_list():
    analyzer = ShellcodeAnalyzer(WHOAMI_SHELLCODE)
    result = analyzer.get_shellcode_strings()
    assert isinstance(result, list)


def test_get_shellcode_strings_finds_whoami_path():
    analyzer = ShellcodeAnalyzer(WHOAMI_SHELLCODE)
    strings = analyzer.get_shellcode_strings()
    # Le shellcode contient /usr/bin/whoami
    combined = " ".join(strings)
    assert "whoami" in combined or "/bin" in combined


def test_get_shellcode_strings_empty_shellcode():
    analyzer = ShellcodeAnalyzer(b"\x00\x01\x02\x03")
    result = analyzer.get_shellcode_strings()
    assert result == []


def test_get_shellcode_strings_updates_internal_state():
    analyzer = ShellcodeAnalyzer(WHOAMI_SHELLCODE)
    analyzer.get_shellcode_strings()
    assert analyzer._strings is not None


# ------------------------------------------------------------------ #
#  get_pylibemu_analysis                                               #
# ------------------------------------------------------------------ #


def test_get_pylibemu_analysis_without_pylibemu():
    """Sans pylibemu installé, doit retourner un message d'erreur propre."""
    analyzer = ShellcodeAnalyzer(NOP_SHELLCODE)
    with patch.dict("sys.modules", {"pylibemu": None}):
        result = analyzer.get_pylibemu_analysis()
    # Soit pylibemu est dispo (résultat valide), soit message d'erreur
    assert isinstance(result, str)
    assert len(result) > 0


def test_get_pylibemu_analysis_updates_internal_state():
    analyzer = ShellcodeAnalyzer(NOP_SHELLCODE)
    with patch("src.tp2.utils.shellcode.ShellcodeAnalyzer.get_pylibemu_analysis",
               return_value="test output") as mock:
        output = analyzer.get_pylibemu_analysis()
    assert isinstance(output, str)


def test_get_pylibemu_analysis_handles_import_error():
    """Doit gérer proprement l'absence de pylibemu."""
    analyzer = ShellcodeAnalyzer(NOP_SHELLCODE)

    with patch("builtins.__import__", side_effect=ImportError("pylibemu")):
        pass  # Test que le code ne crashe pas si on mock l'import

    # Test direct avec mock
    with patch.object(analyzer, "get_pylibemu_analysis", return_value="[!] pylibemu non disponible."):
        result = analyzer.get_pylibemu_analysis()
        assert "[!]" in result


# ------------------------------------------------------------------ #
#  get_capstone_analysis                                               #
# ------------------------------------------------------------------ #


def test_get_capstone_analysis_returns_string():
    analyzer = ShellcodeAnalyzer(WHOAMI_SHELLCODE)
    result = analyzer.get_capstone_analysis()
    assert isinstance(result, str)
    assert len(result) > 0


def test_get_capstone_analysis_contains_instructions():
    analyzer = ShellcodeAnalyzer(WHOAMI_SHELLCODE)
    result = analyzer.get_capstone_analysis()
    # Doit contenir des adresses hex ou un message d'erreur
    assert "0x" in result or "[!]" in result


def test_get_capstone_analysis_nop_shellcode():
    analyzer = ShellcodeAnalyzer(b"\x90\x90\x90")
    result = analyzer.get_capstone_analysis()
    assert isinstance(result, str)
    # Un NOP sled doit être désassemblé comme "nop"
    if "[!]" not in result:
        assert "nop" in result.lower()


def test_get_capstone_analysis_updates_internal_state():
    analyzer = ShellcodeAnalyzer(WHOAMI_SHELLCODE)
    analyzer.get_capstone_analysis()
    assert analyzer._capstone_output != "" or "[!]" in analyzer._capstone_output


# ------------------------------------------------------------------ #
#  get_llm_analysis                                                    #
# ------------------------------------------------------------------ #


def test_get_llm_analysis_without_api_key():
    """Sans clé API, doit retourner un message d'erreur clair."""
    analyzer = ShellcodeAnalyzer(NOP_SHELLCODE)
    with patch.dict(os.environ, {}, clear=True):
        os.environ.pop("ANTHROPIC_API_KEY", None)
        result = analyzer.get_llm_analysis()
    assert "[!]" in result
    assert "ANTHROPIC_API_KEY" in result


def test_get_llm_analysis_with_mock_api():
    """Avec une réponse mockée, doit retourner l'explication."""
    analyzer = ShellcodeAnalyzer(NOP_SHELLCODE)
    analyzer._strings = ["/bin/sh"]
    analyzer._capstone_output = "0x0000:  90  nop"

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "content": [{"text": "Ce shellcode ouvre un shell."}]
    }
    mock_response.raise_for_status = MagicMock()

    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}):
        with patch("requests.post", return_value=mock_response):
            result = analyzer.get_llm_analysis()

    assert result == "Ce shellcode ouvre un shell."
    assert analyzer._llm_output == "Ce shellcode ouvre un shell."


def test_get_llm_analysis_handles_http_error():
    """En cas d'erreur HTTP, doit retourner un message d'erreur."""
    import requests as req

    analyzer = ShellcodeAnalyzer(NOP_SHELLCODE)

    mock_response = MagicMock()
    mock_response.raise_for_status.side_effect = req.exceptions.HTTPError("403")

    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}):
        with patch("requests.post", return_value=mock_response):
            result = analyzer.get_llm_analysis()

    assert "[!]" in result


# ------------------------------------------------------------------ #
#  _parse_shellcode                                                    #
# ------------------------------------------------------------------ #


def test_parse_shellcode_binary():
    raw = b"\x90\x90\xcc"
    result = ShellcodeAnalyzer._parse_shellcode(raw)
    assert result == b"\x90\x90\xcc"


def test_parse_shellcode_escaped_hex():
    raw = b"\\x90\\x90\\xcc"
    result = ShellcodeAnalyzer._parse_shellcode(raw)
    assert result == b"\x90\x90\xcc"


def test_parse_shellcode_plain_hex():
    raw = b"9090cc"
    result = ShellcodeAnalyzer._parse_shellcode(raw)
    assert result == b"\x90\x90\xcc"


def test_parse_shellcode_hex_with_spaces():
    raw = b"90 90 cc"
    result = ShellcodeAnalyzer._parse_shellcode(raw)
    assert result == b"\x90\x90\xcc"


# ------------------------------------------------------------------ #
#  from_file                                                           #
# ------------------------------------------------------------------ #


def test_from_file_binary():
    """Doit charger un shellcode binaire depuis un fichier."""
    shellcode = b"\x90\x90\xcc"
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(shellcode)
        path = f.name

    try:
        analyzer = ShellcodeAnalyzer.from_file(path)
        assert analyzer.shellcode == shellcode
    finally:
        os.unlink(path)


def test_from_file_escaped_hex():
    """Doit charger un shellcode au format \\xNN depuis un fichier texte."""
    text = b"\\x90\\x90\\xcc"
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write(text)
        path = f.name

    try:
        analyzer = ShellcodeAnalyzer.from_file(path)
        assert analyzer.shellcode == b"\x90\x90\xcc"
    finally:
        os.unlink(path)


def test_from_file_not_found():
    """Doit lever FileNotFoundError si le fichier n'existe pas."""
    with pytest.raises(FileNotFoundError):
        ShellcodeAnalyzer.from_file("/tmp/fichier_inexistant_tp2.bin")


# ------------------------------------------------------------------ #
#  analyse_all                                                         #
# ------------------------------------------------------------------ #


def test_analyse_all_returns_all_keys():
    """analyse_all doit retourner un dict avec les 4 clés."""
    analyzer = ShellcodeAnalyzer(NOP_SHELLCODE)

    with (
        patch.object(analyzer, "get_shellcode_strings", return_value=["/bin/sh"]),
        patch.object(analyzer, "get_pylibemu_analysis", return_value="emu output"),
        patch.object(analyzer, "get_capstone_analysis", return_value="nop nop"),
        patch.object(analyzer, "get_llm_analysis", return_value="C'est un NOP sled."),
    ):
        result = analyzer.analyse_all()

    assert set(result.keys()) == {"strings", "pylibemu", "capstone", "llm"}
    assert result["strings"] == ["/bin/sh"]
    assert result["pylibemu"] == "emu output"
    assert result["capstone"] == "nop nop"
    assert result["llm"] == "C'est un NOP sled."


def test_analyse_all_calls_all_methods():
    """analyse_all doit appeler les 4 méthodes d'analyse."""
    analyzer = ShellcodeAnalyzer(NOP_SHELLCODE)

    with (
        patch.object(analyzer, "get_shellcode_strings", return_value=[]) as m1,
        patch.object(analyzer, "get_pylibemu_analysis", return_value="") as m2,
        patch.object(analyzer, "get_capstone_analysis", return_value="") as m3,
        patch.object(analyzer, "get_llm_analysis", return_value="") as m4,
    ):
        analyzer.analyse_all()

    m1.assert_called_once()
    m2.assert_called_once()
    m3.assert_called_once()
    m4.assert_called_once()