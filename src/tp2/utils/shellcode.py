import os
import re

from src.tp2.utils.config import logger


class ShellcodeAnalyzer:
    """
    Analyseur de shellcode combinant plusieurs techniques :
    - Extraction de chaînes (strings)
    - Émulation via pylibemu
    - Désassemblage via capstone
    - Analyse sémantique via LLM
    """

    MIN_STRING_LENGTH = 4

    def __init__(self, shellcode: bytes) -> None:
        self.shellcode = shellcode
        self._strings: list[str] = []
        self._pylibemu_output: str = ""
        self._capstone_output: str = ""
        self._llm_output: str = ""

    def get_shellcode_strings(self) -> list[str]:
        """
        Retourne les chaînes de caractères lisibles présentes dans le shellcode.
        Equivalent à la commande `strings` sur le binaire.

        Returns:
            Liste des chaînes ASCII/UTF-16 trouvées (longueur >= MIN_STRING_LENGTH)
        """

        results: list[str] = []

        ascii_pattern = re.compile(
            rb"[\x20-\x7e]{" + str(self.MIN_STRING_LENGTH).encode() + rb",}"
        )
        for match in ascii_pattern.finditer(self.shellcode):
            results.append(match.group().decode("ascii"))

        utf16_pattern = re.compile(
            rb"(?:[\x20-\x7e]\x00){" + str(self.MIN_STRING_LENGTH).encode() + rb",}"
        )
        for match in utf16_pattern.finditer(self.shellcode):
            try:
                decoded = match.group().decode("utf-16-le").strip("\x00")
                if decoded and decoded not in results:
                    results.append(decoded)
            except UnicodeDecodeError:
                continue

        self._strings = results
        logger.debug(f"Strings trouvées : {results}")
        return results

    def get_pylibemu_analysis(self) -> str:
        """
        Retourne l'analyse comportementale du shellcode via pylibemu.
        Émule l'exécution du shellcode et intercepte les appels API Windows.

        Returns:
            Sortie de l'émulateur (appels API, comportements détectés)
            ou message d'erreur si pylibemu n'est pas disponible.
        """

        try:
            import pylibemu

            emulator = pylibemu.Emulator(output_size=10_000)

            offset = emulator.shellcode_getpc_test(self.shellcode)
            logger.debug(f"Offset GetPC détecté : {offset}")

            emulator.prepare(self.shellcode, offset)
            emulator.test()

            output: str = emulator.emu_profile_output or ""
            self._pylibemu_output = output

            logger.info(f"Shellcode analysed !\n{output}")
            return output

        except ImportError:
            msg = (
                "[!] pylibemu non disponible. "
                "Installez libemu + pylibemu (voir cours p.68) dans un environnement isolé."
            )
            logger.warning(msg)
            self._pylibemu_output = msg
            return msg

        except Exception as exc:
            msg = f"[!] Erreur pylibemu : {exc}"
            logger.error(msg)
            self._pylibemu_output = msg
            return msg

    def get_capstone_analysis(self) -> str:
        """
        Retourne le désassemblage du shellcode via Capstone.
        Tente x86 32 bits puis x86 64 bits si le résultat est trop pauvre.

        Returns:
            Instructions désassemblées au format : adresse\\tmnemonic\\top_str
        """

        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

            lines: list[str] = []

            md32 = Cs(CS_ARCH_X86, CS_MODE_32)
            instructions_32 = list(md32.disasm(self.shellcode, 0x0))

            md64 = Cs(CS_ARCH_X86, CS_MODE_64)
            instructions_64 = list(md64.disasm(self.shellcode, 0x0))

            instructions = (
                instructions_32
                if len(instructions_32) >= len(instructions_64)
                else instructions_64
            )

            mode_label = "x86-32" if instructions is instructions_32 else "x86-64"
            lines.append(f"; Désassemblage Capstone ({mode_label})")
            lines.append(f"; Taille du shellcode : {len(self.shellcode)} octets")
            lines.append("")

            for instr in instructions:
                bytes_hex = " ".join(f"{b:02x}" for b in instr.bytes)
                lines.append(
                    f"0x{instr.address:04x}:  {bytes_hex:<30s}  {instr.mnemonic}  {instr.op_str}"
                )

            self._capstone_output = "\n".join(lines)
            return self._capstone_output

        except ImportError:
            msg = "[!] capstone non disponible. Exécutez : poetry add capstone"
            logger.warning(msg)
            self._capstone_output = msg
            return msg

        except Exception as exc:
            msg = f"[!] Erreur capstone : {exc}"
            logger.error(msg)
            self._capstone_output = msg
            return msg

    def get_llm_analysis(self) -> str:
        """
        Retourne l'analyse sémantique du shellcode générée par un LLM (Claude).
        Agrège les résultats des autres analyses pour construire le prompt.

        La clé API doit être définie dans la variable d'environnement ANTHROPIC_API_KEY.

        Returns:
            Explication en langage naturel de ce que fait le shellcode.
        """

        import requests

        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            msg = (
                "[!] Variable ANTHROPIC_API_KEY non définie. "
                "Exportez votre clé : export ANTHROPIC_API_KEY=sk-ant-..."
            )
            logger.warning(msg)
            self._llm_output = msg
            return msg

        prompt = self._build_llm_prompt()

        try:
            response = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5-20251001",
                    "max_tokens": 1024,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=90,
            )
            response.raise_for_status()

            data = response.json()
            explanation: str = data["content"][0]["text"]
            self._llm_output = explanation
            logger.info(f"Explication LLM : {explanation}")
            return explanation

        except requests.exceptions.HTTPError as exc:
            detail = exc.response.text if exc.response is not None else "pas de détail disponible"
            msg = f"[!] Erreur HTTP Anthropic API : {exc}\nDétail : {detail}"
            logger.error(msg)
            self._llm_output = msg
            return msg

        except Exception as exc:
            msg = f"[!] Erreur LLM : {exc}"
            logger.error(msg)
            self._llm_output = msg
            return msg

    def _build_llm_prompt(self) -> str:
        """
        Construit le prompt envoyé au LLM en agrégeant toutes les analyses.
        """

        hex_repr = self.shellcode.hex()
        size = len(self.shellcode)

        sections: list[str] = [
            f"Tu es un expert en sécurité offensive et analyse de shellcodes.",
            f"Analyse le shellcode suivant ({size} octets) et explique précisément ce qu'il fait.",
            f"Identifie : l'OS ciblé, le type de shellcode, les appels système/API utilisés,",
            f"les adresses IP/ports présents, et le comportement général.",
            f"",
            f"## Shellcode (hex, extrait)",
            hex_repr[:200] + "...",
        ]

        if self._strings:
            sections += [
                "",
                "## Chaînes extraites",
                "\n".join(f"  - {s}" for s in self._strings),
            ]

        if self._pylibemu_output and not self._pylibemu_output.startswith("[!]"):
            sections += [
                "",
                "## Analyse pylibemu (émulation)",
                self._pylibemu_output[:3000],
            ]

        if self._capstone_output and not self._capstone_output.startswith("[!]"):
            capstone_short = "\n".join(self._capstone_output.splitlines()[:50])
            sections += [
                "",
                "## Désassemblage capstone (extrait)",
                capstone_short,
            ]

        sections += [
            "",
            "Fournis une explication détaillée en français.",
        ]

        return "\n".join(sections)

    def analyse_all(self) -> dict[str, object]:
        """
        Lance les 4 analyses dans l'ordre et retourne un dictionnaire de résultats.

        Returns:
            Dictionnaire avec les clés : strings, pylibemu, capstone, llm
        """

        logger.info(f"Testing shellcode of size {len(self.shellcode)}B")

        strings = self.get_shellcode_strings()
        pylibemu = self.get_pylibemu_analysis()
        capstone = self.get_capstone_analysis()
        llm = self.get_llm_analysis()

        return {
            "strings": strings,
            "pylibemu": pylibemu,
            "capstone": capstone,
            "llm": llm,
        }

    @staticmethod
    def from_file(path: str) -> "ShellcodeAnalyzer":
        """
        Charge un shellcode depuis un fichier.

        Le fichier peut contenir :
        - Des bytes bruts (binaire)
        - Du texte au format \\xNN\\xNN... (une ligne)
        - Du hex pur sans préfixe (ex: fc e8 8f 00...)

        Args:
            path: Chemin vers le fichier shellcode

        Returns:
            Instance de ShellcodeAnalyzer prête à l'emploi
        """

        with open(path, "rb") as f:
            raw = f.read()

        shellcode = ShellcodeAnalyzer._parse_shellcode(raw)
        logger.debug(f"Shellcode chargé : {len(shellcode)} octets depuis '{path}'")
        return ShellcodeAnalyzer(shellcode)

    @staticmethod
    def _parse_shellcode(raw: bytes) -> bytes:
        """
        Détecte et convertit le format du shellcode.
        """

        text = raw.decode("ascii", errors="ignore").strip()
        if "\\x" in text:
            hex_values = re.findall(r"\\x([0-9a-fA-F]{2})", text)
            if hex_values:
                return bytes(int(h, 16) for h in hex_values)

        clean = text.replace(" ", "").replace("\n", "").replace("\r", "")
        if re.fullmatch(r"[0-9a-fA-F]+", clean) and len(clean) % 2 == 0:
            return bytes.fromhex(clean)

        return raw