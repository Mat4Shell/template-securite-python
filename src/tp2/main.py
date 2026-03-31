import argparse
import sys
import io

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from src.tp2.utils.config import logger
from src.tp2.utils.shellcode import ShellcodeAnalyzer


def _print_section(title: str, content: str) -> None:
    """
    Affiche une section formatée dans la console.
    """

    logger.info("=" * 70)
    logger.info(title)
    logger.info("=" * 70)
    for line in content.splitlines():
        logger.info(line)
    logger.info("")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TP2 - Analyse de shellcode (strings / pylibemu / capstone / LLM)"
    )
    parser.add_argument(
        "-f",
        "--file",
        required=True,
        metavar="SHELLCODE_FILE",
        help="Chemin vers le fichier contenant le shellcode (binaire ou \\xNN...)",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        default=False,
        help="Désactive l'analyse LLM (utile si pas de clé API)",
    )

    args = parser.parse_args()

    try:
        analyzer = ShellcodeAnalyzer.from_file(args.file)

        logger.info("=" * 70)
        logger.info("TP2 - SHELLCODE ANALYSIS")
        logger.info("=" * 70)
        logger.info(f"Fichier : {args.file}")
        logger.info(f"Testing shellcode of size {len(analyzer.shellcode)}B")
        logger.info("")

        strings = analyzer.get_shellcode_strings()
        _print_section(
            "1. STRINGS EXTRAITES",
            "\n".join(f"  [{i+1}] {s}" for i, s in enumerate(strings))
            if strings
            else "  (aucune chaîne trouvée)",
        )

        pylibemu_output = analyzer.get_pylibemu_analysis()
        _print_section("2. ANALYSE PYLIBEMU (émulation)", pylibemu_output)

        capstone_output = analyzer.get_capstone_analysis()
        _print_section("3. DÉSASSEMBLAGE CAPSTONE", capstone_output)

        if not args.no_llm:
            llm_output = analyzer.get_llm_analysis()
            _print_section("4. EXPLICATION LLM", f"Explication LLM : {llm_output}")
        else:
            logger.info("[--no-llm] Analyse LLM ignorée.")

        logger.info("=" * 70)
        logger.info("ANALYSE TERMINÉE")
        logger.info("=" * 70)

    except FileNotFoundError:
        logger.error(f"[ERREUR] Fichier introuvable : {args.file}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.warning("\nInterrompu par l'utilisateur.")
        sys.exit(0)
    except Exception as exc:
        logger.error(f"[ERREUR] {exc}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()