from src.tp1.utils.capture import Capture
from src.tp1.utils.config import logger
from src.tp1.utils.report import Report


def main():
    try:
        # Étape 1: Setup (tout en print, pas de logger)
        print("\n" + "=" * 70)
        print("TP1 - NETWORK TRAFFIC ANALYSIS AND THREAT DETECTION")
        print("=" * 70)
        print("\n[1/4] Setting up capture...\n")

        # Sélection d'interface (sans logger)
        capture = Capture()

        if not capture.interface:
            print("\n[!] No interface selected. Exiting.")
            return

        # Demander les paramètres de capture (AVANT tout log)
        print("\n" + "-" * 70)
        print("CAPTURE PARAMETERS")
        print("-" * 70)

        try:
            packet_count = input("Number of packets to capture (default: 100): ").strip()
            packet_count = int(packet_count) if packet_count else 100

            timeout = input("Timeout in seconds (default: 30): ").strip()
            timeout = int(timeout) if timeout else 30
        except ValueError:
            print("[!] Invalid input, using defaults (100 packets, 30s timeout)")
            packet_count = 100
            timeout = 30

        print("-" * 70 + "\n")

        # MAINTENANT on peut logger (toutes les saisies sont finies)
        logger.info("=" * 70)
        logger.info("CAPTURE CONFIGURATION")
        logger.info("=" * 70)
        logger.info(f"Selected interface: {capture.interface}")
        logger.info(f"Capture parameters: {packet_count} packets, {timeout}s timeout")
        logger.info("=" * 70)

        logger.info("\n[2/4] Starting capture...")
        logger.warning("NOTE: You must run this script as Administrator/root!")

        capture.capture_traffic(count=packet_count, timeout=timeout)

        if not capture.packets:
            logger.warning("No packets captured. Exiting.")
            return

        # Étape 2: Analyse du trafic
        logger.info("\n[3/4] Analyzing traffic for threats...")
        capture.analyse("all")

        # Afficher le résumé dans la console
        summary = capture.get_summary()
        if summary:
            print("\n" + summary)

        # Étape 3: Génération du rapport
        logger.info("\n[4/4] Generating PDF report...")

        print("\n" + "-" * 70)
        filename = input("Report filename (default: 'network_analysis_report'): ").strip()
        filename = filename if filename else "network_analysis_report"
        print("-" * 70 + "\n")

        report = Report(capture, filename, summary)
        report.generate("graph")
        report.generate("array")
        report.save()

        logger.info("\n" + "=" * 70)
        logger.info("ANALYSIS COMPLETE!")
        logger.info(f"Report saved as: {report.filename}")
        logger.info("=" * 70)

    except KeyboardInterrupt:
        logger.warning("\n\nInterrupted by user. Exiting...")
    except PermissionError:
        logger.error("\n[ERROR] Permission denied!")
        logger.error("Please run this script as Administrator (Windows) or with sudo (Linux)")
    except Exception as e:
        logger.error(f"\n[ERROR] An error occurred: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()