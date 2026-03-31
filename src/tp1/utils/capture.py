from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Raw
from scapy.plist import PacketList

from collections import defaultdict, Counter
from typing import Dict, Any
import re
from datetime import datetime

from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets: PacketList = PacketList()
        self.protocol_count: Counter = Counter()
        self.suspicious_activities: list[Dict[str, str]] = []

        # Tracking pour détection d'attaques
        self.arp_table: Dict[str, set] = defaultdict(set)
        self.syn_attempts: Dict[str, int] = defaultdict(int)
        self.icmp_count: Dict[str, int] = defaultdict(int)

    def capture_traffic(self, count: int = 100, timeout: int = 30) -> None:
        """
        Capture network traffic from an interface

        Args:
            count: Number of packets to capture (default: 100)
            timeout: Timeout in seconds (default: 30)
        """
        interface = self.interface

        # Si pas d'interface, on ne fait rien (pour les tests)
        if not interface:
            logger.warning("No interface selected, skipping capture")
            return

        logger.info(f"Starting capture on interface {interface}")
        logger.info(f"Capturing {count} packets or waiting {timeout} seconds...")

        try:
            # Capture des paquets
            self.packets = sniff(
                iface=interface,
                count=count,
                timeout=timeout,
                store=True
            )

            logger.info(f"Captured {len(self.packets)} packets")

            # Traitement des paquets capturés
            for pkt in self.packets:
                self._process_packet(pkt)

        except PermissionError:
            logger.error("Permission denied. Run as administrator/root!")
            raise
        except Exception as e:
            logger.error(f"Error during capture: {e}")
            raise

    def _process_packet(self, pkt: Any) -> None:
        """
        Process a single packet and update statistics
        Dispatches packet analysis to specialized methods
        """
        self._count_ip_protocols(pkt)
        self._count_arp_protocol(pkt)
        self._count_ethernet_protocol(pkt)
        self._track_syn_packets(pkt)

    def _count_ip_protocols(self, pkt: Any) -> None:
        """
        Count IP layer protocols (IP, TCP, UDP, ICMP)
        Also tracks ICMP packets for flood detection
        """
        if IP not in pkt:
            return

        self.protocol_count['IP'] += 1

        if TCP in pkt:
            self.protocol_count['TCP'] += 1
        elif UDP in pkt:
            self.protocol_count['UDP'] += 1
        elif ICMP in pkt:
            self.protocol_count['ICMP'] += 1
            # Track ICMP pour flood detection
            if pkt[IP].src:
                self.icmp_count[pkt[IP].src] += 1

    def _count_arp_protocol(self, pkt: Any) -> None:
        """
        Count ARP protocol packets
        Tracks ARP mappings for spoofing detection
        """
        if ARP not in pkt:
            return

        self.protocol_count['ARP'] += 1

        # Track ARP pour spoofing detection
        if pkt[ARP].psrc:  # Source IP
            self.arp_table[pkt[ARP].psrc].add(pkt[ARP].hwsrc)

    def _count_ethernet_protocol(self, pkt: Any) -> None:
        """
        Count Ethernet layer packets
        """
        if Ether in pkt:
            self.protocol_count['Ethernet'] += 1

    def _track_syn_packets(self, pkt: Any) -> None:
        """
        Track TCP SYN packets for port scanning detection
        """
        if TCP not in pkt:
            return

        # Check for SYN flag
        if pkt[TCP].flags == 'S' and IP in pkt:
            self.syn_attempts[pkt[IP].src] += 1

    def sort_network_protocols(self) -> Dict[str, int] | None:
        """
        Sort and return all captured network protocols

        Returns:
            Dictionary of protocols sorted by packet count (descending), or None if empty
        """
        if not self.protocol_count:
            return None

        sorted_protocols = dict(
            sorted(self.protocol_count.items(),
                   key=lambda x: x[1],
                   reverse=True)
        )

        logger.debug(f"Sorted protocols: {sorted_protocols}")
        return sorted_protocols

    def get_all_protocols(self) -> Dict[str, int] | None:
        """
        Return all protocols captured with total packets number

        Returns:
            Dictionary of protocol names and their packet counts, or None if empty
        """
        if not self.protocol_count:
            return None

        total = sum(self.protocol_count.values())
        logger.info(f"Total protocol instances: {total}")

        return dict(self.protocol_count)

    def _detect_arp_spoofing(self) -> None:
        """
        Detect ARP spoofing attacks
        Identifies when multiple MAC addresses claim the same IP
        """
        for ip, macs in self.arp_table.items():
            if len(macs) > 1:
                self.suspicious_activities.append({
                    'type': 'ARP Spoofing',
                    'protocol': 'ARP',
                    'attacker_ip': ip,
                    'attacker_macs': ', '.join(macs),
                    'details': f'Multiple MAC addresses ({len(macs)}) detected for IP {ip}',
                    'severity': 'HIGH'
                })
                logger.warning(f"[!] ARP Spoofing detected from IP {ip} with MACs: {macs}")

    def _detect_port_scanning(self, threshold: int = 20) -> None:
        """
        Detect port scanning attempts
        Identifies excessive SYN packets from a single source
        """
        for src_ip, count in self.syn_attempts.items():
            if count > threshold:
                self.suspicious_activities.append({
                    'type': 'Port Scanning',
                    'protocol': 'TCP',
                    'attacker_ip': src_ip,
                    'attacker_macs': 'N/A',
                    'details': f'{count} SYN packets sent from {src_ip}',
                    'severity': 'MEDIUM'
                })
                logger.warning(f"[!] Possible port scan from {src_ip} ({count} SYN packets)")

    def _detect_icmp_flood(self, threshold: int = 50) -> None:
        """
        Detect ICMP flood attacks
        Identifies excessive ICMP packets from a single source
        """
        for src_ip, count in self.icmp_count.items():
            if count > threshold:
                self.suspicious_activities.append({
                    'type': 'ICMP Flood',
                    'protocol': 'ICMP',
                    'attacker_ip': src_ip,
                    'attacker_macs': 'N/A',
                    'details': f'{count} ICMP packets from {src_ip}',
                    'severity': 'MEDIUM'
                })
                logger.warning(f"[!] ICMP flood detected from {src_ip} ({count} packets)")

    def _detect_sql_injection(self) -> None:
        """
        Detect SQL injection attempts in HTTP traffic
        Scans packet payloads for SQL injection patterns
        """
        # Dictionnaire pour grouper les détections par IP
        sqli_by_ip: Dict[str, int] = defaultdict(int)

        # Patterns plus stricts pour éviter les faux positifs
        sql_patterns = [
            r"(\bunion\b.*\bselect\b)",  # UNION SELECT
            r"(\bor\b.*[=<>].*\bor\b)",  # OR 1=1 OR
            r"(\band\b.*[=<>].*\band\b)",  # AND 1=1 AND
            r"(exec\s*\()",  # exec(
            r"(execute\s*\()",  # execute(
            r"(;.*drop\s+table)",  # ; DROP TABLE
            r"(;.*insert\s+into)",  # ; INSERT INTO
            r"(;.*delete\s+from)",  # ; DELETE FROM
            r"(;.*update\s+.*set)",  # ; UPDATE ... SET
        ]

        for pkt in self.packets:
            # Ne scanner que le trafic HTTP non-HTTPS
            if Raw in pkt and TCP in pkt:
                # Filtrer le trafic HTTPS (port 443)
                if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                    continue

                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').lower()

                    # Ignorer les payloads trop courts ou binaires
                    if len(payload) < 20:
                        continue

                    for pattern in sql_patterns:
                        if re.search(pattern, payload, re.IGNORECASE):
                            src_ip = pkt[IP].src if IP in pkt else 'Unknown'
                            sqli_by_ip[src_ip] += 1
                            break  # Un seul pattern par paquet suffit

                except Exception:
                    # Ignorer les erreurs de décodage
                    continue

        # Créer les alertes groupées par IP (seuil: 3+ détections)
        for src_ip, count in sqli_by_ip.items():
            if count >= 3:  # Seuil pour confirmer une vraie attaque
                self.suspicious_activities.append({
                    'type': 'SQL Injection Attempt',
                    'protocol': 'HTTP/TCP',
                    'attacker_ip': src_ip,
                    'attacker_macs': 'N/A',
                    'details': f'{count} SQLi patterns detected in HTTP traffic from {src_ip}',
                    'severity': 'HIGH'
                })
                logger.warning(f"[!] SQL Injection attempts from {src_ip} ({count} patterns detected)")

    def analyse(self, protocols: str = "all") -> None:
        """
        Analyse all captured data and detect attacks

        Si un trafic est illégitime (exemple : Injection SQL, ARP Spoofing, etc)
        a) Noter la tentative d'attaque.
        b) Relever le protocole ainsi que l'adresse réseau/physique de l'attaquant.
        c) (FACULTATIF) Opérer le blocage de la machine attaquante.
        Sinon afficher que tout va bien

        Args:
            protocols: Specific protocols to analyze (default: "all")
        """
        logger.info("Starting traffic analysis...")

        all_protocols = self.get_all_protocols()
        sorted_protocols = self.sort_network_protocols()

        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sorted_protocols}")

        # Détection des attaques uniquement si on a des paquets
        if self.packets:
            self._detect_arp_spoofing()
            self._detect_port_scanning(threshold=20)
            self._detect_icmp_flood(threshold=50)
            self._detect_sql_injection()

        # Résumé
        self._log_analysis_results()
        self.summary = self.gen_summary()

    def _log_analysis_results(self) -> None:
        """
        Log analysis results to console
        Shows detected threats or confirms normal traffic
        """
        if self.suspicious_activities:
            logger.warning(f"[!] {len(self.suspicious_activities)} suspicious activities detected!")

            # Grouper par type d'attaque
            attacks_by_type: Dict[str, int] = defaultdict(int)
            for activity in self.suspicious_activities:
                attacks_by_type[activity['type']] += 1

            # Afficher un résumé groupé
            for attack_type, count in attacks_by_type.items():
                logger.warning(f"  - {attack_type}: {count} incident(s)")
        else:
            logger.info("[OK] No suspicious activity detected. Network traffic appears normal.")

    def get_summary(self) -> str:
        """Return the analysis summary"""
        return self.summary

    def gen_summary(self) -> str:
        """
        Generate analysis summary

        Returns:
            Formatted summary string (empty if no packets captured)
        """
        # Si pas de paquets, retourner une chaîne vide (pour les tests)
        if not self.packets:
            return ""

        summary_lines = []

        # Header
        self._add_summary_header(summary_lines)

        # Protocol statistics
        self._add_protocol_statistics(summary_lines)

        # Security analysis
        self._add_security_analysis(summary_lines)

        # Footer
        summary_lines.append("=" * 60)

        return "\n".join(summary_lines)

    def _add_summary_header(self, summary_lines: list[str]) -> None:
        """
        Add header section to summary
        Includes timestamp, interface, and packet count
        """
        summary_lines.extend([
            "=" * 60,
            "NETWORK TRAFFIC ANALYSIS SUMMARY",
            "=" * 60,
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Interface: {self.interface}",
            f"Total packets captured: {len(self.packets)}",
            ""
        ])

    def _add_protocol_statistics(self, summary_lines: list[str]) -> None:
        """
        Add protocol statistics section to summary
        Shows distribution of captured protocols
        """
        summary_lines.extend([
            "PROTOCOL STATISTICS:",
            "-" * 60
        ])

        sorted_protocols = self.sort_network_protocols()
        if sorted_protocols:
            for protocol, count in sorted_protocols.items():
                percentage = (count / len(self.packets) * 100) if self.packets else 0
                summary_lines.append(f"  {protocol:15s}: {count:5d} packets ({percentage:5.2f}%)")

        summary_lines.append("")

    def _add_security_analysis(self, summary_lines: list[str]) -> None:
        """
        Add security analysis section to summary
        Lists detected threats or confirms normal traffic
        """
        summary_lines.extend([
            "SECURITY ANALYSIS:",
            "-" * 60
        ])

        if self.suspicious_activities:
            summary_lines.append(f"[!] {len(self.suspicious_activities)} SUSPICIOUS ACTIVITIES DETECTED\n")

            # Grouper par type
            grouped = self._group_suspicious_activities()

            for attack_type, activities in grouped.items():
                summary_lines.append(f"{attack_type} ({len(activities)} incident(s)):")

                # Afficher les détails (limiter à 5 pour ne pas surcharger)
                for i, activity in enumerate(activities[:5], 1):
                    summary_lines.extend([
                        f"  [{i}] Severity: {activity['severity']}",
                        f"      Attacker IP: {activity['attacker_ip']}",
                        f"      Details: {activity['details']}"
                    ])

                if len(activities) > 5:
                    summary_lines.append(f"  ... and {len(activities) - 5} more similar incidents")

                summary_lines.append("")
        else:
            summary_lines.extend([
                "[OK] No suspicious activity detected.",
                "[OK] Network traffic appears normal."
            ])

    def _group_suspicious_activities(self) -> Dict[str, list]:
        """
        Group suspicious activities by type for cleaner display
        """
        grouped: Dict[str, list] = defaultdict(list)
        for activity in self.suspicious_activities:
            grouped[activity['type']].append(activity)
        return grouped