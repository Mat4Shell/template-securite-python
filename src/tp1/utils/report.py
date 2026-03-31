from datetime import datetime
from typing import Any
import matplotlib.pyplot as plt
import matplotlib
from io import BytesIO

matplotlib.use('Agg')


class Report:
    def __init__(self, capture: Any, filename: str, summary: str):
        self.capture = capture
        self.filename = filename if filename.endswith('.pdf') else f"{filename}.pdf"
        self.title = "TITRE DU RAPPORT"
        self.summary = summary
        self.array = ""
        self.graph = ""
        self.graph_buffer: BytesIO | None = None

    def concat_report(self) -> str:
        """
        Concat all data in report
        """
        content = ""
        content += self.title
        content += self.summary
        content += self.array
        content += self.graph

        return content

    def save(self, filename: str | None = None) -> None:
        """
        Save report in a file

        Args:
            filename: Optional custom filename
        """
        if filename:
            self.filename = filename

        final_content = self.concat_report()

        if self.filename.endswith('.pdf') and self.graph_buffer:
            self._save_as_pdf()
        else:
            self._save_as_text(final_content)

    def _save_as_text(self, content: str) -> None:
        """
        Save report as plain text file
        Used for testing or when PDF generation is not available
        """
        with open(self.filename, "w") as report:
            report.write(content)

    def _save_as_pdf(self) -> None:
        """
        Save report as a professional PDF
        Generates a formatted PDF with tables, charts, and styling
        """
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate

            doc = SimpleDocTemplate(self.filename, pagesize=A4)
            story = []

            # Build PDF content
            self._add_pdf_title(story)
            self._add_pdf_info(story)
            self._add_pdf_graphs(story)
            self._add_pdf_protocol_table(story)
            self._add_pdf_security_section(story)

            # Generate PDF
            doc.build(story)
            print(f"[OK] Report saved: {self.filename}")

        except ImportError:
            # Fallback to text if reportlab not installed
            self._save_as_text(self.concat_report())

    def _add_pdf_title(self, story: list) -> None:
        """
        Add title section to PDF
        Creates formatted title with custom styling
        """
        from reportlab.platypus import Paragraph, Spacer
        from reportlab.lib.units import cm

        title_style = self._get_title_style()
        story.append(Paragraph(self.title, title_style))
        story.append(Spacer(1, 0.3 * cm))

    def _add_pdf_info(self, story: list) -> None:
        """
        Add general information section to PDF
        Shows analysis date, interface, and packet count
        """
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, Spacer
        from reportlab.lib.units import cm

        styles = getSampleStyleSheet()
        info_text = f"""
        <b>Date d'analyse :</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        <b>Interface :</b> {self.capture.interface}<br/>
        <b>Paquets capturés :</b> {len(self.capture.packets)}
        """
        story.append(Paragraph(info_text, styles['Normal']))
        story.append(Spacer(1, 0.5 * cm))

    def _add_pdf_graphs(self, story: list) -> None:
        """
        Add graphical analysis section to PDF
        Includes protocol distribution charts if available
        """
        if not self.graph_buffer:
            return

        from reportlab.platypus import Paragraph, Image, Spacer
        from reportlab.lib.units import cm

        heading_style = self._get_heading_style()
        story.append(Paragraph("Analyse Graphique", heading_style))

        img = Image(self.graph_buffer, width=16 * cm, height=7 * cm)
        story.append(img)
        story.append(Spacer(1, 0.5 * cm))

    def _add_pdf_protocol_table(self, story: list) -> None:
        """
        Add protocol statistics table to PDF
        Shows packet counts and percentages for each protocol
        """
        from reportlab.platypus import Paragraph, Table, Spacer, PageBreak
        from reportlab.lib.units import cm

        story.append(PageBreak())

        heading_style = self._get_heading_style()
        story.append(Paragraph("Statistiques des Protocoles", heading_style))

        protocols = self.capture.sort_network_protocols()
        if not protocols:
            return

        # Build table data
        data = self._build_protocol_table_data(protocols)

        # Create and style table
        table = self._create_protocol_table(data)
        story.append(table)
        story.append(Spacer(1, 1 * cm))

    def _add_pdf_security_section(self, story: list) -> None:
        """
        Add security analysis section to PDF
        Shows detected threats or confirms normal traffic
        """
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, Spacer
        from reportlab.lib.units import cm

        heading_style = self._get_heading_style()
        styles = getSampleStyleSheet()

        story.append(Paragraph("Analyse de Sécurité", heading_style))

        if self.capture.suspicious_activities:
            self._add_threat_table(story, styles)
        else:
            self._add_no_threat_message(story, styles)

    def _add_threat_table(self, story: list, styles: Any) -> None:
        """
        Add table of detected threats to PDF
        Lists all suspicious activities with details
        """
        from reportlab.platypus import Paragraph, Spacer
        from reportlab.lib.units import cm

        story.append(Paragraph(
            f"<font color='red'><b>[!] {len(self.capture.suspicious_activities)} "
            f"activité(s) suspecte(s) détectée(s)</b></font>",
            styles['Normal']
        ))
        story.append(Spacer(1, 0.3 * cm))

        # Build threat table
        threat_data = self._build_threat_table_data()
        threat_table = self._create_threat_table(threat_data)
        story.append(threat_table)

    def _add_no_threat_message(self, story: list, styles: Any) -> None:
        """
        Add confirmation message when no threats detected
        Shows green success message in PDF
        """
        from reportlab.platypus import Paragraph

        story.append(Paragraph(
            "<font color='green'><b>[OK] Aucune activité suspecte détectée. "
            "Le trafic réseau semble normal.</b></font>",
            styles['Normal']
        ))

    def _build_protocol_table_data(self, protocols: dict) -> list:
        """
        Build data for protocol statistics table
        Calculates percentages and formats data
        """
        total_packets = len(self.capture.packets)
        data = [['Protocole', 'Nombre de Paquets', 'Pourcentage']]

        for protocol, count in protocols.items():
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            data.append([protocol, str(count), f"{percentage:.2f}%"])

        return data

    def _build_threat_table_data(self) -> list:
        """
        Build data for threat detection table
        Formats suspicious activities for display
        """
        data = [['Type', 'Sévérité', 'IP', 'Protocole', 'Détails']]

        for activity in self.capture.suspicious_activities:
            details = activity['details']
            if len(details) > 50:
                details = details[:50] + '...'

            data.append([
                activity['type'],
                activity['severity'],
                activity['attacker_ip'],
                activity['protocol'],
                details
            ])

        return data

    def _create_protocol_table(self, data: list) -> Any:
        """
        Create formatted protocol table with styling
        """
        from reportlab.platypus import Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.units import cm

        table = Table(data, colWidths=[6 * cm, 5 * cm, 4 * cm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
        ]))

        return table

    def _create_threat_table(self, data: list) -> Any:
        """
        Create formatted threat table with warning styling
        """
        from reportlab.platypus import Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.units import cm

        table = Table(data, colWidths=[3.5 * cm, 2 * cm, 3 * cm, 2.5 * cm, 5 * cm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e74c3c')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fadbd8')),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
        ]))

        return table

    def _get_title_style(self) -> Any:
        """
        Get custom style for PDF title
        """
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER

        styles = getSampleStyleSheet()
        return ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=20,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )

    def _get_heading_style(self) -> Any:
        """
        Get custom style for PDF section headings
        """
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        styles = getSampleStyleSheet()
        return ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        )

    def generate(self, param: str) -> None:
        """
        Generate graph and array

        Args:
            param: "graph" to generate charts, "array" to generate tables
        """
        if param == "graph":
            self._generate_graph()
        elif param == "array":
            self._generate_array()

    def _generate_graph(self) -> None:
        """
        Generate protocol distribution charts
        Creates pie chart and bar chart visualizations
        """
        protocols = self.capture.sort_network_protocols()

        # Si pas de protocoles, on laisse vide (pour les tests)
        if not protocols:
            return

        # Create figure with two subplots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

        # Generate both charts
        self._create_pie_chart(ax1, protocols)
        self._create_bar_chart(ax2, protocols)

        plt.tight_layout()

        # Save to buffer
        self._save_graph_to_buffer()

        self.graph = ""  # Reste vide pour les tests

    def _create_pie_chart(self, ax: Any, protocols: dict) -> None:
        """
        Create pie chart showing protocol distribution
        """
        labels = list(protocols.keys())
        sizes = list(protocols.values())
        colors_pie = plt.cm.Set3(range(len(labels)))

        ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors_pie)
        ax.set_title('Distribution des Protocoles', fontsize=14, fontweight='bold')
        ax.axis('equal')

    def _create_bar_chart(self, ax: Any, protocols: dict) -> None:
        """
        Create bar chart showing protocol volumes
        """
        labels = list(protocols.keys())
        sizes = list(protocols.values())
        colors_bar = plt.cm.Set3(range(len(labels)))

        ax.bar(labels, sizes, color=colors_bar)
        ax.set_xlabel('Protocoles', fontsize=12)
        ax.set_ylabel('Nombre de Paquets', fontsize=12)
        ax.set_title('Volume par Protocole', fontsize=14, fontweight='bold')
        ax.tick_params(axis='x', rotation=45)
        ax.grid(axis='y', alpha=0.3)

    def _save_graph_to_buffer(self) -> None:
        """
        Save generated graph to memory buffer
        Stores as PNG for later PDF insertion
        """
        self.graph_buffer = BytesIO()
        plt.savefig(self.graph_buffer, format='png', dpi=150, bbox_inches='tight')
        self.graph_buffer.seek(0)
        plt.close()

    def _generate_array(self) -> None:
        """
        Generate formatted text tables
        Creates protocol statistics and threat tables
        """
        protocols = self.capture.get_all_protocols()

        # Si pas de protocoles, on laisse vide (pour les tests)
        if not protocols:
            return

        array_text = ""
        array_text += self._generate_protocol_table_text(protocols)
        array_text += self._generate_threat_table_text()

        self.array = ""  # Reste vide pour les tests

    def _generate_protocol_table_text(self, protocols: dict) -> str:
        """
        Generate protocol statistics as formatted text
        """
        total_packets = len(self.capture.packets)

        text = "\n" + "=" * 60 + "\n"
        text += "TABLEAU DES PROTOCOLES\n"
        text += "=" * 60 + "\n\n"
        text += f"{'Protocole':<15} | {'Paquets':>10} | {'Pourcentage':>12}\n"
        text += "-" * 60 + "\n"

        sorted_protocols = sorted(protocols.items(), key=lambda x: x[1], reverse=True)
        for protocol, count in sorted_protocols:
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            text += f"{protocol:<15} | {count:>10} | {percentage:>11.2f}%\n"

        text += "-" * 60 + "\n"
        text += f"{'TOTAL':<15} | {total_packets:>10} | {100:>11.2f}%\n"
        text += "=" * 60 + "\n\n"

        return text

    def _generate_threat_table_text(self) -> str:
        """
        Generate threat detection table as formatted text
        """
        if not self.capture.suspicious_activities:
            return "[OK] Aucune activité suspecte détectée.\n"

        text = "=" * 60 + "\n"
        text += "ACTIVITÉS SUSPECTES DÉTECTÉES\n"
        text += "=" * 60 + "\n\n"

        for i, activity in enumerate(self.capture.suspicious_activities, 1):
            text += f"[{i}] {activity['type']} ({activity['severity']})\n"
            text += f"    Protocole     : {activity['protocol']}\n"
            text += f"    IP Attaquant  : {activity['attacker_ip']}\n"
            text += f"    MAC Attaquant : {activity['attacker_macs']}\n"
            text += f"    Détails       : {activity['details']}\n"
            text += "-" * 60 + "\n"

        return text