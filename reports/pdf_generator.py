"""
Executive PDF Report Generator for HRTIP
Generates professional threat intelligence reports
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, 
    PageBreak, Image, HRFlowable
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from datetime import datetime
from pathlib import Path
from collections import Counter
import json


class ThreatReportGenerator:
    """Generate executive-ready PDF threat intelligence reports"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Create custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=28,
            spaceAfter=30,
            textColor=colors.HexColor('#1a365d'),
            alignment=1  # Center
        ))
        self.styles.add(ParagraphStyle(
            name='SectionTitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.HexColor('#2c5282')
        ))
        self.styles.add(ParagraphStyle(
            name='MetricTitle',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#666666')
        ))
        self.styles.add(ParagraphStyle(
            name='MetricValue',
            parent=self.styles['Normal'],
            fontSize=24,
            textColor=colors.HexColor('#1a365d'),
            fontName='Helvetica-Bold'
        ))
        self.styles.add(ParagraphStyle(
            name='ReportBody',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceBefore=6,
            spaceAfter=6,
            leading=14
        ))
    
    def generate_report(self, data: dict, output_path: str = None) -> str:
        """Generate a complete threat intelligence report"""
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"reports/threat_report_{timestamp}.pdf"
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        story = []
        
        # Title Page
        story.extend(self._create_title_page(data))
        story.append(PageBreak())
        
        # Executive Summary
        story.extend(self._create_executive_summary(data))
        story.append(PageBreak())
        
        # IOC Overview
        story.extend(self._create_ioc_overview(data))
        story.append(PageBreak())
        
        # MITRE ATT&CK Coverage
        story.extend(self._create_mitre_section(data))
        story.append(PageBreak())
        
        # Threat Campaigns
        story.extend(self._create_campaigns_section(data))
        story.append(PageBreak())
        
        # Top IOCs Table
        story.extend(self._create_top_iocs_section(data))
        
        # Build PDF
        doc.build(story)
        return output_path
    
    def _create_title_page(self, data: dict) -> list:
        """Create the report title page"""
        elements = []
        elements.append(Spacer(1, 2*inch))
        elements.append(Paragraph("THREAT INTELLIGENCE REPORT", self.styles['ReportTitle']))
        elements.append(Spacer(1, 0.5*inch))
        elements.append(HRFlowable(width="50%", thickness=2, color=colors.HexColor('#2c5282')))
        elements.append(Spacer(1, 0.5*inch))
        
        date_str = datetime.now().strftime("%B %d, %Y")
        elements.append(Paragraph(f"Generated: {date_str}", self.styles['ReportBody']))
        elements.append(Paragraph("Healthcare & Retail Threat Intelligence Platform", self.styles['ReportBody']))
        
        elements.append(Spacer(1, 1*inch))
        
        # Quick stats box
        summary = data.get('summary', {})
        total_iocs = summary.get('total_iocs', 0)
        mitre = data.get('mitre_summary', {})
        anomalies = data.get('anomalies', {})
        
        stats_data = [
            ['Total IOCs', 'ATT&CK Coverage', 'Anomalies Detected', 'Active Feeds'],
            [
                str(total_iocs),
                f"{mitre.get('unique_techniques', 0)} techniques",
                str(anomalies.get('anomalies_found', 0)),
                str(len(data.get('feeds', {})))
            ]
        ]
        
        stats_table = Table(stats_data, colWidths=[1.5*inch]*4)
        stats_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#666666')),
            ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 1), (-1, 1), 18),
            ('TEXTCOLOR', (0, 1), (-1, 1), colors.HexColor('#1a365d')),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('TOPPADDING', (0, 1), (-1, 1), 6),
        ]))
        elements.append(stats_table)
        
        return elements
    
    def _create_executive_summary(self, data: dict) -> list:
        """Create executive summary section"""
        elements = []
        elements.append(Paragraph("Executive Summary", self.styles['SectionTitle']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
        elements.append(Spacer(1, 0.2*inch))
        
        summary = data.get('summary', {})
        mitre = data.get('mitre_summary', {})
        anomalies = data.get('anomalies', {})
        clusters = data.get('clusters', [])
        
        total_iocs = summary.get('total_iocs', 0)
        sources = summary.get('sources', {})
        threat_types = summary.get('threat_types', {})
        
        # Summary paragraph
        summary_text = f"""
        This report summarizes threat intelligence collected from {len(sources)} active sources, 
        comprising {total_iocs} unique indicators of compromise (IOCs). 
        Analysis identified {mitre.get('unique_techniques', 0)} MITRE ATT&CK techniques 
        across {mitre.get('unique_tactics', 0)} tactics, with {anomalies.get('anomalies_found', 0)} 
        anomalous indicators flagged for priority investigation.
        """
        elements.append(Paragraph(summary_text.strip(), self.styles['ReportBody']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Key findings
        elements.append(Paragraph("<b>Key Findings:</b>", self.styles['ReportBody']))
        
        # Top threat type
        if threat_types:
            top_threat = max(threat_types.items(), key=lambda x: x[1])
            elements.append(Paragraph(
                f"• Primary threat category: <b>{top_threat[0]}</b> ({top_threat[1]} IOCs)",
                self.styles['ReportBody']
            ))
        
        # Top malware
        malware_families = mitre.get('malware_families', [])
        if malware_families:
            top_malware = malware_families[0]
            elements.append(Paragraph(
                f"• Most prevalent malware family: <b>{top_malware[0]}</b> ({top_malware[1]} samples)",
                self.styles['ReportBody']
            ))
        
        # Campaigns
        if clusters:
            critical_campaigns = [c for c in clusters if c.get('malware_families')]
            elements.append(Paragraph(
                f"• Active threat campaigns detected: <b>{len(clusters)}</b> ({len(critical_campaigns)} with malware attribution)",
                self.styles['ReportBody']
            ))
        
        # Anomaly rate
        anomaly_rate = anomalies.get('anomaly_rate', 0)
        elements.append(Paragraph(
            f"• Anomaly detection rate: <b>{anomaly_rate}%</b> of indicators flagged as unusual",
            self.styles['ReportBody']
        ))
        
        return elements
    
    def _create_ioc_overview(self, data: dict) -> list:
        """Create IOC overview section with charts"""
        elements = []
        elements.append(Paragraph("IOC Distribution Analysis", self.styles['SectionTitle']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
        elements.append(Spacer(1, 0.2*inch))
        
        summary = data.get('summary', {})
        ioc_types = summary.get('ioc_types', {})
        sources = summary.get('sources', {})
        
        # IOC Types pie chart
        if ioc_types:
            elements.append(Paragraph("<b>IOC Types</b>", self.styles['ReportBody']))
            drawing = self._create_pie_chart(ioc_types, 300, 200)
            elements.append(drawing)
            elements.append(Spacer(1, 0.3*inch))
        
        # Sources table
        if sources:
            elements.append(Paragraph("<b>Collection Sources</b>", self.styles['ReportBody']))
            source_data = [['Source', 'IOC Count', 'Percentage']]
            total = sum(sources.values())
            for source, count in sorted(sources.items(), key=lambda x: x[1], reverse=True):
                pct = (count / total * 100) if total > 0 else 0
                source_data.append([source, str(count), f"{pct:.1f}%"])
            
            source_table = Table(source_data, colWidths=[2.5*inch, 1.5*inch, 1.5*inch])
            source_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5282')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
                ('PADDING', (0, 0), (-1, -1), 8),
            ]))
            elements.append(source_table)
        
        return elements
    
    def _create_mitre_section(self, data: dict) -> list:
        """Create MITRE ATT&CK section"""
        elements = []
        elements.append(Paragraph("MITRE ATT&CK Coverage", self.styles['SectionTitle']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
        elements.append(Spacer(1, 0.2*inch))
        
        mitre = data.get('mitre_summary', {})
        
        # Summary stats
        stats_text = f"""
        Threat mapping identified <b>{mitre.get('unique_techniques', 0)}</b> unique ATT&CK techniques 
        across <b>{mitre.get('unique_tactics', 0)}</b> tactics, covering approximately 
        <b>{int(mitre.get('kill_chain_coverage', 0) * 100)}%</b> of the kill chain.
        """
        elements.append(Paragraph(stats_text.strip(), self.styles['ReportBody']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Top techniques table
        top_techniques = mitre.get('top_techniques', [])
        if top_techniques:
            elements.append(Paragraph("<b>Top ATT&CK Techniques</b>", self.styles['ReportBody']))
            tech_data = [['Technique ID', 'IOC Count']]
            for tech_id, count in top_techniques[:10]:
                tech_data.append([tech_id, str(count)])
            
            tech_table = Table(tech_data, colWidths=[3*inch, 2*inch])
            tech_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#c53030')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fff5f5')]),
                ('PADDING', (0, 0), (-1, -1), 8),
            ]))
            elements.append(tech_table)
        
        return elements
    
    def _create_campaigns_section(self, data: dict) -> list:
        """Create threat campaigns section"""
        elements = []
        elements.append(Paragraph("Detected Threat Campaigns", self.styles['SectionTitle']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
        elements.append(Spacer(1, 0.2*inch))
        
        clusters = data.get('clusters', [])
        
        if not clusters:
            elements.append(Paragraph("No distinct threat campaigns identified in this collection period.", self.styles['ReportBody']))
            return elements
        
        elements.append(Paragraph(
            f"ML clustering identified <b>{len(clusters)}</b> potential threat campaigns based on shared infrastructure, malware, and behavioral patterns.",
            self.styles['ReportBody']
        ))
        elements.append(Spacer(1, 0.2*inch))
        
        # Campaigns table
        campaign_data = [['Campaign', 'Size', 'Malware', 'Threat Types']]
        for cluster in clusters[:10]:
            name = cluster.get('potential_campaign', 'Unknown')
            size = cluster.get('size', 0)
            malware = ', '.join(cluster.get('malware_families', [])[:2]) or '-'
            threats = ', '.join(cluster.get('threat_types', [])[:2]) or '-'
            campaign_data.append([name, str(size), malware, threats])
        
        campaign_table = Table(campaign_data, colWidths=[2*inch, 0.8*inch, 1.7*inch, 2*inch])
        campaign_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#d69e2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fffff0')]),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(campaign_table)
        
        return elements
    
    def _create_top_iocs_section(self, data: dict) -> list:
        """Create top IOCs section"""
        elements = []
        elements.append(Paragraph("High-Confidence Indicators", self.styles['SectionTitle']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
        elements.append(Spacer(1, 0.2*inch))
        
        top_iocs = data.get('top_iocs', [])
        
        if not top_iocs:
            elements.append(Paragraph("No high-confidence IOCs available.", self.styles['ReportBody']))
            return elements
        
        elements.append(Paragraph(
            "The following indicators have the highest confidence scores based on source reliability, corroboration, and threat context.",
            self.styles['ReportBody']
        ))
        elements.append(Spacer(1, 0.2*inch))
        
        # IOCs table
        ioc_data = [['Type', 'Value', 'Confidence', 'Threat Type']]
        for ioc in top_iocs[:15]:
            ioc_type = ioc.get('type', '-')
            value = ioc.get('value', '-')
            if len(value) > 40:
                value = value[:37] + '...'
            confidence = ioc.get('confidence_score', 0)
            threat = ioc.get('threat_type', '-') or '-'
            ioc_data.append([ioc_type, value, str(confidence), threat])
        
        ioc_table = Table(ioc_data, colWidths=[1*inch, 3.2*inch, 0.9*inch, 1.4*inch])
        ioc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5282')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (1, -1), 'Courier'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ALIGN', (2, 0), (2, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(ioc_table)
        
        return elements
    
    def _create_pie_chart(self, data: dict, width: int, height: int) -> Drawing:
        """Create a pie chart"""
        drawing = Drawing(width, height)
        pie = Pie()
        pie.x = 100
        pie.y = 20
        pie.width = 120
        pie.height = 120
        
        # Limit to top 6 categories
        sorted_items = sorted(data.items(), key=lambda x: x[1], reverse=True)[:6]
        pie.data = [v for k, v in sorted_items]
        pie.labels = [k for k, v in sorted_items]
        
        pie.slices.strokeWidth = 0.5
        pie.slices.strokeColor = colors.white
        
        # Colors
        chart_colors = [
            colors.HexColor('#4299e1'),
            colors.HexColor('#48bb78'),
            colors.HexColor('#ed8936'),
            colors.HexColor('#9f7aea'),
            colors.HexColor('#f56565'),
            colors.HexColor('#38b2ac'),
        ]
        for i, color in enumerate(chart_colors[:len(sorted_items)]):
            pie.slices[i].fillColor = color
        
        drawing.add(pie)
        return drawing


def generate_report_from_api():
    """Generate report by fetching data from API"""
    import requests
    
    try:
        response = requests.get('http://localhost:8000/dashboard-data', timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"Error fetching data from API: {e}")
        print("Make sure the API is running: python -m analyzer.api")
        return None
    
    generator = ThreatReportGenerator()
    output_path = generator.generate_report(data)
    print(f"Report generated: {output_path}")
    return output_path


def generate_report_from_file(filepath: str):
    """Generate report from a saved data file"""
    with open(filepath) as f:
        data = json.load(f)
    
    generator = ThreatReportGenerator()
    output_path = generator.generate_report(data)
    print(f"Report generated: {output_path}")
    return output_path


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # Generate from file
        generate_report_from_file(sys.argv[1])
    else:
        # Generate from API
        generate_report_from_api()
