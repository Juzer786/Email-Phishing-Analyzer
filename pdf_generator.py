from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet


def generate_pdf(report):

    pdf_file = "report.pdf"

    doc = SimpleDocTemplate(pdf_file)

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "Phishing Email Analysis Report",
            styles["Title"]
        )
    )

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            f"Risk Level: {report['risk_level']}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"Risk Score: {report['risk_score']}/100",
            styles["Normal"]
        )
    )

    content.append(Spacer(1, 10))

    content.append(
        Paragraph("URLs Found", styles["Heading2"])
    )

    for url in report["urls_found"]:
        content.append(
            Paragraph(url, styles["Normal"])
        )

    content.append(Spacer(1, 10))

    content.append(
        Paragraph(
            "Detection Reasons",
            styles["Heading2"]
        )
    )

    for reason in report["reasons"]:
        content.append(
            Paragraph(reason, styles["Normal"])
        )

    doc.build(content)

    return pdf_file