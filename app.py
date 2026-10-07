import streamlit as st
import os
import tempfile
from io import BytesIO

from analyzers.file_analyzer import analyze_file
from analyzers.risk_analyzer import calculate_risk


# ==========================================================
# PDF REPORT GENERATOR
# ==========================================================

def generate_pdf_report(file_result, risk_result):

    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle
    )
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.enums import TA_CENTER

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = styles["Title"]
    title_style.alignment = TA_CENTER

    story = []

    # ------------------------------------------------------
    # Title
    # ------------------------------------------------------

    story.append(
        Paragraph(
            "TrustLens AI - File Trust & Risk Analysis Report",
            title_style
        )
    )

    story.append(Spacer(1, 20))

    # ------------------------------------------------------
    # File Information
    # ------------------------------------------------------

    story.append(
        Paragraph("<b>File Information</b>", styles["Heading2"])
    )

    file_name = file_result.get("file_name", "Unknown")
    extension = file_result.get("extension", "Unknown")
    size_kb = file_result.get("size_kb", 0)
    actual_type = file_result.get("actual_type", "Unknown")
    sha256 = file_result.get("sha256", "Not available")
    mismatch = file_result.get("extension_mismatch", False)

    file_data = [
        ["Property", "Value"],
        ["File Name", str(file_name)],
        ["Extension", str(extension)],
        ["File Size", f"{size_kb} KB"],
        ["Actual File Type", str(actual_type)],
        ["Extension Mismatch", str(mismatch)],
        ["SHA-256", str(sha256)]
    ]

    table = Table(file_data, colWidths=[160, 330])

    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
        ])
    )

    story.append(table)
    story.append(Spacer(1, 20))

    # ------------------------------------------------------
    # Risk Analysis
    # ------------------------------------------------------

    story.append(
        Paragraph("<b>Risk Analysis</b>", styles["Heading2"])
    )

    risk_score = risk_result.get("risk_score", 0)
    risk_level = risk_result.get("risk_level", "UNKNOWN")
    status = risk_result.get("status", "UNKNOWN")

    risk_data = [
        ["Risk Score", f"{risk_score} / 100"],
        ["Risk Level", str(risk_level)],
        ["Status", str(status)]
    ]

    risk_table = Table(
        risk_data,
        colWidths=[160, 330]
    )

    risk_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
        ])
    )

    story.append(risk_table)
    story.append(Spacer(1, 20))

    # ------------------------------------------------------
    # Risk Reasons
    # ------------------------------------------------------

    story.append(
        Paragraph("<b>Risk Indicators</b>", styles["Heading2"])
    )

    reasons = risk_result.get("reasons", [])

    if reasons:

        for reason in reasons:

            story.append(
                Paragraph(
                    f"• {reason}",
                    styles["Normal"]
                )
            )

            story.append(Spacer(1, 5))

    else:

        story.append(
            Paragraph(
                "No major risk indicators detected.",
                styles["Normal"]
            )
        )

    story.append(Spacer(1, 20))

    # ------------------------------------------------------
    # Final Result
    # ------------------------------------------------------

    story.append(
        Paragraph("<b>Final Result</b>", styles["Heading2"])
    )

    if status == "SAFE":

        final_message = (
            "This file appears to be SAFE based on the available analysis."
        )

    elif status == "SUSPICIOUS":

        final_message = (
            "This file is SUSPICIOUS. "
            "Review it carefully before opening."
        )

    else:

        final_message = (
            "This file appears DANGEROUS. "
            "Do not open or execute it without further investigation."
        )

    story.append(
        Paragraph(
            final_message,
            styles["Normal"]
        )
    )

    story.append(Spacer(1, 30))

    story.append(
        Paragraph(
            "Generated by TrustLens AI",
            styles["Normal"]
        )
    )

    document.build(story)

    buffer.seek(0)

    return buffer.getvalue()


# ==========================================================
# PAGE CONFIGURATION
# ==========================================================

st.set_page_config(
    page_title="TrustLens AI",
    page_icon="🛡️",
    layout="wide"
)


# ==========================================================
# CUSTOM CSS
# ==========================================================

st.markdown(
    """
    <style>

    .main-title {
        text-align: center;
        font-size: 42px;
        font-weight: bold;
        margin-bottom: 5px;
    }

    .subtitle {
        text-align: center;
        font-size: 18px;
        color: gray;
        margin-bottom: 30px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ==========================================================
# HEADER
# ==========================================================

st.markdown(
    '<div class="main-title">🛡️ TrustLens AI</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">AI-Powered File Trust & Risk Analysis System</div>',
    unsafe_allow_html=True
)


# ==========================================================
# INTRODUCTION
# ==========================================================

st.info(
    """
    **TrustLens AI** analyzes uploaded files and identifies
    potential security risks using file metadata, file type,
    extension mismatch, and suspicious extensions.
    """
)


# ==========================================================
# FILE UPLOAD
# ==========================================================

st.subheader("📂 Upload a File")

uploaded_file = st.file_uploader(
    "Choose a file to analyze",
    type=None
)


# ==========================================================
# ANALYSIS
# ==========================================================

if uploaded_file is not None:

    st.success(
        f"File uploaded: **{uploaded_file.name}**"
    )

    if st.button(
        "🔍 Analyze File",
        use_container_width=True
    ):

        temp_path = None

        try:

            # ------------------------------------------------
            # Save temporary file
            # ------------------------------------------------

            file_extension = os.path.splitext(
                uploaded_file.name
            )[1]

            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=file_extension
            ) as temp_file:

                temp_file.write(
                    uploaded_file.getbuffer()
                )

                temp_path = temp_file.name


            # ------------------------------------------------
            # File Analyzer
            # ------------------------------------------------

            with st.spinner("Analyzing file..."):

                file_result = analyze_file(
                    temp_path
                )


            # ------------------------------------------------
            # Error Check
            # ------------------------------------------------

            if "error" in file_result:

                st.error(
                    f"File analysis failed: "
                    f"{file_result['error']}"
                )

            else:

                # ------------------------------------------------
                # Risk Analyzer
                # ------------------------------------------------

                risk_result = calculate_risk(
                    file_result
                )


                # =================================================
                # FILE INFORMATION
                # =================================================

                st.subheader("📄 File Information")

                col1, col2, col3 = st.columns(3)

                with col1:

                    st.metric(
                        "File Name",
                        file_result.get(
                            "file_name",
                            uploaded_file.name
                        )
                    )

                with col2:

                    st.metric(
                        "Extension",
                        file_result.get(
                            "extension",
                            "Unknown"
                        )
                    )

                with col3:

                    st.metric(
                        "File Size",
                        f"{file_result.get('size_kb', 0)} KB"
                    )


                # =================================================
                # TECHNICAL ANALYSIS
                # =================================================

                st.subheader("🔐 Technical Analysis")

                col1, col2 = st.columns(2)

                with col1:

                    st.write(
                        "**Actual File Type:**",
                        file_result.get(
                            "actual_type",
                            "Unknown"
                        )
                    )

                    st.write(
                        "**Extension Mismatch:**",
                        file_result.get(
                            "extension_mismatch",
                            False
                        )
                    )

                with col2:

                    st.write(
                        "**SHA-256 Hash:**"
                    )

                    st.code(
                        file_result.get(
                            "sha256",
                            "Not available"
                        )
                    )


                # =================================================
                # RISK ANALYSIS
                # =================================================

                st.subheader("🚨 Risk Analysis")

                risk_score = risk_result.get(
                    "risk_score",
                    0
                )

                risk_level = risk_result.get(
                    "risk_level",
                    "UNKNOWN"
                )

                status = risk_result.get(
                    "status",
                    "UNKNOWN"
                )


                col1, col2, col3 = st.columns(3)

                with col1:

                    st.metric(
                        "Risk Score",
                        f"{risk_score} / 100"
                    )

                with col2:

                    st.metric(
                        "Risk Level",
                        risk_level
                    )

                with col3:

                    st.metric(
                        "Status",
                        status
                    )


                # =================================================
                # RISK MESSAGE
                # =================================================

                if risk_level == "LOW":

                    st.success(
                        "🟢 SAFE — "
                        "No major risk indicators detected."
                    )

                elif risk_level == "MEDIUM":

                    st.warning(
                        "🟡 SUSPICIOUS — "
                        "Some risk indicators were detected."
                    )

                elif risk_level == "HIGH":

                    st.error(
                        "🔴 DANGEROUS — "
                        "High-risk indicators were detected."
                    )


                # =================================================
                # RISK INDICATORS
                # =================================================

                st.subheader("🔎 Risk Indicators")

                reasons = risk_result.get(
                    "reasons",
                    []
                )

                if reasons:

                    for reason in reasons:

                        st.warning(
                            f"⚠️ {reason}"
                        )

                else:

                    st.success(
                        "✅ No major risk indicators detected."
                    )


                # =================================================
                # FINAL RESULT
                # =================================================

                st.divider()

                st.subheader(
                    "🛡️ TrustLens AI Final Result"
                )

                if status == "SAFE":

                    st.success(
                        "✅ This file appears to be SAFE."
                    )

                elif status == "SUSPICIOUS":

                    st.warning(
                        "⚠️ This file is SUSPICIOUS. "
                        "Review it carefully before opening."
                    )

                else:

                    st.error(
                        "🚨 This file appears DANGEROUS. "
                        "Do not open or execute it without "
                        "further investigation."
                    )


                # =================================================
                # PDF REPORT
                # =================================================

                st.divider()

                st.subheader(
                    "📑 Security Report"
                )

                try:

                    pdf_data = generate_pdf_report(
                        file_result,
                        risk_result
                    )

                    st.success(
                        "✅ PDF security report generated successfully!"
                    )

                    st.download_button(
                        label="📥 Download PDF Report",
                        data=pdf_data,
                        file_name="TrustLens_AI_Report.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )

                except Exception as pdf_error:

                    st.error(
                        f"PDF generation failed: {pdf_error}"
                    )


        except Exception as e:

            st.error(
                f"Unexpected error: {str(e)}"
            )


        finally:

            # ------------------------------------------------
            # Delete temporary file
            # ------------------------------------------------

            if temp_path and os.path.exists(temp_path):

                try:

                    os.remove(temp_path)

                except Exception:

                    pass


# ==========================================================
# FOOTER
# ==========================================================

st.divider()

st.caption(
    "TrustLens AI | File Trust & Risk Analysis System"
)