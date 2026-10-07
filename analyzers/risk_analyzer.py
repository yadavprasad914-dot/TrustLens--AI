# TrustLens AI - Improved Risk Analyzer


def calculate_risk(file_result):
    """
    Calculate file risk using multiple static indicators.
    No uploaded file is executed.
    """

    risk_score = 0
    reasons = []

    # -------------------------------------------------
    # Get file information
    # -------------------------------------------------

    file_name = file_result.get("file_name", "")
    extension = file_result.get("extension", "").lower()
    actual_type = file_result.get(
        "actual_type",
        "Unknown"
    )

    mismatch = file_result.get(
        "extension_mismatch",
        False
    )

    size_bytes = file_result.get(
        "size_bytes",
        file_result.get("file_size", 0)
    )

    # -------------------------------------------------
    # 1. Extension mismatch
    # -------------------------------------------------

    if mismatch:
        risk_score += 40

        reasons.append(
            "File extension does not match the actual file type"
        )

    # -------------------------------------------------
    # 2. Suspicious extensions
    # -------------------------------------------------

    suspicious_extensions = [
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".scr",
        ".msi",
        ".js",
        ".jar"
    ]

    if extension in suspicious_extensions:

        risk_score += 25

        reasons.append(
            "Suspicious executable or script file extension"
        )

    # -------------------------------------------------
    # 3. Executable actual file type
    # -------------------------------------------------

    if actual_type == "EXE/DLL":

        risk_score += 20

        reasons.append(
            "File contains an executable Windows PE format"
        )

    # -------------------------------------------------
    # 4. Unknown file type
    # -------------------------------------------------

    if actual_type == "Unknown":

        risk_score += 10

        reasons.append(
            "Actual file type could not be identified"
        )

    # -------------------------------------------------
    # 5. Script file
    # -------------------------------------------------

    script_extensions = [
        ".py",
        ".js",
        ".vbs",
        ".ps1",
        ".bat",
        ".cmd"
    ]

    if extension in script_extensions:

        risk_score += 10

        reasons.append(
            "Script file can contain executable commands"
        )

    # -------------------------------------------------
    # 6. Archive files
    # -------------------------------------------------

    archive_extensions = [
        ".zip",
        ".rar",
        ".7z",
        ".gz"
    ]

    if extension in archive_extensions:

        risk_score += 5

        reasons.append(
            "Archive file may contain multiple embedded files"
        )

    # -------------------------------------------------
    # 7. Double extension detection
    # Example:
    # invoice.pdf.exe
    # photo.jpg.scr
    # -------------------------------------------------

    lower_name = file_name.lower()

    dangerous_patterns = [
        ".pdf.exe",
        ".doc.exe",
        ".docx.exe",
        ".xls.exe",
        ".xlsx.exe",
        ".jpg.exe",
        ".jpeg.exe",
        ".png.exe",
        ".txt.exe",
        ".pdf.scr",
        ".jpg.scr",
        ".docx.scr"
    ]

    for pattern in dangerous_patterns:

        if lower_name.endswith(pattern):

            risk_score += 20

            reasons.append(
                "Multiple file extensions may hide the real file type"
            )

            break

    # -------------------------------------------------
    # 8. Very large file
    # -------------------------------------------------

    if size_bytes > 100 * 1024 * 1024:

        risk_score += 5

        reasons.append(
            "File size is larger than 100 MB"
        )

    # -------------------------------------------------
    # 9. Empty file
    # -------------------------------------------------

    if size_bytes == 0:

        reasons.append(
            "File size is 0 KB"
        )

    # -------------------------------------------------
    # 10. Safe common file types
    # -------------------------------------------------

    safe_extensions = [
        ".txt",
        ".csv",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif"
    ]

    if (
        extension in safe_extensions
        and not mismatch
        and actual_type != "Unknown"
    ):

        # Reduce unnecessary risk for correctly
        # identified common files.

        risk_score = max(
            0,
            risk_score - 5
        )

    # -------------------------------------------------
    # Limit score
    # -------------------------------------------------

    risk_score = min(
        risk_score,
        100
    )

    # -------------------------------------------------
    # Determine risk level
    # -------------------------------------------------

    if risk_score >= 60:

        risk_level = "HIGH"
        status = "DANGEROUS"

    elif risk_score >= 30:

        risk_level = "MEDIUM"
        status = "SUSPICIOUS"

    else:

        risk_level = "LOW"
        status = "SAFE"

    # -------------------------------------------------
    # Remove duplicate reasons
    # -------------------------------------------------

    reasons = list(
        dict.fromkeys(reasons)
    )

    # -------------------------------------------------
    # Return result
    # -------------------------------------------------

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "status": status,
        "reasons": reasons
    }


# -----------------------------------------------------
# Test Risk Analyzer
# -----------------------------------------------------

if __name__ == "__main__":

    print()
    print("======================================")
    print("      TrustLens AI Risk Analyzer")
    print("======================================")

    # Test file
    sample_result = {

        "file_name": "invoice.pdf.exe",

        "extension": ".exe",

        "actual_type": "TEXT/CSV",

        "extension_mismatch": True,

        "size_bytes": 0
    }

    # Calculate risk
    result = calculate_risk(
        sample_result
    )

    print()

    print(
        "File Name   :",
        sample_result["file_name"]
    )

    print(
        "Extension   :",
        sample_result["extension"]
    )

    print(
        "Actual Type :",
        sample_result["actual_type"]
    )

    print()

    print(
        "Risk Score  :",
        result["risk_score"],
        "/ 100"
    )

    print(
        "Risk Level  :",
        result["risk_level"]
    )

    print(
        "Status      :",
        result["status"]
    )

    print()

    print("Risk Reasons:")

    if result["reasons"]:

        for reason in result["reasons"]:

            print(
                "-",
                reason
            )

    else:

        print(
            "- No major risk indicators detected"
        )

    print()
    print("======================================")