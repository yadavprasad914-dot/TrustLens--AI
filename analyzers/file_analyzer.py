# TrustLens AI - File Analyzer

import hashlib
import zipfile
from pathlib import Path


# ---------------------------------------------------------
# 1. Calculate SHA-256 Hash
# ---------------------------------------------------------

def calculate_hash(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


# ---------------------------------------------------------
# 2. Detect Actual File Type
# ---------------------------------------------------------

def detect_file_type(file_path):

    with open(file_path, "rb") as file:
        header = file.read(32)

    # PDF
    if header.startswith(b"%PDF"):
        return "PDF"

    # Windows EXE / DLL
    if header.startswith(b"MZ"):
        return "EXE/DLL"

    # PNG
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"

    # JPG / JPEG
    if header.startswith(b"\xff\xd8\xff"):
        return "JPG/JPEG"

    # GIF
    if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
        return "GIF"

    # ZIP based formats
    if header.startswith(b"PK"):

        try:

            with zipfile.ZipFile(file_path, "r") as zip_file:

                names = zip_file.namelist()

                # DOCX
                if any(
                    name.startswith("word/")
                    for name in names
                ):
                    return "DOCX"

                # XLSX
                if any(
                    name.startswith("xl/")
                    for name in names
                ):
                    return "XLSX"

                # PPTX
                if any(
                    name.startswith("ppt/")
                    for name in names
                ):
                    return "PPTX"

                return "ZIP"

        except Exception:
            return "ZIP"

    # RAR
    if header.startswith(b"Rar!"):
        return "RAR"

    # 7-Zip
    if header.startswith(
        b"\x37\x7a\xbc\xaf\x27\x1c"
    ):
        return "7Z"

    # Text / CSV
    try:

        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            sample = file.read(1000)

        if sample.strip():

            # CSV detection
            first_line = sample.splitlines()[0]

            if "," in first_line:
                return "TEXT/CSV"

            return "TEXT"

    except Exception:
        pass

    return "Unknown"


# ---------------------------------------------------------
# 3. Get File Extension
# ---------------------------------------------------------

def get_extension(file_path):

    extension = Path(file_path).suffix.lower()

    if extension:
        return extension

    return "No Extension"


# ---------------------------------------------------------
# 4. Check Extension Mismatch
# ---------------------------------------------------------

def check_extension_mismatch(
    extension,
    actual_type
):

    # Normal extension mapping

    valid_extensions = {

        ".pdf": ["PDF"],

        ".txt": [
            "TEXT",
            "TEXT/CSV"
        ],

        ".csv": [
            "TEXT/CSV",
            "TEXT"
        ],

        ".png": ["PNG"],

        ".jpg": ["JPG/JPEG"],

        ".jpeg": ["JPG/JPEG"],

        ".gif": ["GIF"],

        ".zip": ["ZIP"],

        ".rar": ["RAR"],

        ".7z": ["7Z"],

        ".docx": ["DOCX"],

        ".xlsx": ["XLSX"],

        ".pptx": ["PPTX"],

        ".exe": ["EXE/DLL"],

        ".dll": ["EXE/DLL"]
    }

    # Unknown actual type
    if actual_type == "Unknown":
        return True

    # Extension not available
    if extension not in valid_extensions:
        return True

    # Check actual type
    if actual_type not in valid_extensions[extension]:
        return True

    return False


# ---------------------------------------------------------
# 5. Analyze Complete File
# ---------------------------------------------------------

def analyze_file(file_path):

    try:

        path = Path(file_path)

        # Check file exists
        if not path.exists():

            return {
                "error": "File does not exist"
            }

        # Basic information
        file_name = path.name

        extension = get_extension(
            file_path
        )

        file_size = path.stat().st_size

        # Detect actual type
        actual_type = detect_file_type(
            file_path
        )

        # SHA-256
        file_hash = calculate_hash(
            file_path
        )

        # Extension mismatch
        extension_mismatch = (
            check_extension_mismatch(
                extension,
                actual_type
            )
        )

        # Final result
        result = {

            "file_name": file_name,

            "extension": extension,

            "file_size": file_size,

            "actual_type": actual_type,

            "extension_mismatch":
                extension_mismatch,

            "sha256": file_hash
        }

        return result

    except Exception as e:

        return {
            "error": str(e)
        }


# ---------------------------------------------------------
# 6. Test Program
# ---------------------------------------------------------

if __name__ == "__main__":

    print()
    print("======================================")
    print("       TrustLens AI File Analyzer")
    print("======================================")

    test_file = "dataset/sample.txt"

    result = analyze_file(
        test_file
    )

    if "error" in result:

        print()
        print(
            "Error:",
            result["error"]
        )

    else:

        print()
        print(
            "File Name:",
            result["file_name"]
        )

        print(
            "Extension:",
            result["extension"]
        )

        print(
            "File Size:",
            result["file_size"],
            "bytes"
        )

        print(
            "Actual Type:",
            result["actual_type"]
        )

        print(
            "Extension Mismatch:",
            result["extension_mismatch"]
        )

        print(
            "SHA-256:",
            result["sha256"]
        )

    print()
    print("======================================")