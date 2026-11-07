import json

import pytest

from app.services.ingestion import parse_upload


def test_csv_parser_keeps_header_fields():
    assert parse_upload(
        "scanner", "scanner.csv", b"host,cve\nweb01,CVE-2024-1000\n"
    ) == [{"host": "web01", "cve": "CVE-2024-1000"}]


def test_json_parser_accepts_wrapped_items():
    assert parse_upload(
        "cspm", "findings.json", json.dumps({"items": [{"asset": "a"}]}).encode()
    ) == [{"asset": "a"}]


@pytest.mark.parametrize("filename,content", [("bad.exe", b"x"), ("empty.csv", b"")])
def test_upload_rejects_unsupported_or_empty_files(filename, content):
    with pytest.raises(ValueError):
        parse_upload("scanner", filename, content)
