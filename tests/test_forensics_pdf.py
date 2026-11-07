from ctf_toolkit.forensics.pdf_tools import extract_pdf_metadata


def test_pdf_metadata_extraction():
    fake_pdf = b"""%PDF-1.4
1 0 obj
<< /Title (Confidential Plan)
   /Author (John\\137Doe\\173Admin\\175)
   /Creator (ReportLab) >>
endobj
trailer
<< /Info 1 0 R >>
%%EOF"""

    meta = extract_pdf_metadata(fake_pdf)
    assert meta["Title"] == "Confidential Plan"
    assert meta["Author"] == "John_Doe{Admin}"
    assert meta["Creator"] == "ReportLab"
