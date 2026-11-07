from ctf_toolkit.osint_misc.config_hunter import extract_tsv_secrets


def test_extract_tsv_secrets() -> None:
    sample_tsv = (
        "timestamp\tlevel\tmessage\n"
        "1001\tINFO\tsystem startup completed\n"
        "1002\tWARN\ttoken leak detected: GETSFLAG{mca_tsv_cell}\n"
        "1003\tINFO\tservice shutting down\n"
    )
    secrets = extract_tsv_secrets(sample_tsv)
    assert len(secrets) == 1
    assert secrets[0]["secret"] == "GETSFLAG{mca_tsv_cell}"
    assert secrets[0]["header"] == "message"
    assert secrets[0]["row"] == "2"
    assert secrets[0]["col"] == "2"


def test_extract_tsv_no_secrets() -> None:
    clean_tsv = "id\tusername\trole\n1\talice\tadmin\n2\tbob\tuser\n"
    secrets = extract_tsv_secrets(clean_tsv)
    assert secrets == []


def test_extract_tsv_empty() -> None:
    assert extract_tsv_secrets("") == []
