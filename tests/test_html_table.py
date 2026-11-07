from ctf_toolkit.osint_misc.config_hunter import extract_html_table_secrets


def test_extract_html_table_secrets() -> None:
    html = """
    <html>
      <body>
        <h2>Audit Report</h2>
        <table>
          <tr><th>ID</th><th>User</th><th>Note</th></tr>
          <tr><td>1</td><td>Admin</td><td>Normal operation</td></tr>
          <tr><td>2</td><td>Operator</td><td>Found flag: GETSFLAG{mca_html_table}</td></tr>
        </table>
      </body>
    </html>
    """
    secrets = extract_html_table_secrets(html)
    assert len(secrets) == 1
    assert secrets[0]["secret"] == "GETSFLAG{mca_html_table}"
    assert secrets[0]["row"] == "2"
    assert secrets[0]["col"] == "2"


def test_extract_html_table_empty() -> None:
    assert extract_html_table_secrets("<div>No table here</div>") == []
