from ctf_toolkit.osint_misc.config_hunter import (
    extract_json_secrets,
    extract_yaml_secrets,
    find_nested_secrets,
)


def test_find_nested_secrets() -> None:
    data = {
        "app": {"name": "demo"},
        "database": {
            "config": {
                "admin_password": "super_secret_pass",
                "hosts": ["10.0.0.1", "10.0.0.2"],
            }
        },
    }
    findings = find_nested_secrets(data)
    assert any("admin_password" in path and "super_secret_pass" in val for path, val in findings)


def test_extract_yaml_secrets() -> None:
    yaml_doc = """
    service: auth
    env: prod
    secrets:
      api_key: "GETSFLAG{yaml_hunter_test}"
    """
    findings = extract_yaml_secrets(yaml_doc)
    flags = [val for _, val in findings if "GETSFLAG" in val]
    assert "GETSFLAG{yaml_hunter_test}" in flags


def test_extract_json_secrets() -> None:
    json_doc = """
    {
      "config": {
        "db": {
          "pool": {
            "creds": {
              "secret": "GETSFLAG{json_hunter_test}"
            }
          }
        }
      }
    }
    """
    findings = extract_json_secrets(json_doc)
    flags = [val for _, val in findings if "GETSFLAG" in val]
    assert "GETSFLAG{json_hunter_test}" in flags
