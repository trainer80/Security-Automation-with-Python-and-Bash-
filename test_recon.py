import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import recon_pipeline as rp  # noqa: E402


def test_valid_targets():
    assert rp.is_valid_target("example.com")
    assert rp.is_valid_target("sub.example.co.in")
    assert rp.is_valid_target("127.0.0.1")
    assert rp.is_valid_target("localhost")


def test_invalid_targets_rejected():
    assert not rp.is_valid_target("http://example.com")
    assert not rp.is_valid_target("example.com; rm -rf /")
    assert not rp.is_valid_target("")
    assert not rp.is_valid_target("-oN evil")


def test_in_scope_exact_and_subdomain():
    scope = {"example.com"}
    assert rp.in_scope("example.com", scope)
    assert rp.in_scope("api.example.com", scope)


def test_out_of_scope_lookalike_domain():
    assert not rp.in_scope("evilexample.com", {"example.com"})
    assert not rp.in_scope("example.com.evil.io", {"example.com"})


def test_load_scope_ignores_comments(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("# comment\nExample.com  # trailing\n\nlocalhost\n")
    assert rp.load_scope(f) == {"example.com", "localhost"}


def test_refuses_without_permission_flag(tmp_path, capsys):
    f = tmp_path / "scope.txt"
    f.write_text("example.com\n")
    code = rp.main(["-t", "example.com", "-s", str(f)])
    assert code == 2
    assert "Refusing" in capsys.readouterr().out


def test_refuses_target_not_in_scope(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("example.com\n")
    assert rp.main(["-t", "other.com", "-s", str(f), "--i-have-permission"]) == 2


def test_dry_run_runs_nothing(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("example.com\n")
    assert rp.main(["-t", "example.com", "-s", str(f), "--i-have-permission", "--dry-run"]) == 0


def test_pipeline_with_mocked_tools(tmp_path, monkeypatch):
    monkeypatch.setattr(rp, "find_subdomains", lambda t: [t, "www." + t])
    monkeypatch.setattr(rp, "find_live_hosts", lambda hosts: ["https://www.example.com"])
    monkeypatch.setattr(rp, "scan_ports", lambda h: ["443/tcp open https"])
    monkeypatch.setattr(rp, "scan_vulnerabilities", lambda u: ["[medium] sample-finding"])
    results = rp.pipeline("example.com", tmp_path)
    assert results["live_hosts"] == ["https://www.example.com"]
    assert results["open_ports"]["www.example.com"] == ["443/tcp open https"]
    assert len(list(tmp_path.glob("*.json"))) == 1
    assert len(list(tmp_path.glob("*.md"))) == 1
