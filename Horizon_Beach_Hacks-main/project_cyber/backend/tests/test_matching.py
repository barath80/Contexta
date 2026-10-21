"""Version-aware CVE/software matching."""

import pytest

from app.services.software_matcher import installed_version, match_asset_versioned, version_verdict

NGINX_RANGES = [{"product": "f5:nginx", "exact": None, "start_incl": "0.6.18", "end_excl": "1.20.1"}]


@pytest.mark.parametrize("text,expected", [
    ("Apache Log4j 2.14.1", "2.14.1"), ("nginx 1.18.0", "1.18.0"), ("PostgreSQL 15", "15"), ("OpenSSL v3.0.2", "3.0.2"), ("Redis", None)])
def test_installed_version(text, expected):
    assert installed_version(text) == expected


@pytest.mark.parametrize("installed,verdict", [
    ("nginx 1.18.0", "affected"), ("nginx 1.20.0", "affected"), ("nginx 1.20.1", "not_affected"),
    ("nginx 1.25.3", "not_affected"), ("nginx 0.5.0", "not_affected"), ("nginx", "unknown")])
def test_range_verdicts(installed, verdict):
    assert version_verdict("f5:nginx", NGINX_RANGES, installed) == verdict


def test_exact_version_and_no_data():
    exact = [{"product": "vendor:app", "exact": "2.1"}]
    assert version_verdict("vendor:app", exact, "app 2.1.5") == "affected"
    assert version_verdict("vendor:app", exact, "app 3.0") == "not_affected"
    assert version_verdict("vendor:app", [], "app 3.0") == "unknown"  # no NVD data: never silently dropped


def test_patched_software_is_not_matched_but_unverifiable_is_kept():
    kept = match_asset_versioned(["f5:nginx"], NGINX_RANGES, ["nginx 1.18.0"])
    assert kept and "confirmed" in kept[0].reason
    assert match_asset_versioned(["f5:nginx"], NGINX_RANGES, ["nginx 1.25.3"]) == []
    unverified = match_asset_versioned(["f5:nginx"], [], ["nginx 1.25.3"])
    assert unverified and "not verified" in unverified[0].reason
