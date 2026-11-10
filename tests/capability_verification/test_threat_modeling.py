"""Threat Modeling verification."""

def test_stride_coverage():
    stride_categories = ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"]
    covered = ["Spoofing", "Tampering", "Information Disclosure"]
    missing = [c for c in stride_categories if c not in covered]
    assert len(missing) > 0
    assert "Denial of Service" in missing

def test_gap_analysis():
    findings = ["SQLi", "XSS"]
    threats = ["SQLi", "XSS", "IDOR"]
    gaps = [t for t in threats if t not in findings]
    assert "IDOR" in gaps
