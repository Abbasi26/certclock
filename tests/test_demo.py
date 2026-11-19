from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_demo_runs_twice_in_same_dir(tmp_path: Path) -> None:
    """Regression test: running demo twice into the same directory should work."""
    out_dir = tmp_path / "certclock-demo"
    
    # First run
    result1 = subprocess.run(
        [sys.executable, "-m", "certclock", "demo", "--out", str(out_dir), "--offline"],
        capture_output=True,
        text=True,
    )
    assert result1.returncode == 0, f"First run failed: {result1.stderr}"
    assert out_dir.exists()
    assert (out_dir / "index.html").exists()
    
    # Second run into the same directory (simulates dirty re-run)
    result2 = subprocess.run(
        [sys.executable, "-m", "certclock", "demo", "--out", str(out_dir), "--offline"],
        capture_output=True,
        text=True,
    )
    assert result2.returncode == 0, f"Second run failed: {result2.stderr}"
    assert (out_dir / "index.html").exists()
    
    # Verify the output is valid
    html_content = (out_dir / "index.html").read_text()
    assert "CertClock" in html_content
    assert "example.test" in html_content

