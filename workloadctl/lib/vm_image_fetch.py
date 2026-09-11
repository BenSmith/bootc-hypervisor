"""A cloud image, fetched and verified: the checksum, the cache, the download.

The URL is anything urllib handles, file:// included, and every source goes
through the same checksum and the same per-workload cache. A cached copy
whose checksum no longer matches is replaced, not trusted.
"""
import hashlib
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from helper_main import log


def verify_checksum(path: Path, checksum_spec: str):
    """Verify file checksum. checksum_spec format: 'sha256:<hex>'."""
    algo, _, expected = checksum_spec.partition(":")
    if algo != "sha256":
        raise ValueError(f"Unsupported checksum algorithm: {algo!r} (only sha256 supported)")
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    actual = h.hexdigest()
    if actual != expected.lower():
        raise ValueError(
            f"Checksum mismatch for {path.name}:\n"
            f"  expected: {expected.lower()}\n"
            f"  actual:   {actual}"
        )
    log(f"  Checksum verified (sha256:{actual[:12]}...)")


def download_cloud_image(url: str, checksum: str, home_dir: Path) -> Path:
    """Download a cloud image, verify its checksum, return path to the qcow2."""
    cache_dir = home_dir / ".image-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    filename = url.split("/")[-1].split("?")[0] or "cloud-image.qcow2"
    cached = cache_dir / filename

    if cached.exists():
        log(f"  Cached image found: {cached.name}")
        try:
            verify_checksum(cached, checksum)
            return cached
        except ValueError:
            log("  Cached image checksum invalid; re-downloading")
            cached.unlink()

    log(f"  Downloading {url}")
    # Bind tmp_path before the try so the except handler can clean it up
    # even when urlopen fails before the inner tempfile is created.
    tmp_path: Path | None = None
    try:
        with urllib.request.urlopen(url, timeout=300) as resp:
            # resp.headers is the one accessor every urlopen result carries.
            # getheader() belongs to HTTPResponse only: a file:// URL yields an
            # addinfourl, whose attribute lookup falls through to the wrapped
            # BufferedReader, so resp.getheader raises AttributeError and takes
            # the whole build down. Content-Length is set for file:// too.
            # The value only drives a progress percentage, so a missing or
            # malformed one degrades to "no percentage" rather than failing.
            try:
                total = int(resp.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                total = 0
            downloaded = 0
            with tempfile.NamedTemporaryFile(dir=cache_dir, delete=False, suffix=".tmp") as tmp:
                tmp_path = Path(tmp.name)
                while chunk := resp.read(1 << 20):
                    tmp.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = downloaded * 100 // total
                        print(f"\r  Downloaded {downloaded // (1 << 20)}M / {total // (1 << 20)}M ({pct}%)",
                              end="", flush=True)
        print()
    except urllib.error.URLError as e:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)
        raise RuntimeError(f"Download failed: {e}") from e

    verify_checksum(tmp_path, checksum)
    tmp_path.rename(cached)
    log(f"  Saved to {cached.name}")
    return cached
