#!/usr/bin/env python3
"""Build deterministic skill ZIP, checksums, and CycloneDX file SBOM."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skill" / "review-software-security"
DIST = ROOT / "dist"
EPOCH = (1980, 1, 1, 0, 0, 0)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def files_to_package() -> list[Path]:
    files: list[Path] = []
    for path in sorted(SKILL.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"symlinks are not permitted in releases: {path}")
        if path.is_file() and "__pycache__" not in path.parts and not path.name.endswith((".pyc", ".pyo")):
            files.append(path)
    if not files:
        raise ValueError("skill directory is empty")
    return files


def build_zip(version: str, files: list[Path]) -> Path:
    output = DIST / f"review-software-security-v{version}.zip"
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            relative = path.relative_to(SKILL)
            info = zipfile.ZipInfo(str(Path("review-software-security") / relative), EPOCH)
            mode = 0o755 if path.name.endswith(".py") else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.create_system = 3
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return output


def build_sbom(version: str, files: list[Path]) -> Path:
    components = []
    for path in files:
        relative = path.relative_to(SKILL).as_posix()
        components.append(
            {
                "type": "file",
                "name": relative,
                "bom-ref": f"file:{relative}",
                "hashes": [{"alg": "SHA-256", "content": sha256(path)}],
            }
        )
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:00000000-0000-4000-8000-{version.replace('.', '').ljust(12, '0')[:12]}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "review-software-security",
                "version": version,
                "bom-ref": f"pkg:github/AI-Jerry/review-software-security@v{version}",
                "purl": f"pkg:github/AI-Jerry/review-software-security@v{version}",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            }
        },
        "components": components,
    }
    output = DIST / f"review-software-security-v{version}.cdx.json"
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", args.version):
        parser.error("--version must be a SemVer core such as 0.1.0")

    DIST.mkdir(exist_ok=True)
    files = files_to_package()
    zip_path = build_zip(args.version, files)
    sbom_path = build_sbom(args.version, files)
    checksums = DIST / "SHA256SUMS"
    checksums.write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in (zip_path, sbom_path)),
        encoding="utf-8",
    )
    print(f"built: {zip_path.relative_to(ROOT)}")
    print(f"built: {sbom_path.relative_to(ROOT)}")
    print(f"built: {checksums.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
