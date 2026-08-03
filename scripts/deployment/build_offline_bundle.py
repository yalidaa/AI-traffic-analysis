from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL = ROOT / "checkpoints" / "deep_mineshark_legacy_20260304.pt"
MANIFEST = ROOT / "configs" / "sensor" / "model-manifest.json"
FRONTEND_DIST = ROOT / "web" / "frontend" / "dist"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_tree(source: Path, destination: Path) -> None:
    if destination.exists():
        raise RuntimeError(f"refusing to overwrite existing bundle path: {destination}")
    shutil.copytree(source, destination)


def build_bundle(output: Path, model_path: Path, *, python: str) -> Path:
    if sys.platform != "linux":
        raise RuntimeError("offline bundles must be built on Linux matching the target Ubuntu/Python runtime")
    if output.exists():
        raise RuntimeError(f"refusing to overwrite existing output: {output}")
    if not model_path.is_file():
        raise RuntimeError(f"model checkpoint not found: {model_path}")
    if not MANIFEST.is_file():
        raise RuntimeError(f"model manifest not found: {MANIFEST}")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    actual_model_hash = sha256_file(model_path)
    if actual_model_hash != manifest["checkpoint_sha256"]:
        raise RuntimeError("model checkpoint hash does not match model-manifest.json")
    if not (FRONTEND_DIST / "index.html").is_file():
        raise RuntimeError("web/frontend/dist is missing; run the production frontend build first")

    with tempfile.TemporaryDirectory(prefix="mineshark-bundle-") as tmp:
        staging = Path(tmp) / "mineshark-offline"
        wheels = staging / "wheels"
        wheels.mkdir(parents=True)
        subprocess.run(
            [
                python,
                "-m",
                "pip",
                "wheel",
                "--only-binary=:all:",
                "--extra-index-url",
                "https://download.pytorch.org/whl/cpu",
                "--wheel-dir",
                str(wheels),
                f"{ROOT}[sensor,ml,web]",
            ],
            check=True,
            cwd=ROOT,
        )

        (staging / "models").mkdir()
        shutil.copy2(model_path, staging / "models" / "deep_mineshark_legacy_20260304.pt")
        shutil.copy2(MANIFEST, staging / "models" / "model-manifest.json")
        (staging / "configs").mkdir()
        shutil.copy2(ROOT / "configs" / "sensor" / "sensor.toml", staging / "configs" / "sensor.toml")
        copy_tree(FRONTEND_DIST, staging / "web" / "frontend" / "dist")
        for directory in ("systemd", "wazuh", "nginx", "logrotate"):
            copy_tree(ROOT / "deploy" / directory, staging / directory)
        copy_tree(ROOT / "deploy" / "wsl-lab", staging / "wsl-lab")
        for filename in ("install.sh", "install-console.sh", "uninstall.sh", "console.env.example"):
            shutil.copy2(ROOT / "deploy" / filename, staging / filename)
        copy_tree(ROOT / "docs", staging / "docs")
        copy_tree(ROOT / "scripts" / "deployment", staging / "tools")

        wheel_manifest = {
            "schema_version": 1,
            "python_version": sys.version.split()[0],
            "platform": sys.platform,
            "wheels": [
                {"filename": path.name, "sha256": sha256_file(path)}
                for path in sorted(wheels.glob("*.whl"))
            ],
        }
        (staging / "BUNDLE-MANIFEST.json").write_text(
            json.dumps(wheel_manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        entries = []
        for path in sorted(candidate for candidate in staging.rglob("*") if candidate.is_file()):
            if path.name == "SHA256SUMS":
                continue
            entries.append(f"{sha256_file(path)}  {path.relative_to(staging).as_posix()}")
        (staging / "SHA256SUMS").write_text("\n".join(entries) + "\n", encoding="utf-8")
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(staging, output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a verified MineShark offline deployment directory")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()
    output = build_bundle(args.output.resolve(), args.model.resolve(), python=args.python)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
