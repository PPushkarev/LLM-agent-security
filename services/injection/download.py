"""Explicit setup only. Download immutable ONNX/JSON artifacts, never model code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from huggingface_hub import snapshot_download
from model_spec import MODEL_FILES, MODEL_ID, MODEL_REPO, MODEL_REVISION


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", required=True, type=Path)
    args = parser.parse_args()
    args.model_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    snapshot_download(MODEL_REPO, revision=MODEL_REVISION, local_dir=args.model_dir,
                      allow_patterns=list(MODEL_FILES))
    manifest = {"model": MODEL_ID, "files": {
        name: sha256(args.model_dir / name) for name in MODEL_FILES}}
    temporary = args.model_dir / "model.lock.tmp"
    temporary.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    os.replace(temporary, args.model_dir / "model.lock.json")
    print(f"Model ready: {MODEL_ID}")


if __name__ == "__main__":
    main()
