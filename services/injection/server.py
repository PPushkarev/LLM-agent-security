"""Local binary classifier, not an instruction-following/chat model.

No request logging, no external inference API, no model-supplied Python code.
All tokenizer overflow windows must be evaluated before issuing a verdict.
"""
import argparse
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer
from model_spec import MODEL_FILES, MODEL_ID


class Classifier:
    def __init__(self, model_dir, window=1024, overlap=128, max_windows=256):
        if not 128 <= window <= 2048 or not 0 < overlap < window:
            raise ValueError("invalid tokenizer window/overlap")
        manifest = json.loads((model_dir / "model.lock.json").read_text())
        if manifest.get("model") != MODEL_ID:
            raise ValueError("unexpected model identity")
        for name in MODEL_FILES:
            digest = hashlib.sha256()
            with open(model_dir / name, "rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            if digest.hexdigest() != manifest["files"].get(name):
                raise ValueError(f"model integrity check failed: {name}")
        config = json.loads((model_dir / "config.json").read_text())
        if config["id2label"] != {"0": "SAFE", "1": "INJECTION"}:
            raise ValueError("unexpected classifier label mapping")
        self.tokenizer = Tokenizer.from_file(str(model_dir / "tokenizer.json"))
        self.tokenizer.enable_truncation(max_length=window, stride=overlap)
        self.tokenizer.no_padding()
        options = ort.SessionOptions()
        options.intra_op_num_threads = min(os.cpu_count() or 1, 4)
        options.inter_op_num_threads = 1
        self.session = ort.InferenceSession(str(model_dir / "onnx/model_quantized.onnx"),
                                            sess_options=options,
                                            providers=["CPUExecutionProvider"])
        self.input_names = {node.name for node in self.session.get_inputs()}
        if not self.input_names <= {"input_ids", "attention_mask", "token_type_ids", "position_ids"}:
            raise ValueError("unsupported ONNX inputs")
        self.max_windows = max_windows

    def score(self, text, timeout=20):
        deadline = time.monotonic() + timeout
        encoding = self.tokenizer.encode(text)
        windows = [encoding, *encoding.overflowing]
        if len(windows) > self.max_windows:
            raise ValueError("too_many_windows")
        scores = []
        for window in windows:
            if time.monotonic() > deadline:
                raise TimeoutError("classifier_timeout")
            length = len(window.ids)
            values = {
                "input_ids": np.array([window.ids], dtype=np.int64),
                "attention_mask": np.array([window.attention_mask], dtype=np.int64),
                "token_type_ids": np.array([window.type_ids], dtype=np.int64),
                "position_ids": np.arange(length, dtype=np.int64)[None, :],
            }
            logits = np.asarray(self.session.run(None, {
                name: values[name] for name in self.input_names})[0], dtype=np.float64)
            if logits.shape != (1, 2) or not np.isfinite(logits).all():
                raise ValueError("invalid_model_logits")
            logits -= logits.max(axis=-1, keepdims=True)
            probabilities = np.exp(logits)
            probabilities /= probabilities.sum(axis=-1, keepdims=True)
            scores.append(float(probabilities[0, 1]))
        if time.monotonic() > deadline:
            raise TimeoutError("classifier_timeout")
        score = max(scores)
        if not math.isfinite(score):
            raise ValueError("invalid_model_score")
        return score, len(windows)


def make_handler(classifier, token):
    busy = threading.BoundedSemaphore(1)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # Prompts, headers, paths and tokens never enter access logs.

        def setup(self):
            super().setup()
            self.connection.settimeout(30)

        def reply(self, code, value):
            data = json.dumps(value, allow_nan=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def authenticated(self):
            return hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + token)

        def do_GET(self):
            if not self.authenticated():
                return self.reply(401, {"error": "unauthorized"})
            if self.path != "/health":
                return self.reply(404, {"error": "not_found"})
            self.reply(200, {"ready": True, "model": MODEL_ID})

        def do_POST(self):
            if not self.authenticated():
                return self.reply(401, {"error": "unauthorized"})
            if self.path != "/scan":
                return self.reply(404, {"error": "not_found"})
            if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Encoding"):
                return self.reply(400, {"error": "unsupported_encoding"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self.reply(400, {"error": "invalid_length"})
            if not 0 < length <= 8 * 1024 * 1024:
                return self.reply(413, {"error": "body_limit"})
            if not busy.acquire(blocking=False):
                return self.reply(503, {"error": "classifier_busy"})
            try:
                data = json.loads(self.rfile.read(length))
                if set(data) != {"id", "source", "text"} or not all(isinstance(v, str) for v in data.values()):
                    raise ValueError("invalid_request")
                text = data["text"]
                count = len(text.encode("utf-8"))
                if count > 1024 * 1024 or not 1 <= len(data["id"]) <= 128:
                    return self.reply(413, {"error": "text_limit"})
                score, windows = classifier.score(text)
                self.reply(200, {"id": data["id"], "model": MODEL_ID,
                                 "injection_score": score, "complete": True,
                                 "scanned_bytes": count, "windows": windows})
            except (ValueError, KeyError, TypeError, TimeoutError, socket.timeout):
                self.reply(422, {"error": "classification_incomplete"})
            except Exception:
                self.reply(503, {"error": "classification_failed"})
            finally:
                busy.release()

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", required=True, type=Path)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    if args.token_file.is_symlink() or args.token_file.stat().st_mode & 0o077:
        raise ValueError("token file must be private and not a symlink")
    token = args.token_file.read_text().strip()
    if len(token) < 32 or len(token) > 512 or not token.isascii():
        raise ValueError("invalid classifier token")
    classifier = Classifier(args.model_dir)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(classifier, token))
    server.daemon_threads = True
    print(f"Prompt injection classifier ready on 127.0.0.1:{args.port}: {MODEL_ID}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
