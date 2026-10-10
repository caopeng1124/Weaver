"""Run a real Weaver instance and Promptfoo in disposable, isolated test storage."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import httpx
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[2]
EVAL_DIR = Path(__file__).resolve().parent


def serve():
    # The fallback memory store ignores WEAVER_DATA_DIR; redirect only storage,
    # before importing main. All real security/model/tool code remains enabled.
    from tools.core import memory_client

    data = Path(os.environ["WEAVER_DATA_DIR"])
    memory_client._fallback_path = data / "memory_store.json"
    memory_client._legacy_fallback_path = data / "legacy_memory_store.json"
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=int(os.environ["PORT"]), log_level="warning")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--filter", help="Run cases matching this description regex")
    parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="Connect directly instead of using environment/system proxies",
    )
    args = parser.parse_args()
    if args.serve:
        serve()
        return 0
    cli = EVAL_DIR / "node_modules" / ".bin" / "promptfoo"
    if not cli.exists():
        parser.error("Install dependencies first: npm ci --prefix evals/promptfoo")
    # Copy only model connection settings from .env, never the full production config.
    source = {**os.environ, **dotenv_values(ROOT / ".env")}
    model_keys = (
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_EXTRA_BODY",
        "USE_AZURE",
        "AZURE_API_KEY",
        "AZURE_ENDPOINT",
        "AZURE_API_VERSION",
        "PRIMARY_MODEL",
        "REASONING_MODEL",
    )
    if not source.get("OPENAI_API_KEY"):
        parser.error("OPENAI_API_KEY must be configured in .env or the process environment")
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)
    runtime = ROOT / ".cache" / "promptfoo" / run_id
    workspace = runtime / "workspace"
    workspace.mkdir(parents=True)
    (runtime / "data").mkdir()
    (workspace / "note.txt").write_text("before\n")
    (runtime / "outside-note.txt").write_text("before\n")
    results = EVAL_DIR / "results" / run_id
    results.mkdir(parents=True)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = dict(os.environ)
    # httpx/Node do not automatically inherit macOS system proxy preferences.
    if args.no_proxy:
        for key in list(env):
            if key.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}:
                env.pop(key)
    else:
        for scheme, proxy in urllib.request.getproxies().items():
            if scheme in {"http", "https"}:
                env.setdefault(f"{scheme.upper()}_PROXY", proxy)
    env["NO_PROXY"] = ",".join(filter(None, [env.get("NO_PROXY", ""), "127.0.0.1", "localhost"]))
    env.update({key: str(source[key]) for key in model_keys if source.get(key) is not None})
    env.update(
        {
            "PYTHONPATH": str(ROOT),
            "PYTHONUNBUFFERED": "1",
            "APP_ENV": "production",
            "DEBUG": "false",
            "PORT": str(port),
            "WEAVER_BASE_URL": f"http://127.0.0.1:{port}",
            "WEAVER_INTERNAL_API_KEY": secrets.token_urlsafe(32),
            "WEAVER_DATA_DIR": str(runtime / "data"),
            "WEAVER_TEST_WORKSPACE": str(workspace),
            "SECURITY_ENABLED": "true",
            "SECURITY_WORKSPACE": str(workspace),
            "SECURITY_STORE_PATH": str(runtime / "data" / "security.sqlite3"),
            "SECURITY_MCP_TOOLS": "{}",
            "SECURITY_PRINCIPAL_POLICIES": "{}",
            "SECURITY_ADMIN_PRINCIPALS": "",
            "ENABLE_MCP": "false",
            "MCP_SERVERS": "{}",
            "ENABLE_MEMORY": "false",
            "MEMORY_STORE_BACKEND": "memory",
            "MEMORY_STORE_URL": "",
            "DATABASE_URL": "",
            "RAG_ENABLED": "false",
            "RAG_PERMISSIONS_PATH": str(runtime / "data" / "rag.sqlite3"),
            "SANDBOX_MODE": "docker",
            "SANDBOX_STATE_DIR": str(runtime / "sandbox"),
            "SANDBOX_ALLOW_INTERNET": "false",
            "ENABLE_TRACING": "false",
            "LANGCHAIN_TRACING_V2": "false",
            "LANGSMITH_TRACING": "false",
            "RATE_LIMIT_ENABLED": "false",
            "LOG_LEVEL": "WARNING",
            "LOG_FORMAT": "%(asctime)s %(levelname)s %(message)s",
            "ENABLE_FILE_LOGGING": "false",
            "OPENAI_TIMEOUT": "40",
            "TOOL_RETRY": "false",
            "TOOL_CALL_LIMIT": "4",
            "PROMPTFOO_PYTHON": sys.executable,
            "PROMPTFOO_CONFIG_DIR": str(runtime / ".promptfoo"),
            "PROMPTFOO_DISABLE_TELEMETRY": "1",
            "PROMPTFOO_DISABLE_UPDATE": "1",
            "PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION": "true",
        }
    )
    manifest = {
        "run_id": run_id,
        "model": env.get("PRIMARY_MODEL", "deepseek-chat"),
        "filter": args.filter,
        "proxy_mode": "direct" if args.no_proxy else "environment/system",
        "runtime": str(runtime),
        "results": str(results),
        "scope": "10 fixed cases: controls, DLP, approval, workspace boundary; no generated redteam",
    }
    (results / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
    print(f"Results: {results}", flush=True)
    with (results / "server.log").open("w") as log:
        server = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--serve"],
            cwd=runtime,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            with httpx.Client(timeout=2, trust_env=False) as client:
                for _ in range(120):
                    if server.poll() is not None:
                        raise RuntimeError("Weaver failed to start; inspect results/server.log")
                    try:
                        if client.get(f"{env['WEAVER_BASE_URL']}/health").status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(0.5)
                else:
                    raise RuntimeError("Weaver health check timed out")
            command = [
                str(cli),
                "eval",
                "-c",
                "promptfooconfig.yaml",
                "--no-cache",
                "--no-write",
                "--no-progress-bar",
                "--no-table",
                "--max-concurrency",
                "1",
                "-o",
                str(results / "report.json"),
                "-o",
                str(results / "report.html"),
            ]
            if args.filter:
                command.extend(["--filter-pattern", args.filter])
            with (results / "promptfoo.log").open("w") as eval_log:
                eval_env = {**env, "LOG_LEVEL": "info"}
                evaluation = subprocess.Popen(
                    command,
                    cwd=EVAL_DIR,
                    env=eval_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                try:
                    for line in evaluation.stdout:
                        print(line, end="", flush=True)
                        eval_log.write(line)
                        eval_log.flush()
                    return evaluation.wait()
                finally:
                    if evaluation.poll() is None:
                        evaluation.terminate()
                        evaluation.wait(timeout=10)
        finally:
            server.terminate()
            try:
                server.wait(timeout=15)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


if __name__ == "__main__":
    raise SystemExit(main())
