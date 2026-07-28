"""``sec-guardrails`` command-line entry point.

    sec-guardrails serve [--host H] [--port P]   # run the guardrail gateway in front of Odysseus
    sec-guardrails version                        # print the installed version

Registered via ``[project.scripts]`` in pyproject.toml.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__, build_default_app


def _cmd_version(_: argparse.Namespace) -> int:
    print(__version__)
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ModuleNotFoundError:
        print(
            "uvicorn is required to serve; install with `pip install sec-guardrails`",
            file=sys.stderr,
        )
        return 1

    host = args.host or os.getenv("GATEWAY_HOST", "127.0.0.1")
    port = args.port or int(os.getenv("GATEWAY_PORT", "7100"))
    app = build_default_app(env_fallback=args.env_fallback)
    print(f"[gateway] serving on {host}:{port} -> Odysseus; trace ingest at POST /api/_trace")
    uvicorn.run(app, host=host, port=port, log_level=args.log_level)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sec-guardrails", description=__doc__)
    parser.add_argument("--version", action="version", version=f"sec-guardrails {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser("serve", help="run the guardrail gateway")
    p_serve.add_argument("--host", default=None, help="bind host (default 127.0.0.1)")
    p_serve.add_argument(
        "--port", type=int, default=None, help="bind port (default 7100 / $GATEWAY_PORT)"
    )
    p_serve.add_argument("--env-fallback", default=None, help="path to a fallback .env")
    p_serve.add_argument("--log-level", default="warning", help="uvicorn log level")
    p_serve.set_defaults(func=_cmd_serve)

    p_version = sub.add_parser("version", help="print the installed version")
    p_version.set_defaults(func=_cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):  # Windows cp1252 consoles choke on non-ASCII
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
