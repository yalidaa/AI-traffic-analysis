from __future__ import annotations

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the MineShark Console web server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8008)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    try:
        import uvicorn
    except Exception as exc:
        raise RuntimeError("Install the web extra first: pip install -e '.[web]'") from exc

    uvicorn.run(
        "mineshark.web.api:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
