import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def cli() -> None:
    from mineshark.evaluation.tor_multiclass_eval import main

    main()


if __name__ == "__main__":
    cli()
