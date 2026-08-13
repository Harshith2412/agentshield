from pathlib import Path
from tempfile import TemporaryDirectory

from agentshield.persistence import run_pause_resume_attack


def main() -> None:
    with TemporaryDirectory(prefix="agentshield-demo-") as directory:
        result = run_pause_resume_attack(Path(directory) / "workflow.db")
        print("blocked:", result.blocked)
        print("origin after reload:", result.attribution.source_name)


if __name__ == "__main__": main()
