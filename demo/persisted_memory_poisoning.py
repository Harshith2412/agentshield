from pathlib import Path
from tempfile import TemporaryDirectory
from agentshield.persistence import run_persisted_memory_poisoning

def main() -> None:
    with TemporaryDirectory(prefix="agentshield-demo-") as directory:
        result = run_persisted_memory_poisoning(Path(directory) / "memory.db")
        print("blocked:", result.blocked, "origin:", result.attribution.source_name)

if __name__ == "__main__": main()
