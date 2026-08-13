from pathlib import Path
from tempfile import TemporaryDirectory
from agentshield.persistence import run_persistence_benchmark

def main() -> None:
    with TemporaryDirectory(prefix="agentshield-benchmark-") as directory:
        print(run_persistence_benchmark(Path(directory)).render())

if __name__ == "__main__": main()
