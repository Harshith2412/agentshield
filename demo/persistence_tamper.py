from pathlib import Path
from tempfile import TemporaryDirectory
from agentshield.persistence import run_tamper_detection

def main() -> None:
    with TemporaryDirectory(prefix="agentshield-demo-") as directory:
        print("tamper detected:", run_tamper_detection(Path(directory) / "tamper.db"))

if __name__ == "__main__": main()
