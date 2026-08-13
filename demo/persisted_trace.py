from pathlib import Path
from tempfile import TemporaryDirectory
from agentshield.integrations.microsoft_agent_framework import run_multi_agent
from agentshield.persistence import SQLiteProvenanceStore

def main() -> None:
    normalized = run_multi_agent().adapter.normalized_trace()
    with TemporaryDirectory(prefix="agentshield-demo-") as directory:
        store = SQLiteProvenanceStore(Path(directory) / "trace.db")
        store.persist_normalized_trace(normalized)
        print(store.load_normalized_trace(normalized.run_id))

if __name__ == "__main__": main()
