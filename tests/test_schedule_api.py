from candix.api.openapi import operations, validate
from candix.schedule import Checkpoint, CheckpointStore
from candix.schedule.checkpoint import plan_resume


def test_checkpoint_roundtrip(tmp_path):
    store = CheckpointStore(str(tmp_path / "ckpt"))
    checkpoint = Checkpoint(scan_id="scan-1", phase="detect", completed_detectors=["recon"], pending_detectors=["detect", "report"])
    store.save(checkpoint)
    loaded = store.load("scan-1")
    assert loaded.scan_id == "scan-1"
    assert loaded.digest() == store.load("scan-1").digest()
    assert store.latest().scan_id == "scan-1"
    description = plan_resume(loaded, all_detectors=["headers", "rce"]).describe()
    assert "scan-1" in description


def test_openapi_is_valid():
    assert validate() == []
    methods = {(item["method"], item["path"]) for item in operations()}
    assert ("POST", "/scans") in methods
