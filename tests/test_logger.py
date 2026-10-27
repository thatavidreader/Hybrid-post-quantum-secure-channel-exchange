import json

from src.log_summary import summarize
from src.logger import SecurityLogger


def test_jsonl_fields_and_summary(tmp_path):
    p = tmp_path / "log.jsonl"
    lg = SecurityLogger("server", p, console=False)
    lg.log("BAD_TAG", "1.2.3.4:5", "hybrid", reason="x")
    lg.log("BAD_TAG", "1.2.3.4:5", "hybrid")
    lg.log("HANDSHAKE_OK", "1.2.3.4:6", "pqc")
    rec = json.loads(p.read_text().splitlines()[0])
    for k in ("ts", "event", "role", "peer", "mode", "backend", "details"):
        assert k in rec
    assert rec["backend"] in ("kyber-py", "liboqs")
    c = summarize([str(p)])
    assert c["BAD_TAG"] == 2 and c["HANDSHAKE_OK"] == 1


def test_console_alert_is_coloured(capsys):
    SecurityLogger("client").log("DOWNGRADE_DETECTED", "p", "classical", reason="why")
    err = capsys.readouterr().out
    assert "\033[91m" in err and "DOWNGRADE_DETECTED" in err
