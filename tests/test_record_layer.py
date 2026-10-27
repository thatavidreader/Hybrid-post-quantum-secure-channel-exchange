"""Record-layer unit tests: normal path, BAD_TAG, REPLAY_DETECTED, SEQ_GAP."""
import struct

import pytest

from src import crypto_suite as cs
from src.record_layer import (C2S, BadTag, RecordReceiver, RecordSender, ReplayDetected,
                              SeqGap, MAX_PLAINTEXT)


@pytest.fixture()
def pair():
    key, iv = b"K" * 32, b"IVIV"
    return RecordSender(key, iv, C2S), RecordReceiver(key, iv, C2S)


def body(frame: bytes) -> bytes:
    return frame[4:]  # strip the length prefix


def test_in_order_delivery_and_frame_layout(pair):
    tx, rx = pair
    frame = tx.seal(b"hello")
    (length,) = struct.unpack("!I", frame[:4])
    assert length == len(frame) - 4 == 8 + 5 + 16
    assert struct.unpack("!Q", frame[4:12])[0] == 0           # explicit seq field
    assert rx.open(body(frame)) == b"hello"
    assert rx.open(body(tx.seal(b"world"))) == b"world"
    assert rx.expected == 2


@pytest.mark.matrix("T3", "Tampered ciphertext", "Rejected: BAD_TAG, connection aborted")
def test_bit_flip_in_ciphertext_is_bad_tag(pair, actual):
    tx, rx = pair
    f = bytearray(tx.seal(b"secret"))
    f[14] ^= 0x01
    with pytest.raises(BadTag) as e:
        rx.open(body(bytes(f)))
    actual(f"record layer raised {type(e.value).__name__} -> event {e.value.event}")


def test_bit_flip_in_tag_is_bad_tag(pair):
    tx, rx = pair
    f = bytearray(tx.seal(b"secret"))
    f[-1] ^= 0x80
    with pytest.raises(BadTag):
        rx.open(body(bytes(f)))


@pytest.mark.matrix("T4", "Replay of a captured record", "Rejected: REPLAY_DETECTED")
def test_replayed_record_detected(pair, actual):
    tx, rx = pair
    f = tx.seal(b"pay $10")
    rx.open(body(f))
    rx.open(body(tx.seal(b"next")))
    with pytest.raises(ReplayDetected) as e:
        rx.open(body(f))  # same authentic record again
    actual(f"record layer raised {type(e.value).__name__} -> event {e.value.event}")


def test_immediate_duplicate_is_replay(pair):
    tx, rx = pair
    f = tx.seal(b"x")
    rx.open(body(f))
    with pytest.raises(ReplayDetected):
        rx.open(body(f))


@pytest.mark.matrix("T5", "Dropped / reordered record", "Rejected: SEQ_GAP")
def test_gap_detected(pair, actual):
    tx, rx = pair
    tx.seal(b"dropped")             # seq 0 never delivered
    with pytest.raises(SeqGap) as e:
        rx.open(body(tx.seal(b"seq1")))
    actual(f"record layer raised {type(e.value).__name__} -> event {e.value.event}")


def test_rewriting_seq_field_is_bad_tag_not_replay(pair):
    """Lowering the visible counter must not turn a forgery into a 'replay'."""
    tx, rx = pair
    rx.open(body(tx.seal(b"a")))
    f = bytearray(tx.seal(b"b"))
    f[4:12] = struct.pack("!Q", 0)  # claim seq 0
    with pytest.raises(BadTag):
        rx.open(body(bytes(f)))


def test_wrong_direction_reflection_rejected():
    key, iv = b"K" * 32, b"IVIV"
    tx = RecordSender(key, iv, C2S)
    rx_other_direction = RecordReceiver(key, iv, b"s2c")
    with pytest.raises(BadTag):
        rx_other_direction.open(body(tx.seal(b"reflect me")))


def test_oversize_and_truncated():
    key, iv = b"K" * 32, b"IVIV"
    tx, rx = RecordSender(key, iv, C2S), RecordReceiver(key, iv, C2S)
    with pytest.raises(ValueError):
        tx.seal(b"x" * (MAX_PLAINTEXT + 1))
    with pytest.raises(BadTag):
        rx.open(b"short")
