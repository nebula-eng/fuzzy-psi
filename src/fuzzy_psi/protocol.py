"""End-to-end fuzzy PSI protocol.

Four rounds on top of one TCP-like channel:

    round 0  (local)   both parties sketch every indicator: simhash -> b bands
    round 1  C -> S    blinded band keys + batch consistency proof
             S -> C    blinded server band keys + double-blinded client keys
             C         learns which of its band keys exist on the server
    round 2  C -> S    blinded 64-bit sketches of the candidate items
             S -> C    PSI reply for those sketches
             C         learns which candidates are exact sketch duplicates (d=0)
    round 3  C -> S    (band key, simhash) for candidates still unconfirmed
             S -> C    32-byte confirmations for candidates within radius t
             C         learns which of its items have a near match

Round 3 exists because an equality PSI cannot certify 1 <= d <= t without
either revealing sketches or running an MPC distance protocol.  We choose a
server-side distance evaluation under the semi-honest-server assumption and
document the trade-off in docs/DESIGN.md and docs/THREAT_MODEL.md.

All wire messages are counted as real framed bytes (4-byte length prefix
plus payload) by the channel, never estimated.
"""

from __future__ import annotations

import hashlib
import secrets
import struct
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field

from . import dhpsi, group, lsh, net, schnorr

CLIENT1_TAG = b"FPSI-C1"
SERVER1_TAG = b"FPSI-S1"
CLIENT2_TAG = b"FPSI-C2"
SERVER2_TAG = b"FPSI-S2"
CLIENT3_TAG = b"FPSI-C3"
SERVER3_TAG = b"FPSI-S3"
ERROR_TAG = b"FPSI-ERR"

TAG_BYTES = 7  # len("FPSI-C1")
HEADER_BYTES = TAG_BYTES + 8  # tag + bands + band_bits + radius + proof flag + count
VERIFY_TOKEN_BYTES = 8  # exact simhash, round 2
TOKEN_BYTES = 12  # 4-byte band key + 8-byte simhash, round 3
CONFIRM_BYTES = 32


class ProtocolError(RuntimeError):
    pass


class ProofRejected(ProtocolError):
    pass


@dataclass(frozen=True)
class Params:
    bands: int = lsh.BANDS
    band_bits: int = lsh.BAND_BITS
    radius: int = 4
    exponent_bits: int = group.DEFAULT_EXPONENT_BITS
    pad_client_keys: int = 0
    use_proof: bool = True

    def __post_init__(self) -> None:
        if not 0 <= self.radius <= 64:
            raise ValueError("radius must be in [0, 64]")
        lsh.LshParams(self.bands, self.band_bits)  # validates
        if self.exponent_bits < group.MIN_EXPONENT_BITS:
            raise ValueError("exponent_bits below the minimum")
        if not 0 <= self.pad_client_keys <= 1 << 16:
            raise ValueError("pad_client_keys must be in [0, 65536]")

    @property
    def lsh_params(self) -> lsh.LshParams:
        return lsh.LshParams(self.bands, self.band_bits)


class Recorder:
    """Per-party timing and payload accounting."""

    def __init__(self) -> None:
        self.time: dict[str, float] = {}
        self.bytes: dict[str, int] = {}
        self.counters: dict[str, int] = {}

    @contextmanager
    def phase(self, name: str):
        started = time.perf_counter()
        try:
            yield
        finally:
            self.time[name] = self.time.get(name, 0.0) + (time.perf_counter() - started)

    def add_bytes(self, name: str, payload: bytes) -> None:
        self.bytes[name] = self.bytes.get(name, 0) + len(payload)

    def bump(self, name: str, amount: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + amount


@dataclass
class PartyOutcome:
    matches: set[str] = field(default_factory=set)
    candidates: set[str] = field(default_factory=set)
    exact_matches: set[str] = field(default_factory=set)
    candidate_tokens: int = 0
    exact_tokens: int = 0
    pending_tokens: int = 0
    band_keys: int = 0
    error: BaseException | None = None


@dataclass
class ProtocolResult:
    client: PartyOutcome
    server: PartyOutcome
    client_recorder: Recorder
    server_recorder: Recorder
    wall_time: float
    client_channel_bytes: int
    server_channel_bytes: int

    @property
    def total_bytes(self) -> int:
        return self.client_channel_bytes + self.server_channel_bytes


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------
def _header(tag: bytes, params: Params, count: int) -> bytes:
    return (
        tag
        + bytes([params.bands, params.band_bits, params.radius, int(params.use_proof)])
        + struct.pack(">I", count)
    )


def _unheader(payload: bytes, tag: bytes) -> tuple[Params, int]:
    if len(payload) < HEADER_BYTES or payload[:TAG_BYTES] != tag:
        raise ProtocolError(f"bad header, expected {tag!r}")
    bands, band_bits, radius, flag = payload[TAG_BYTES : TAG_BYTES + 4]
    (count,) = struct.unpack(">I", payload[TAG_BYTES + 4 : HEADER_BYTES])
    return Params(bands=bands, band_bits=band_bits, radius=radius, use_proof=bool(flag)), count


def _same_params(left: Params, right: Params) -> bool:
    """The client's header must match the server's own configuration.

    Without this a client could clear its own proof flag in the header and the
    server would skip verification.
    """
    return (
        left.bands == right.bands
        and left.band_bits == right.band_bits
        and left.radius == right.radius
        and left.use_proof == right.use_proof
    )


def _encode_c1(tag: bytes, params: Params, blinded: list[int], bases: list[int],
               proof: schnorr.BatchProof | None) -> bytes:
    body = group.encode_elements(blinded) + group.encode_elements(bases)
    return _header(tag, params, len(blinded)) + (proof.to_bytes() if proof else b"") + body


def _decode_c1(payload: bytes, tag: bytes) -> tuple[Params, list[int], list[int], schnorr.BatchProof | None]:
    try:
        params, count = _unheader(payload, tag)
        offset = HEADER_BYTES
        proof = None
        if params.use_proof and count > 0:
            proof = schnorr.BatchProof.from_bytes(payload[offset : offset + schnorr.PROOF_BYTES])
            offset += schnorr.PROOF_BYTES
        span = count * group.ELEMENT_BYTES
        if len(payload) != offset + 2 * span:
            raise ProtocolError("truncated client message")
        blinded = group.decode_elements(payload[offset : offset + span])
        bases = group.decode_elements(payload[offset + span : offset + 2 * span])
    except (ValueError, IndexError) as exc:
        raise ProtocolError(f"malformed client message: {exc}") from exc
    if len(blinded) != count or len(bases) != count:
        raise ProtocolError("truncated client message")
    return params, blinded, bases, proof


def _encode_s1(tag: bytes, params: Params, v_list: list[int], w_list: list[int]) -> bytes:
    return (
        _header(tag, params, len(v_list))
        + struct.pack(">I", len(w_list))
        + group.encode_elements(v_list)
        + group.encode_elements(w_list)
    )


def _decode_s1(payload: bytes, tag: bytes) -> tuple[list[int], list[int]]:
    try:
        _params, count = _unheader(payload, tag)
        (wcount,) = struct.unpack(">I", payload[HEADER_BYTES : HEADER_BYTES + 4])
        body = HEADER_BYTES + 4
        span = count * group.ELEMENT_BYTES
        if len(payload) != body + span + wcount * group.ELEMENT_BYTES:
            raise ProtocolError("truncated server message")
        v_list = group.decode_elements(payload[body : body + span])
        w_list = group.decode_elements(payload[body + span : body + span + wcount * group.ELEMENT_BYTES])
    except (ValueError, IndexError) as exc:
        raise ProtocolError(f"malformed server message: {exc}") from exc
    if len(v_list) != count or len(w_list) != wcount:
        raise ProtocolError("truncated server message")
    return v_list, w_list


def _encode_tokens(tag: bytes, params: Params, tokens: list[bytes]) -> bytes:
    return _header(tag, params, len(tokens)) + b"".join(tokens)


def _decode_tokens(payload: bytes, tag: bytes, width: int) -> list[bytes]:
    _params, count = _unheader(payload, tag)
    body = payload[HEADER_BYTES:]
    if len(body) != count * width:
        raise ProtocolError("truncated token vector")
    return [body[i : i + width] for i in range(0, len(body), width)]


def _encode_confirms(tag: bytes, params: Params, digests: list[bytes]) -> bytes:
    return _header(tag, params, len(digests)) + b"".join(digests)


def _decode_confirms(payload: bytes, tag: bytes) -> list[bytes]:
    _params, count = _unheader(payload, tag)
    body = payload[HEADER_BYTES:]
    if len(body) != count * CONFIRM_BYTES:
        raise ProtocolError("truncated confirmation vector")
    return [body[i : i + CONFIRM_BYTES] for i in range(0, len(body), CONFIRM_BYTES)]


def token_digest(token: bytes) -> bytes:
    return hashlib.sha256(b"fpsi-confirm-v1" + token).digest()


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
def client_side(
    channel: net.Channel,
    items: list[str],
    params: Params = Params(),
    recorder: Recorder | None = None,
    tamper=None,
) -> PartyOutcome:
    """Run the client half; returns what the client learned (and nothing else).

    ``tamper`` is a test hook: it receives (blinded, bases) right before the
    first message and may return a modified pair, used to check that the
    server rejects exponent-inconsistent submissions.
    """
    rec = recorder or Recorder()
    out = PartyOutcome()
    rng = secrets.SystemRandom()

    with rec.phase("lsh"):
        sketches = [lsh.simhash(lsh.shingles(item)) for item in items]
        per_item = [lsh.band_keys(sketch, params.lsh_params) for sketch in sketches]

    keys = sorted({key for row in per_item for key in row})
    if params.pad_client_keys > len(keys):
        padding = set()
        while len(keys) + len(padding) < params.pad_client_keys:
            padding.add(struct.pack(">H", 0xFFFF) + secrets.token_bytes(2))
        keys = keys + sorted(padding)
    out.band_keys = len(keys)

    # ---- round 1: band-key PSI -------------------------------------------
    with rec.phase("psi1_blind"):
        a1 = group.rand_exponent(bits=params.exponent_bits)
        order = list(range(len(keys)))
        rng.shuffle(order)
        shuffled_keys = [keys[i] for i in order]
        state = dhpsi.client_blind(shuffled_keys, a1)
        blinded = state.blinded
        bases = state.bases
        if tamper is not None:
            blinded, bases = tamper(blinded, bases)
    with rec.phase("psi1_prove"):
        proof = None
        if params.use_proof and blinded:
            proof = schnorr.prove(a1, bases, blinded, context=b"band-keys")
    with rec.phase("psi1_send"):
        payload = _encode_c1(CLIENT1_TAG, params, blinded, bases, proof)
        rec.add_bytes("psi1", payload)
        channel.send(payload)
    with rec.phase("psi1_wait"):
        reply = channel.recv()
    if reply.startswith(ERROR_TAG):
        raise ProofRejected("server rejected the round-1 submission")
    with rec.phase("psi1_finish"):
        v_list, w_list = _decode_s1(reply, SERVER1_TAG)
        matched_keys = dhpsi.client_finish(state, a1, v_list, w_list) if keys else set()
    rec.bump("matched_band_keys", len(matched_keys))

    # ---- round 2: verification PSI over exact simhashes -------------------
    # Candidate scoping already came from the band keys, so the round-2 item is
    # the 64-bit sketch alone.  Including the band would multiply the server's
    # PSI input by b_lsh for no extra matching power.
    candidate_indices = [
        idx for idx, row in enumerate(per_item) if any(key in matched_keys for key in row)
    ]
    tokens = sorted({sketches[idx].to_bytes(VERIFY_TOKEN_BYTES, "big") for idx in candidate_indices})
    out.candidate_tokens = len(tokens)  # distinct candidate sketches
    out.candidates = {items[idx] for idx in candidate_indices}

    exact_tokens: set[bytes] = set()
    with rec.phase("psi2_blind"):
        a2 = group.rand_exponent(bits=params.exponent_bits)
        order2 = list(range(len(tokens)))
        rng.shuffle(order2)
        shuffled_tokens = [tokens[i] for i in order2]
        state2 = dhpsi.client_blind(shuffled_tokens, a2)
        blinded2 = state2.blinded
        bases2 = state2.bases
    with rec.phase("psi2_prove"):
        proof2 = None
        if params.use_proof and blinded2:
            proof2 = schnorr.prove(a2, bases2, blinded2, context=b"tokens")
    with rec.phase("psi2_send"):
        payload = _encode_c1(CLIENT2_TAG, params, blinded2, bases2, proof2)
        rec.add_bytes("psi2", payload)
        channel.send(payload)
    with rec.phase("psi2_wait"):
        reply = channel.recv()
    if reply.startswith(ERROR_TAG):
        raise ProofRejected("server rejected the round-2 submission")
    with rec.phase("psi2_finish"):
        v2, w2 = _decode_s1(reply, SERVER2_TAG)
        exact_tokens = dhpsi.client_finish(state2, a2, v2, w2) if tokens else set()
    out.exact_tokens = len(exact_tokens)

    # ---- round 3: distance completion for 1 <= d <= t ---------------------
    confirmed_sketches = set(exact_tokens)
    pending = []
    for idx in candidate_indices:
        suffix = sketches[idx].to_bytes(VERIFY_TOKEN_BYTES, "big")
        if suffix in exact_tokens:
            continue
        pending.extend(key + suffix for key in per_item[idx] if key in matched_keys)
    pending = dhpsi.unique_keys(pending)
    out.pending_tokens = len(pending)
    # Always exchanged, even with radius 0, so both parties stay in lockstep.
    with rec.phase("stage3_send"):
        payload = _encode_tokens(CLIENT3_TAG, params, pending)
        rec.add_bytes("stage3", payload)
        channel.send(payload)
    with rec.phase("stage3_wait"):
        reply = channel.recv()
    with rec.phase("stage3_finish"):
        digests = set(_decode_confirms(reply, SERVER3_TAG))
        for token in pending:
            if token_digest(token) in digests:
                confirmed_sketches.add(token[4:])

    out.matches = {
        items[idx] for idx in candidate_indices
        if sketches[idx].to_bytes(VERIFY_TOKEN_BYTES, "big") in confirmed_sketches
    }
    out.exact_matches = {
        items[idx] for idx in candidate_indices
        if sketches[idx].to_bytes(VERIFY_TOKEN_BYTES, "big") in exact_tokens
    }
    rec.bump("confirmed_sketches", len(confirmed_sketches))
    return out


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
def server_side(
    channel: net.Channel,
    items: list[str],
    params: Params = Params(),
    recorder: Recorder | None = None,
) -> PartyOutcome:
    rec = recorder or Recorder()
    out = PartyOutcome()

    with rec.phase("lsh"):
        sketches = [lsh.simhash(lsh.shingles(item)) for item in items]
        per_item = [lsh.band_keys(sketch, params.lsh_params) for sketch in sketches]
    server_keys = sorted({key for row in per_item for key in row})
    out.band_keys = len(server_keys)

    # ---- round 1 ----------------------------------------------------------
    with rec.phase("psi1_wait"):
        payload = channel.recv()
    with rec.phase("psi1_parse"):
        _params, blinded, bases, proof = _decode_c1(payload, CLIENT1_TAG)
        if not _same_params(_params, params):
            channel.send(ERROR_TAG)
            raise ProtocolError("client parameters do not match the server configuration")
    with rec.phase("psi1_verify"):
        if params.use_proof and blinded and proof is not None:
            if not schnorr.verify(proof, bases, blinded, context=b"band-keys"):
                channel.send(ERROR_TAG)
                raise ProofRejected("batch consistency proof failed")
    with rec.phase("psi1_reply"):
        b1 = group.rand_exponent(bits=params.exponent_bits)
        v_list, w_list = dhpsi.server_respond(server_keys, blinded, b1)
    with rec.phase("psi1_send"):
        reply = _encode_s1(SERVER1_TAG, params, v_list, w_list)
        rec.add_bytes("psi1", reply)
        channel.send(reply)

    # ---- round 2 ----------------------------------------------------------
    with rec.phase("psi2_wait"):
        payload = channel.recv()
    with rec.phase("psi2_parse"):
        _params, blinded, bases, proof = _decode_c1(payload, CLIENT2_TAG)
        if not _same_params(_params, params):
            channel.send(ERROR_TAG)
            raise ProtocolError("client parameters do not match the server configuration")
    with rec.phase("psi2_verify"):
        if params.use_proof and blinded and proof is not None:
            if not schnorr.verify(proof, bases, blinded, context=b"tokens"):
                channel.send(ERROR_TAG)
                raise ProofRejected("batch consistency proof failed")
    with rec.phase("psi2_reply"):
        server_tokens = sorted({sketch.to_bytes(VERIFY_TOKEN_BYTES, "big") for sketch in sketches})
        b2 = group.rand_exponent(bits=params.exponent_bits)
        v2, w2 = dhpsi.server_respond(server_tokens, blinded, b2)
    with rec.phase("psi2_send"):
        reply = _encode_s1(SERVER2_TAG, params, v2, w2)
        rec.add_bytes("psi2", reply)
        channel.send(reply)

    # ---- round 3 ----------------------------------------------------------
    with rec.phase("stage3_wait"):
        payload = channel.recv()
    with rec.phase("stage3"):
        tokens = _decode_tokens(payload, CLIENT3_TAG, TOKEN_BYTES)
        by_band: dict[bytes, list[int]] = {}
        for sketch, row in zip(sketches, per_item):
            for key in row:
                by_band.setdefault(key, []).append(sketch)
        digests = []
        for token in tokens:
            band_key, raw = token[:4], int.from_bytes(token[4:], "big")
            for sketch in by_band.get(band_key, ()):
                if lsh.hamming(raw, sketch) <= params.radius:
                    digests.append(token_digest(token))
                    break
    with rec.phase("stage3_send"):
        reply = _encode_confirms(SERVER3_TAG, params, digests)
        rec.add_bytes("stage3", reply)
        channel.send(reply)
    rec.bump("confirmations", len(digests))
    return out


# ---------------------------------------------------------------------------
# Harnesses
# ---------------------------------------------------------------------------
def run(
    client_items: list[str],
    server_items: list[str],
    params: Params = Params(),
    tamper=None,
) -> ProtocolResult:
    """Run both parties over an in-memory channel and collect measurements."""
    client_channel, server_channel = net.local_pair()
    client_rec, server_rec = Recorder(), Recorder()
    capture: dict[str, PartyOutcome] = {}
    errors: list[BaseException] = []

    def serve() -> None:
        try:
            capture["server"] = server_side(server_channel, server_items, params, server_rec)
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            errors.append(exc)

    thread = threading.Thread(target=serve, name="fpsi-local-server", daemon=True)
    started = time.perf_counter()
    thread.start()
    try:
        result = client_side(client_channel, client_items, params, client_rec, tamper=tamper)
    except BaseException:
        thread.join(timeout=net.DEFAULT_TIMEOUT)
        raise
    wall = time.perf_counter() - started
    thread.join(timeout=net.DEFAULT_TIMEOUT)
    if thread.is_alive():
        raise ProtocolError("server thread did not terminate")
    if errors:
        raise errors[0]
    return ProtocolResult(
        client=result,
        server=capture.get("server", PartyOutcome()),
        client_recorder=client_rec,
        server_recorder=server_rec,
        wall_time=wall,
        client_channel_bytes=client_channel.bytes_sent,
        server_channel_bytes=server_channel.bytes_sent,
    )


def run_tcp(
    client_items: list[str],
    server_items: list[str],
    params: Params = Params(),
    host: str = "127.0.0.1",
) -> ProtocolResult:
    """Same protocol over a real loopback TCP connection."""
    client_rec, server_rec = Recorder(), Recorder()
    capture: dict[str, PartyOutcome] = {}

    def handle(channel: net.Channel) -> None:
        capture["server"] = server_side(channel, server_items, params, server_rec)

    server = net.LoopbackServer(handle).start()
    channel = net.connect(server.port, host=host)
    started = time.perf_counter()
    try:
        outcome = client_side(channel, client_items, params, client_rec)
        wall = time.perf_counter() - started
    finally:
        channel.close()
        server.join()
    return ProtocolResult(
        client=outcome,
        server=capture.get("server", PartyOutcome()),
        client_recorder=client_rec,
        server_recorder=server_rec,
        wall_time=wall,
        client_channel_bytes=channel.bytes_sent,
        server_channel_bytes=channel.bytes_recv,
    )


# ---------------------------------------------------------------------------
# Insecure baselines used for comparison in the evaluation
# ---------------------------------------------------------------------------
@dataclass
class BaselineResult:
    name: str
    matches: set[str]
    total_bytes: int
    wall_time: float


def run_plaintext(client_items: list[str], server_items: list[str]) -> BaselineResult:
    """Send the indicators in the clear; compare against exact string match."""
    started = time.perf_counter()
    client_channel, server_channel = net.local_pair()
    payload = "\n".join(client_items).encode("utf-8")
    client_channel.send(payload)
    received = server_channel.recv().decode("utf-8").split("\n")
    server_set = set(server_items)
    hits = [item for item in received if item in server_set]
    server_channel.send("\n".join(hits).encode("utf-8"))
    reply = client_channel.recv().decode("utf-8")
    matches = set(reply.split("\n")) if reply else set()
    wall = time.perf_counter() - started
    return BaselineResult("plaintext", matches, client_channel.bytes_sent + server_channel.bytes_sent, wall)


def run_hash_psi(client_items: list[str], server_items: list[str]) -> BaselineResult:
    """Naive hash PSI: 32-byte digests in the clear plus a membership bitmap."""
    started = time.perf_counter()
    client_channel, server_channel = net.local_pair()
    digests = [hashlib.sha256(item.encode("utf-8")).digest() for item in client_items]
    client_channel.send(b"".join(digests))
    received = server_channel.recv()
    server_hashes = {hashlib.sha256(item.encode("utf-8")).digest() for item in server_items}
    bitmap = bytearray((len(digests) + 7) // 8)
    for idx in range(len(digests)):
        chunk = received[idx * 32 : (idx + 1) * 32]
        if chunk in server_hashes:
            bitmap[idx // 8] |= 1 << (idx % 8)
    server_channel.send(bytes(bitmap))
    reply = client_channel.recv()
    matches = {
        item for idx, item in enumerate(client_items)
        if reply[idx // 8] & (1 << (idx % 8))
    }
    wall = time.perf_counter() - started
    return BaselineResult("hash-psi", matches, client_channel.bytes_sent + server_channel.bytes_sent, wall)
