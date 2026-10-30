"""Standard-library EVM and smart-contract assessment helpers.

Everything here runs against public or authorized JSON-RPC endpoints and
engagement-local Solidity sources. Keccak-256 is implemented in this module
because ``hashlib.sha3_256`` is NIST SHA3-256 (padding ``0x06``), which produces
different digests and therefore wrong function selectors.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from typing import Any, Iterable
import uuid

from .engagements import resolve_engagement_path
from .workspace import write_workspace_file


# ---------------------------------------------------------------------------
# Keccak-256 (original Keccak padding, not NIST SHA3)
# ---------------------------------------------------------------------------

_KECCAK_MASK = (1 << 64) - 1
_KECCAK_RATE = 136  # bytes; 1088-bit rate for a 256-bit output
_KECCAK_ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)
# Rotation offsets indexed as _KECCAK_ROTATIONS[x][y] for lane A[x, y].
_KECCAK_ROTATIONS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def _rotate_left_64(value: int, shift: int) -> int:
    shift %= 64
    if shift == 0:
        return value & _KECCAK_MASK
    return ((value << shift) | (value >> (64 - shift))) & _KECCAK_MASK


def _keccak_f1600(state: list[int]) -> list[int]:
    lanes = [[state[x + 5 * y] for y in range(5)] for x in range(5)]
    for round_constant in _KECCAK_ROUND_CONSTANTS:
        columns = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
        delta = [columns[(x - 1) % 5] ^ _rotate_left_64(columns[(x + 1) % 5], 1) for x in range(5)]
        lanes = [[lanes[x][y] ^ delta[x] for y in range(5)] for x in range(5)]
        rotated = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                rotated[y][(2 * x + 3 * y) % 5] = _rotate_left_64(lanes[x][y], _KECCAK_ROTATIONS[x][y])
        lanes = [
            [
                rotated[x][y] ^ ((~rotated[(x + 1) % 5][y]) & rotated[(x + 2) % 5][y])
                for y in range(5)
            ]
            for x in range(5)
        ]
        lanes[0][0] ^= round_constant
    return [lanes[x][y] for y in range(5) for x in range(5)]


def keccak_256(data: bytes) -> bytes:
    """Return the original Keccak-256 digest of ``data`` (32 bytes)."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("keccak_256 requires bytes")
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % _KECCAK_RATE:
        padded.append(0x00)
    padded[-1] ^= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), _KECCAK_RATE):
        block = padded[offset : offset + _KECCAK_RATE]
        for lane in range(_KECCAK_RATE // 8):
            state[lane] ^= int.from_bytes(block[lane * 8 : lane * 8 + 8], "little")
        state = _keccak_f1600(state)
    return b"".join(state[lane].to_bytes(8, "little") for lane in range(4))


# ---------------------------------------------------------------------------
# ABI encoding and decoding
# ---------------------------------------------------------------------------

_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")
_INTEGER_PATTERN = re.compile(r"^(u?)int([0-9]{1,3})$")
_FIXED_BYTES_PATTERN = re.compile(r"^bytes([0-9]{1,2})$")
_HEX_PATTERN = re.compile(r"^(?:0x)?([0-9a-fA-F]*)$")


def _normalize_type(type_name: str) -> str:
    normalized = type_name.strip().lower()
    if normalized in {"uint", "int"}:
        return f"{normalized}256"
    if _INTEGER_PATTERN.fullmatch(normalized):
        match = _INTEGER_PATTERN.fullmatch(normalized)
        assert match is not None
        bits = int(match.group(2))
        if bits < 8 or bits > 256 or bits % 8:
            raise ValueError(f"unsupported integer width in ABI type: {type_name}")
        return normalized
    if _FIXED_BYTES_PATTERN.fullmatch(normalized):
        match = _FIXED_BYTES_PATTERN.fullmatch(normalized)
        assert match is not None
        size = int(match.group(1))
        if size < 1 or size > 32:
            raise ValueError(f"unsupported fixed bytes width in ABI type: {type_name}")
        return normalized
    if normalized in {"address", "bool", "bytes", "string"}:
        return normalized
    raise ValueError(f"unsupported ABI type: {type_name}")


def _is_dynamic(type_name: str) -> bool:
    return type_name in {"bytes", "string"}


def function_selector(signature: str) -> str:
    """Return the 4-byte function selector for a canonical signature."""
    canonical = signature.strip()
    if "(" not in canonical or not canonical.endswith(")"):
        raise ValueError(f"ABI signature must look like name(type1,type2): {signature}")
    return "0x" + keccak_256(canonical.encode("utf-8")).hex()[:8]


def event_topic(signature: str) -> str:
    """Return the 32-byte topic0 hash for an event signature."""
    canonical = signature.strip()
    if "(" not in canonical or not canonical.endswith(")"):
        raise ValueError(f"event signature must look like Name(type1,type2): {signature}")
    return "0x" + keccak_256(canonical.encode("utf-8")).hex()


def _coerce_bytes(value: bytes | bytearray | str, field: str = "value") -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if not isinstance(value, str):
        raise ValueError(f"{field} must be bytes or a hex string")
    raw = value.strip()
    if raw.lower().startswith("0x"):
        raw = raw[2:]
    if not _HEX_PATTERN.fullmatch(raw):
        raise ValueError(f"{field} is not valid hexadecimal")
    if len(raw) % 2:
        raise ValueError(f"{field} hex string must contain an even number of digits")
    return bytes.fromhex(raw)


def _coerce_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if raw.lower().startswith("0x"):
            return int(raw, 16)
        return int(raw, 10)
    raise ValueError(f"cannot interpret {value!r} as an integer")


def _encode_static(type_name: str, value: Any) -> bytes:
    integer_match = _INTEGER_PATTERN.fullmatch(type_name)
    if integer_match:
        bits = int(integer_match.group(2))
        number = _coerce_int(value)
        if integer_match.group(1):
            if number < 0 or number >= (1 << bits):
                raise ValueError(f"{type_name} value out of range: {value!r}")
            return number.to_bytes(32, "big")
        bound = 1 << (bits - 1)
        if number < -bound or number >= bound:
            raise ValueError(f"{type_name} value out of range: {value!r}")
        return (number & ((1 << 256) - 1)).to_bytes(32, "big")
    if type_name == "address":
        if not isinstance(value, str) or not _ADDRESS_PATTERN.fullmatch(value.strip()):
            raise ValueError(f"address must be 0x plus 40 hex characters: {value!r}")
        return bytes.fromhex(value.strip()[2:].lower()).rjust(32, b"\x00")
    if type_name == "bool":
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered not in {"true", "false"}:
                raise ValueError(f"bool must be true or false: {value!r}")
            return (1 if lowered == "true" else 0).to_bytes(32, "big")
        if not isinstance(value, (bool, int)):
            raise ValueError(f"bool must be true or false: {value!r}")
        return (1 if value else 0).to_bytes(32, "big")
    fixed_match = _FIXED_BYTES_PATTERN.fullmatch(type_name)
    if fixed_match:
        size = int(fixed_match.group(1))
        raw = _coerce_bytes(value, type_name)
        if len(raw) > size:
            raise ValueError(f"{type_name} value is longer than {size} bytes")
        return raw.ljust(32, b"\x00")
    raise ValueError(f"{type_name} is not a static ABI type")


def _encode_dynamic(type_name: str, value: Any) -> bytes:
    if type_name == "string":
        if not isinstance(value, str):
            raise ValueError("string ABI values must be str")
        raw = value.encode("utf-8")
    else:
        raw = _coerce_bytes(value, type_name)
    padded = raw + b"\x00" * (-len(raw) % 32)
    return len(raw).to_bytes(32, "big") + padded


def encode_abi(types: Iterable[str], values: Iterable[Any]) -> str:
    """ABI-encode a head/tail argument list and return ``0x``-prefixed hex."""
    normalized = [_normalize_type(item) for item in types]
    arguments = list(values)
    if len(normalized) != len(arguments):
        raise ValueError(f"ABI type count ({len(normalized)}) does not match argument count ({len(arguments)})")
    head_size = 32 * len(normalized)
    heads: list[bytes] = []
    tails: list[bytes] = []
    offset = head_size
    for type_name, value in zip(normalized, arguments):
        if _is_dynamic(type_name):
            tail = _encode_dynamic(type_name, value)
            heads.append(offset.to_bytes(32, "big"))
            tails.append(tail)
            offset += len(tail)
        else:
            heads.append(_encode_static(type_name, value))
    return "0x" + b"".join(heads + tails).hex()


def encode_call(signature: str, args: list[Any] | None = None) -> str:
    """Return selector plus ABI-encoded arguments for one function call."""
    canonical = signature.strip()
    open_paren = canonical.find("(")
    if open_paren < 0 or not canonical.endswith(")"):
        raise ValueError(f"ABI signature must look like name(type1,type2): {signature}")
    inner = canonical[open_paren + 1 : -1].strip()
    types = [item.strip() for item in inner.split(",")] if inner else []
    values = list(args or [])
    if len(types) != len(values):
        raise ValueError(f"signature declares {len(types)} argument(s) but {len(values)} were supplied")
    encoded = encode_abi(types, values)[2:] if types else ""
    return function_selector(canonical) + encoded


def _abi_word(data: bytes, offset: int, type_name: str) -> bytes:
    if offset < 0 or offset + 32 > len(data):
        raise ValueError(f"ABI data is too short for {type_name} at byte offset {offset}")
    return data[offset : offset + 32]


def decode_abi(types: Iterable[str], data: bytes | bytearray | str) -> list[Any]:
    """Decode ABI-encoded values for the supplied static or dynamic types."""
    normalized = [_normalize_type(item) for item in types]
    payload = _coerce_bytes(data, "data")
    values: list[Any] = []
    for index, type_name in enumerate(normalized):
        if _is_dynamic(type_name):
            offset = int.from_bytes(_abi_word(payload, index * 32, type_name), "big")
            length = int.from_bytes(_abi_word(payload, offset, type_name), "big")
            start = offset + 32
            end = start + length
            if end > len(payload):
                raise ValueError(f"ABI data is too short for {type_name} payload at byte offset {start}")
            raw = payload[start:end]
            values.append(raw.decode("utf-8", errors="replace") if type_name == "string" else "0x" + raw.hex())
            continue
        word = _abi_word(payload, index * 32, type_name)
        integer_match = _INTEGER_PATTERN.fullmatch(type_name)
        if integer_match:
            number = int.from_bytes(word, "big")
            if not integer_match.group(1) and number >= (1 << 255):
                number -= 1 << 256
            values.append(number)
        elif type_name == "address":
            values.append("0x" + word[12:].hex())
        elif type_name == "bool":
            values.append(bool(int.from_bytes(word, "big")))
        else:
            values.append("0x" + word.hex())
    return values


# ---------------------------------------------------------------------------
# JSON-RPC
# ---------------------------------------------------------------------------

DEFAULT_RPC_TIMEOUT = 20.0
_ZERO_ADDRESS = "0x" + "00" * 20

KNOWN_CHAINS: dict[int, tuple[str, str]] = {
    1: ("ethereum", "ETH"),
    10: ("optimism", "ETH"),
    56: ("bsc", "BNB"),
    97: ("bsc-testnet", "tBNB"),
    100: ("gnosis", "xDAI"),
    137: ("polygon", "POL"),
    250: ("fantom", "FTM"),
    324: ("zksync-era", "ETH"),
    8453: ("base", "ETH"),
    31337: ("local-dev", "ETH"),
    42161: ("arbitrum", "ETH"),
    42170: ("arbitrum-nova", "ETH"),
    43114: ("avalanche", "AVAX"),
    59144: ("linea", "ETH"),
    534352: ("scroll", "ETH"),
    11155111: ("sepolia", "ETH"),
    84532: ("base-sepolia", "ETH"),
    421614: ("arbitrum-sepolia", "ETH"),
}

EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"

_MINIMAL_PROXY_PREFIX = "363d3d373d3d3d363d73"
_MINIMAL_PROXY_SUFFIX = "5af43d82803e903d91602b57fd5bf3"

_SELECTOR_CATALOG: dict[str, str] = {
    "06fdde03": "name()",
    "095ea7b3": "approve(address,uint256)",
    "18160ddd": "totalSupply()",
    "23b872dd": "transferFrom(address,address,uint256)",
    "2e1a7d4d": "withdraw(uint256)",
    "2f2ff15d": "grantRole(bytes32,address)",
    "313ce567": "decimals()",
    "3659cfe6": "upgradeTo(address)",
    "3ccfd60b": "withdraw()",
    "3f4ba83a": "unpause()",
    "40c10f19": "mint(address,uint256)",
    "42842e0e": "safeTransferFrom(address,address,uint256)",
    "42966c68": "burn(uint256)",
    "4e71d92d": "claim()",
    "4f1ef286": "upgradeToAndCall(address,bytes)",
    "5c60da1b": "implementation()",
    "5c975abb": "paused()",
    "6352211e": "ownerOf(uint256)",
    "70a08231": "balanceOf(address)",
    "715018a6": "renounceOwnership()",
    "8129fc1c": "initialize()",
    "8456cb59": "pause()",
    "8da5cb5b": "owner()",
    "91d14854": "hasRole(bytes32,address)",
    "95d89b41": "symbol()",
    "a9059cbb": "transfer(address,uint256)",
    "b88d4fde": "safeTransferFrom(address,address,uint256,bytes)",
    "c87b56dd": "tokenURI(uint256)",
    "d0e30db0": "deposit()",
    "dd62ed3e": "allowance(address,address)",
    "f2fde38b": "transferOwnership(address)",
    "01ffc9a7": "supportsInterface(bytes4)",
}

_ERC20_REQUIRED = ("balanceOf", "transfer", "totalSupply")
_ERC721_REQUIRED = ("ownerOf", "safeTransferFrom")


def rpc_call(
    rpc_url: str,
    method: str,
    params: list[Any] | None = None,
    timeout: float | None = None,
) -> Any:
    """Perform one JSON-RPC request and return the ``result`` field."""
    import requests

    payload = {"jsonrpc": "2.0", "id": 1, "method": method.strip(), "params": params or []}
    response = requests.post(
        rpc_url,
        json=payload,
        timeout=timeout or DEFAULT_RPC_TIMEOUT,
        headers={"content-type": "application/json", "user-agent": "drost-ai/1.0"},
    )
    response.raise_for_status()
    try:
        body = response.json()
    except ValueError as exc:
        raise ValueError(f"JSON-RPC endpoint returned non-JSON content from {rpc_url}") from exc
    if not isinstance(body, dict):
        raise ValueError("JSON-RPC response must be an object")
    error = body.get("error")
    if error:
        code = error.get("code") if isinstance(error, dict) else None
        message = error.get("message") if isinstance(error, dict) else error
        raise ValueError(f"JSON-RPC error {code}: {message}")
    return body.get("result")


def _validate_address(address: str) -> str:
    if not isinstance(address, str) or not _ADDRESS_PATTERN.fullmatch(address.strip()):
        raise ValueError("address must be 0x plus 40 hexadecimal characters")
    return address.strip().lower()


def _hex_to_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    raw = str(value).strip()
    if not raw or raw in {"0x", "0x0"}:
        return 0
    return int(raw, 16)


def _format_native(wei: int | None) -> str | None:
    if wei is None:
        return None
    whole, fraction = divmod(wei, 10**18)
    return f"{whole}.{fraction:018d}".rstrip("0").rstrip(".")


def _block_tag(value: Any) -> str:
    if value is None:
        return "latest"
    if isinstance(value, int):
        return hex(value)
    raw = str(value).strip()
    if raw.lower() in {"latest", "earliest", "pending", "safe", "finalized"}:
        return raw.lower()
    if raw.lower().startswith("0x"):
        return raw.lower()
    if raw.isdigit():
        return hex(int(raw))
    return raw


def chain_info(rpc_url: str) -> dict[str, Any]:
    """Return chain identity, head, gas price, and sync state."""
    if not isinstance(rpc_url, str) or not rpc_url.startswith(("http://", "https://")):
        raise ValueError("rpc_url must be an http or https endpoint")
    chain_id = _hex_to_int(rpc_call(rpc_url, "eth_chainId"))
    known = KNOWN_CHAINS.get(int(chain_id or 0))
    return {
        "rpc_url": rpc_url,
        "chain_id": chain_id,
        "chain_name": known[0] if known else None,
        "native_symbol": known[1] if known else None,
        "block_number": _hex_to_int(rpc_call(rpc_url, "eth_blockNumber")),
        "client_version": rpc_call(rpc_url, "web3_clientVersion"),
        "gas_price_wei": _hex_to_int(rpc_call(rpc_url, "eth_gasPrice")),
        "syncing": rpc_call(rpc_url, "eth_syncing"),
    }


def _selector_names(code: bytes) -> dict[str, list[int]]:
    """Map PUSH4 immediates to the offsets that push them."""
    found: dict[str, list[int]] = {}
    for instruction in disassemble_evm(code)["instructions"]:
        push = instruction.get("push")
        if instruction["name"] == "PUSH4" and push and len(push) == 10:
            found.setdefault(push[2:].lower(), []).append(instruction["pc"])
    return found


def _minimal_proxy_target(code_hex: str) -> str | None:
    raw = code_hex[2:] if code_hex.lower().startswith("0x") else code_hex
    if len(raw) != len(_MINIMAL_PROXY_PREFIX) + 40 + len(_MINIMAL_PROXY_SUFFIX):
        return None
    if not raw.startswith(_MINIMAL_PROXY_PREFIX) or not raw.endswith(_MINIMAL_PROXY_SUFFIX):
        return None
    return "0x" + raw[len(_MINIMAL_PROXY_PREFIX) : len(_MINIMAL_PROXY_PREFIX) + 40]


def contract_info(rpc_url: str, address: str) -> dict[str, Any]:
    """Fingerprint one deployed contract: bytecode, proxies, and token standards."""
    target = _validate_address(address)
    code_hex = rpc_call(rpc_url, "eth_getCode", [target, "latest"]) or "0x"
    normalized = code_hex.lower()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    runtime = _coerce_bytes(normalized, "bytecode")
    if not runtime:
        return {
            "rpc_url": rpc_url,
            "address": target,
            "is_contract": False,
            "bytecode_size": 0,
            "minimal_proxy": None,
            "eip1967": {},
            "detected_functions": [],
            "standards": {},
            "selectors": {},
        }
    selector_offsets = _selector_names(runtime)
    detected = sorted(
        {
            signature.split("(")[0]
            for selector in selector_offsets
            if (signature := _SELECTOR_CATALOG.get(selector))
        }
    )
    eip1967: dict[str, str | None] = {}
    for label, slot in (
        ("implementation", EIP1967_IMPLEMENTATION_SLOT),
        ("beacon", EIP1967_BEACON_SLOT),
        ("admin", EIP1967_ADMIN_SLOT),
    ):
        word = rpc_call(rpc_url, "eth_getStorageAt", [target, slot, "latest"]) or "0x"
        candidate = "0x" + str(word)[-40:] if len(str(word)) >= 42 else None
        eip1967[label] = None if candidate in (None, _ZERO_ADDRESS) else candidate
    disassembly = disassemble_evm(runtime)
    return {
        "rpc_url": rpc_url,
        "address": target,
        "is_contract": True,
        "bytecode_size": len(runtime),
        "code_hash": "0x" + keccak_256(runtime).hex(),
        "minimal_proxy": _minimal_proxy_target(normalized),
        "eip1967": eip1967,
        "detected_functions": detected,
        "standards": {
            "erc20": all(name in detected for name in _ERC20_REQUIRED),
            "erc721": all(name in detected for name in _ERC721_REQUIRED),
            "erc165": "supportsInterface" in detected,
        },
        "selectors": {
            selector: {"signature": _SELECTOR_CATALOG.get(selector), "offsets": offsets}
            for selector, offsets in sorted(selector_offsets.items())
        },
        "jumpdest_count": disassembly["jumpdest_count"],
        "flags": disassembly["flags"],
        "metadata_tail": disassembly["metadata_tail"],
    }


def read_contract(
    rpc_url: str,
    address: str,
    signature: str,
    args: list[Any] | None = None,
    output_types: list[str] | None = None,
    block: str = "latest",
) -> dict[str, Any]:
    """eth_call one contract function, optionally decoding the return data."""
    target = _validate_address(address)
    if signature.strip().lower().startswith("0x") and args:
        raise ValueError("raw calldata cannot be combined with ABI arguments")
    calldata = signature if signature.strip().lower().startswith("0x") else encode_call(signature, args)
    raw_result = rpc_call(rpc_url, "eth_call", [{"to": target, "data": calldata}, _block_tag(block)])
    decoded = None
    if output_types and raw_result and str(raw_result) not in {"0x", "0x0"}:
        decoded = decode_abi(output_types, raw_result)
    return {
        "rpc_url": rpc_url,
        "address": target,
        "calldata": calldata,
        "block": _block_tag(block),
        "raw_result": raw_result,
        "empty_result": str(raw_result or "0x") in {"0x", "0x0"},
        "output_types": output_types,
        "decoded": decoded,
    }


def storage_read(rpc_url: str, address: str, slot: Any, length: int = 1) -> dict[str, Any]:
    """Read one or more raw storage slots of an address."""
    target = _validate_address(address)
    start = _coerce_int(slot)
    if start < 0 or start >= (1 << 256):
        raise ValueError("slot must be between 0 and 2**256-1")
    count = int(length)
    if count < 1 or count > 32:
        raise ValueError("length must be between 1 and 32 slots")
    words = []
    for index in range(count):
        current = start + index
        value = rpc_call(rpc_url, "eth_getStorageAt", [target, hex(current), "latest"])
        words.append({"slot": hex(current), "value": value})
    return {
        "rpc_url": rpc_url,
        "address": target,
        "slot": hex(start),
        "length": count,
        "words": words,
    }


def event_logs(
    rpc_url: str,
    address: str | None = None,
    topics: list[Any] | None = None,
    from_block: Any = "latest",
    to_block: Any = "latest",
    event_signature: str = "",
) -> dict[str, Any]:
    """Collect eth_getLogs entries, optionally filtered by event topic0."""
    filter_object: dict[str, Any] = {
        "fromBlock": _block_tag(from_block),
        "toBlock": _block_tag(to_block),
    }
    if address:
        filter_object["address"] = _validate_address(address)
    effective_topics = list(topics or [])
    if event_signature:
        effective_topics = [event_topic(event_signature), *effective_topics]
    if effective_topics:
        filter_object["topics"] = effective_topics
    logs = rpc_call(rpc_url, "eth_getLogs", [filter_object]) or []
    return {
        "rpc_url": rpc_url,
        "filter": filter_object,
        "log_count": len(logs),
        "logs": logs,
    }


def tx_inspect(rpc_url: str, tx_hash: str) -> dict[str, Any]:
    """Inspect a transaction and its receipt, including the input selector."""
    if not isinstance(tx_hash, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", tx_hash.strip()):
        raise ValueError("tx_hash must be 0x plus 64 hexadecimal characters")
    transaction = rpc_call(rpc_url, "eth_getTransactionByHash", [tx_hash.strip()])
    if not transaction:
        raise ValueError(f"transaction not found: {tx_hash}")
    receipt = rpc_call(rpc_url, "eth_getTransactionReceipt", [tx_hash.strip()])
    calldata = str(transaction.get("input") or "0x")
    selector = calldata[:10].lower() if len(calldata) >= 10 else None
    status = receipt.get("status") if isinstance(receipt, dict) else None
    return {
        "rpc_url": rpc_url,
        "tx_hash": tx_hash.strip(),
        "block_number": _hex_to_int(transaction.get("blockNumber")),
        "from": transaction.get("from"),
        "to": transaction.get("to"),
        "value_wei": _hex_to_int(transaction.get("value")),
        "value_native": _format_native(_hex_to_int(transaction.get("value"))),
        "nonce": _hex_to_int(transaction.get("nonce")),
        "gas": _hex_to_int(transaction.get("gas")),
        "gas_price_wei": _hex_to_int(transaction.get("gasPrice")),
        "input": calldata,
        "selector": selector,
        "selector_signature": _SELECTOR_CATALOG.get((selector or "")[2:]),
        "receipt": {
            "present": bool(receipt),
            "status": {None: None, "0x1": "success", "0x0": "reverted"}.get(status, status),
            "gas_used": _hex_to_int(receipt.get("gasUsed")) if isinstance(receipt, dict) else None,
            "contract_address": receipt.get("contractAddress") if isinstance(receipt, dict) else None,
            "log_count": len(receipt.get("logs") or []) if isinstance(receipt, dict) else None,
        },
    }


def wallet_info(rpc_url: str, address: str) -> dict[str, Any]:
    """Return balance, nonce, contract status, and chain for one account."""
    target = _validate_address(address)
    code = rpc_call(rpc_url, "eth_getCode", [target, "latest"]) or "0x"
    balance = _hex_to_int(rpc_call(rpc_url, "eth_getBalance", [target, "latest"]))
    return {
        "rpc_url": rpc_url,
        "address": target,
        "chain_id": _hex_to_int(rpc_call(rpc_url, "eth_chainId")),
        "balance_wei": balance,
        "balance_native": _format_native(balance),
        "nonce": _hex_to_int(rpc_call(rpc_url, "eth_getTransactionCount", [target, "latest"])),
        "is_contract": str(code).lower() not in {"0x", "0x0", ""},
        "code_size": (len(str(code)) - 2) // 2 if str(code).lower().startswith("0x") else 0,
    }


def selector_lookup(selector: str, allow_remote: bool = False, timeout: float = 8.0) -> dict[str, Any]:
    """Resolve a 4-byte selector locally, with an opt-in 4byte.directory query."""
    raw = selector.strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if not re.fullmatch(r"[0-9a-f]{8}", raw):
        raise ValueError("selector must be 4 bytes of hex, such as 0xa9059cbb")
    signature = _SELECTOR_CATALOG.get(raw)
    result: dict[str, Any] = {
        "selector": "0x" + raw,
        "signature": signature,
        "ambiguous": False,
        "candidates": [signature] if signature else [],
        "source": "local" if signature else None,
        "remote_attempted": False,
        "remote_error": None,
    }
    if signature or not allow_remote:
        return result
    import requests

    result["remote_attempted"] = True
    try:
        response = requests.get(
            "https://www.4byte.directory/api/v1/signatures/",
            params={"hex_signature": "0x" + raw},
            timeout=timeout,
            headers={"user-agent": "drost-ai/1.0"},
        )
        response.raise_for_status()
        payload = response.json()
        candidates = [
            str(item.get("text_signature"))
            for item in payload.get("results", [])
            if isinstance(item, dict) and item.get("text_signature")
        ]
        if candidates:
            # 4byte.directory orders hash collisions by insertion, not popularity,
            # so a single entry is never safe to assert when the set disagrees.
            result["candidates"] = candidates
            if len(set(candidates)) == 1:
                result["signature"] = candidates[0]
            else:
                result["ambiguous"] = True
            result["source"] = "4byte.directory"
    except Exception as exc:  # noqa: BLE001 - resolution is optional and must never fail the call
        result["remote_error"] = f"{type(exc).__name__}: {exc}"
    return result


# ---------------------------------------------------------------------------
# EVM disassembly
# ---------------------------------------------------------------------------

_OPCODES: dict[int, str] = {
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x04: "DIV",
    0x05: "SDIV",
    0x06: "MOD",
    0x07: "SMOD",
    0x08: "ADDMOD",
    0x09: "MULMOD",
    0x0A: "EXP",
    0x0B: "SIGNEXTEND",
    0x10: "LT",
    0x11: "GT",
    0x12: "SLT",
    0x13: "SGT",
    0x14: "EQ",
    0x15: "ISZERO",
    0x16: "AND",
    0x17: "OR",
    0x18: "XOR",
    0x19: "NOT",
    0x1A: "BYTE",
    0x1B: "SHL",
    0x1C: "SHR",
    0x1D: "SAR",
    0x20: "KECCAK256",
    0x30: "ADDRESS",
    0x31: "BALANCE",
    0x32: "ORIGIN",
    0x33: "CALLER",
    0x34: "CALLVALUE",
    0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",
    0x38: "CODESIZE",
    0x39: "CODECOPY",
    0x3A: "GASPRICE",
    0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY",
    0x3D: "RETURNDATASIZE",
    0x3E: "RETURNDATACOPY",
    0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH",
    0x41: "COINBASE",
    0x42: "TIMESTAMP",
    0x43: "NUMBER",
    0x44: "PREVRANDAO",
    0x45: "GASLIMIT",
    0x46: "CHAINID",
    0x47: "SELFBALANCE",
    0x48: "BASEFEE",
    0x49: "BLOBHASH",
    0x4A: "BLOBBASEFEE",
    0x50: "POP",
    0x51: "MLOAD",
    0x52: "MSTORE",
    0x53: "MSTORE8",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x58: "PC",
    0x59: "MSIZE",
    0x5A: "GAS",
    0x5B: "JUMPDEST",
    0x5C: "TLOAD",
    0x5D: "TSTORE",
    0x5E: "MCOPY",
    0x5F: "PUSH0",
    0xF0: "CREATE",
    0xF1: "CALL",
    0xF2: "CALLCODE",
    0xF3: "RETURN",
    0xF4: "DELEGATECALL",
    0xF5: "CREATE2",
    0xFA: "STATICCALL",
    0xFD: "REVERT",
    0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}

_CALL_OPCODES = {"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"}


def _opcode_name(opcode: int) -> str:
    if opcode in _OPCODES:
        return _OPCODES[opcode]
    if 0x60 <= opcode <= 0x7F:
        return f"PUSH{opcode - 0x5F}"
    if 0x80 <= opcode <= 0x8F:
        return f"DUP{opcode - 0x7F}"
    if 0x90 <= opcode <= 0x9F:
        return f"SWAP{opcode - 0x8F}"
    if 0xA0 <= opcode <= 0xA4:
        return f"LOG{opcode - 0xA0}"
    return f"UNDEFINED_0x{opcode:02x}"


def _metadata_tail(code: bytes) -> dict[str, Any]:
    """Detect the trailing CBOR metadata block that solc and Vyper append."""
    if len(code) < 4:
        return {"present": False}
    length = int.from_bytes(code[-2:], "big")
    if length <= 0 or length > len(code) - 2:
        return {"present": False}
    start = len(code) - 2 - length
    if not 0xA0 <= code[start] <= 0xBF:
        return {"present": False}
    return {"present": True, "start": start, "length": length, "encoding": "cbor"}


def disassemble_evm(bytecode: bytes | str, max_instructions: int = 20000) -> dict[str, Any]:
    """Disassemble EVM bytecode with correct PUSH0..PUSH32 handling."""
    code = _coerce_bytes(bytecode, "bytecode")
    metadata = _metadata_tail(code)
    analyzed = metadata["start"] if metadata["present"] else len(code)
    limit = int(max_instructions or 0)
    instructions: list[dict[str, Any]] = []
    jumpdests: list[int] = []
    flags: dict[str, list[int]] = {
        "DELEGATECALL": [],
        "CALLCODE": [],
        "SELFDESTRUCT": [],
        "CREATE2": [],
        "TIMESTAMP": [],
    }
    pc = 0
    truncated = False
    while pc < analyzed:
        if limit and len(instructions) >= limit:
            truncated = True
            break
        opcode = code[pc]
        name = _opcode_name(opcode)
        entry: dict[str, Any] = {"pc": pc, "opcode": opcode, "name": name}
        if 0x60 <= opcode <= 0x7F:
            size = opcode - 0x5F
            immediate = code[pc + 1 : pc + 1 + size]
            entry["push"] = "0x" + immediate.hex()
            entry["push_size"] = size
            name = f"PUSH{size}"
        elif opcode == 0x5F:
            entry["push"] = "0x"
            entry["push_size"] = 0
        if opcode == 0x5B:
            jumpdests.append(pc)
        if name in flags:
            flags[name].append(pc)
        instructions.append(entry)
        pc += 1 + (entry.get("push_size") or 0)
    return {
        "bytecode_size": len(code),
        "analyzed_size": analyzed,
        "instruction_count": len(instructions),
        "truncated": truncated,
        "metadata_tail": metadata,
        "jumpdest_count": len(jumpdests),
        "jumpdests": jumpdests,
        "flags": flags,
        "instructions": instructions,
    }


def bytecode_audit(bytecode: bytes | str) -> dict[str, Any]:
    """Produce disassembly-derived, explicitly suspected review items."""
    disassembly = disassemble_evm(bytecode)
    instructions = disassembly["instructions"]
    findings: list[dict[str, Any]] = []

    def add(code: str, severity: str, evidence: str, offsets: list[int]) -> None:
        findings.append(
            {
                "code": code,
                "severity": severity,
                "classification": "suspected",
                "offset": offsets[0] if offsets else None,
                "offsets": offsets,
                "evidence": evidence,
            }
        )

    privileged = {
        "selfdestruct_present": ("SELFDESTRUCT", "high", "SELFDESTRUCT can delete the runtime code and move the balance."),
        "delegatecall_present": ("DELEGATECALL", "medium", "DELEGATECALL executes foreign code in this contract's storage context."),
        "callcode_present": ("CALLCODE", "medium", "CALLCODE runs foreign code against the caller's storage."),
        "create2_present": ("CREATE2", "low", "CREATE2 derives the deployment address from caller-supplied salt."),
    }
    for code, (opcode_name, severity, note) in privileged.items():
        offsets = disassembly["flags"][opcode_name]
        if offsets:
            add(code, severity, f"{note} First occurrence at byte offset {offsets[0]}.", offsets)

    if disassembly["flags"]["TIMESTAMP"]:
        offsets = disassembly["flags"]["TIMESTAMP"]
        add(
            "timestamp_dependence",
            "low",
            f"TIMESTAMP is read at byte offset {offsets[0]}; chain time is miner-influenced.",
            offsets,
        )

    origin_offsets: list[int] = []
    unchecked_offsets: list[int] = []
    weak_randomness: list[int] = []
    for index, instruction in enumerate(instructions):
        if instruction["name"] == "ORIGIN":
            following = [item["name"] for item in instructions[index + 1 : index + 3]]
            if "EQ" in following:
                origin_offsets.append(instruction["pc"])
        if instruction["name"] in _CALL_OPCODES:
            following = instructions[index + 1] if index + 1 < len(instructions) else None
            if following and following["name"] == "POP":
                unchecked_offsets.append(instruction["pc"])
        if instruction["name"] in {"BLOCKHASH", "COINBASE", "NUMBER", "PREVRANDAO", "GASLIMIT"}:
            weak_randomness.append(instruction["pc"])

    if origin_offsets:
        add(
            "tx_origin_authorization",
            "high",
            f"ORIGIN is compared with EQ at byte offset {origin_offsets[0]}; tx.origin authorization is phishable.",
            origin_offsets,
        )
    if unchecked_offsets:
        add(
            "unchecked_call_result",
            "medium",
            f"A call result is discarded with POP at byte offset {unchecked_offsets[0]}.",
            unchecked_offsets,
        )
    if weak_randomness:
        add(
            "weak_randomness_source",
            "low",
            f"Chain-derived value (BLOCKHASH/COINBASE/NUMBER/PREVRANDAO/GASLIMIT) at byte offset {weak_randomness[0]}.",
            weak_randomness,
        )

    return {
        "bytecode_size": disassembly["bytecode_size"],
        "analyzed_size": disassembly["analyzed_size"],
        "metadata_tail": disassembly["metadata_tail"],
        "jumpdest_count": disassembly["jumpdest_count"],
        "finding_count": len(findings),
        "findings": findings,
        "finding_policy": (
            "Disassembly-derived leads only. Every item is suspected until source review or "
            "execution evidence confirms reachability and impact."
        ),
    }


# ---------------------------------------------------------------------------
# Solidity source review
# ---------------------------------------------------------------------------

_FUNCTION_HEADER = re.compile(
    r"^\s*(?:function\s+[A-Za-z_$][\w$]*|modifier\s+[A-Za-z_$][\w$]*|constructor|fallback|receive)\s*\(",
)
_VISIBILITY = re.compile(r"\b(public|external|internal|private)\b")
_MUTABILITY = re.compile(r"\b(view|pure|payable|constant)\b")
_STATE_WRITE = re.compile(r"^\s*([A-Za-z_$][\w$]*(?:\s*\[[^\]]*\])?(?:\s*\.\s*[A-Za-z_$][\w$]*)?)\s*(?:=|\+=|-=|\*=|\+\+)\s*[^=]")
_LOCAL_DECLARATION = re.compile(
    r"^\s*(?:u?int\d*|address(?:\s+payable)?|bool|bytes\d*|string|var|mapping|"
    r"[A-Z][A-Za-z0-9_$]*(?:\[\])?)\s+(?:memory\s+|storage\s+|calldata\s+)?[A-Za-z_$][\w$]*"
)
_AUTH_MARKERS = (
    "onlyowner",
    "onlyadmin",
    "onlyrole",
    "onlyminter",
    "onlygovernance",
    "requiresauth",
    "msg.sender",
    "hasrole",
    "_checkowner",
    "_checkrole",
    "auth",
)


def _function_bodies(lines: list[str]) -> list[tuple[int, str, list[tuple[int, str]]]]:
    """Return (start line index, header, body lines) for brace-delimited functions."""
    blocks: list[tuple[int, str, list[tuple[int, str]]]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if not _FUNCTION_HEADER.match(line):
            index += 1
            continue
        if ";" in line.split("{", 1)[0] and "{" not in line:
            index += 1
            continue
        depth = line.count("{") - line.count("}")
        body: list[tuple[int, str]] = [(index, line)]
        cursor = index + 1
        while depth > 0 and cursor < len(lines):
            body.append((cursor, lines[cursor]))
            depth += lines[cursor].count("{") - lines[cursor].count("}")
            cursor += 1
        blocks.append((index, line, body))
        index = cursor
    return blocks


def _solidity_findings(path_label: str, source: str) -> list[dict[str, Any]]:
    lines = source.splitlines()
    findings: list[dict[str, Any]] = []

    def add(code: str, line_index: int, severity: str, classification: str, evidence: str) -> None:
        findings.append(
            {
                "file": path_label,
                "line": line_index + 1,
                "code": code,
                "severity": severity,
                "classification": classification,
                "evidence": evidence.strip(),
            }
        )

    pragma_seen = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        lowered = stripped.lower()
        if lowered.startswith("pragma solidity"):
            pragma_seen = True
            if any(token in stripped for token in ("^", ">=", ">", "~")):
                add(
                    "floating_pragma",
                    index,
                    "low",
                    "review",
                    stripped,
                )
        if re.search(r"\btx\.origin\b", stripped):
            add("tx_origin_usage", index, "high", "suspected", stripped)
        if re.search(r"\.delegatecall\s*\(", stripped):
            add("delegatecall_usage", index, "high", "suspected", stripped)
        if re.search(r"\bselfdestruct\s*\(|\bsuicide\s*\(", stripped):
            add("selfdestruct_usage", index, "high", "suspected", stripped)
        if re.search(r"\bblock\.timestamp\b|\bnow\b", stripped) and not lowered.startswith("//"):
            add("block_timestamp_dependence", index, "low", "suspected", stripped)
        if re.search(r"\becrecover\s*\(", stripped):
            window = " ".join(item.strip() for item in lines[index : index + 4])
            if not re.search(r"!=|==\s*address\(\s*0\s*\)|!=\s*address\(\s*0\s*\)", window):
                add(
                    "ecrecover_without_zero_check",
                    index,
                    "medium",
                    "suspected",
                    stripped,
                )
        if re.search(r"\bassembly\s*\{", stripped):
            add("inline_assembly", index, "low", "review", stripped)
        if ".call(" in stripped or ".call{" in stripped or ".send(" in stripped:
            checked = any(
                token in stripped for token in ("require(", "if (", "if(", "=", "return ")
            )
            if not checked:
                add("unchecked_low_level_call", index, "medium", "suspected", stripped)
    if not pragma_seen:
        add("missing_pragma", 0, "low", "review", "No pragma solidity directive found in this file.")

    for start, header, body in _function_bodies(lines):
        header_lower = header.lower()
        visibility = _VISIBILITY.search(header_lower)
        mutability = _MUTABILITY.search(header_lower)
        body_text = " ".join(item[1] for item in body if item[1].strip())
        mutated = any(
            _STATE_WRITE.match(item[1]) and not _LOCAL_DECLARATION.match(item[1])
            for item in body[1:]
            if item[1].strip() and not item[1].strip().startswith("//")
        )
        if (
            visibility
            and visibility.group(1) in {"public", "external"}
            and not (mutability and mutability.group(1) in {"view", "pure"})
            and mutated
            and not any(marker in body_text.lower() or marker in header_lower for marker in _AUTH_MARKERS)
        ):
            add(
                "missing_access_control",
                start,
                "high",
                "suspected",
                header.strip(),
            )
        call_positions = [
            position
            for position, (line_index, text) in enumerate(body)
            if re.search(r"\.(?:call|delegatecall|staticcall|send|transfer)\s*[\({]", text)
        ]
        for position in call_positions:
            line_index, text = body[position]
            for later_index, later_text in body[position + 1 : position + 13]:
                if _LOCAL_DECLARATION.match(later_text) or not _STATE_WRITE.match(later_text):
                    continue
                add(
                    "reentrancy_external_call_before_state_write",
                    line_index,
                    "high",
                    "suspected",
                    f"{text.strip()} -> state write at line {later_index + 1}: {later_text.strip()}",
                )
                break
    return findings


def audit_solidity(engagement_id: str, path: str) -> dict[str, Any]:
    """Heuristically review engagement Solidity sources and persist the report."""
    target = resolve_engagement_path(engagement_id, path)
    if target.is_dir():
        sources = sorted(item for item in target.rglob("*.sol") if item.is_file())
    elif target.is_file():
        sources = [target]
    else:
        sources = []
    if not sources:
        raise ValueError(f"no Solidity sources found at engagement path: {path}")

    root = resolve_engagement_path(engagement_id, ".")
    files: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for source_path in sources:
        label = str(source_path.relative_to(root))
        text = source_path.read_text(encoding="utf-8", errors="replace")
        file_findings = _solidity_findings(label, text)
        findings.extend(file_findings)
        files.append(
            {
                "path": label,
                "line_count": len(text.splitlines()),
                "finding_count": len(file_findings),
            }
        )

    findings.sort(key=lambda item: (item["file"], item["line"], item["code"]))
    result: dict[str, Any] = {
        "engagement_id": engagement_id,
        "path": str(target.relative_to(root)) or ".",
        "file_count": len(files),
        "files": files,
        "finding_count": len(findings),
        "findings": findings,
        "finding_policy": (
            "Heuristic source review only. Every item is a line-referenced lead; confirm "
            "reachability and impact in the source before calling it a vulnerability."
        ),
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    artifact = f"evidence/blockchain/solidity-audit-{stamp}-{uuid.uuid4().hex[:8]}.json"
    write_workspace_file(engagement_id, artifact, json.dumps(result, indent=2, sort_keys=True) + "\n")
    result["artifact_path"] = artifact
    return result
