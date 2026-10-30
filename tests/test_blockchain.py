import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import drost_ai.engagements as engagements
from drost_ai.blockchain import (
    EIP1967_IMPLEMENTATION_SLOT,
    audit_solidity,
    bytecode_audit,
    chain_info,
    contract_info,
    decode_abi,
    disassemble_evm,
    encode_abi,
    encode_call,
    event_logs,
    event_topic,
    function_selector,
    keccak_256,
    read_contract,
    rpc_call,
    selector_lookup,
    storage_read,
    tx_inspect,
    wallet_info,
)


CONTRACT = "0x" + "11" * 20
PROXY = "0x" + "22" * 20
WALLET = "0x" + "33" * 20
IMPLEMENTATION = "0x" + "44" * 20

# PUSH4 selectors for transfer, balanceOf, totalSupply, and allowance.
ERC20_BYTECODE = "0x63a9059cbb6370a082316318160ddd63dd62ed3e00"
MINIMAL_PROXY_BYTECODE = "0x363d3d373d3d3d363d73" + IMPLEMENTATION[2:] + "5af43d82803e903d91602b57fd5bf3"
TX_HASH = "0x" + "ab" * 32
LOG = {
    "address": CONTRACT,
    "topics": ["0x" + "cd" * 32],
    "data": "0x" + "00" * 32,
    "blockNumber": "0x10",
    "transactionHash": TX_HASH,
    "logIndex": "0x0",
}


def _dispatch(method, params):
    if method == "eth_chainId":
        return "0x1"
    if method == "eth_blockNumber":
        return "0x10"
    if method == "web3_clientVersion":
        return "FixtureRPC/v1.0.0"
    if method == "eth_gasPrice":
        return "0x3b9aca00"
    if method == "eth_syncing":
        return False
    if method == "eth_getCode":
        return {
            CONTRACT: ERC20_BYTECODE,
            PROXY: MINIMAL_PROXY_BYTECODE,
        }.get(params[0].lower(), "0x")
    if method == "eth_getBalance":
        return "0xde0b6b3a7640000" if params[0].lower() == WALLET else "0x0"
    if method == "eth_getTransactionCount":
        return "0x2"
    if method == "eth_call":
        return "0x" + (100).to_bytes(32, "big").hex()
    if method == "eth_getStorageAt":
        if params[0].lower() == PROXY and params[1].lower() == EIP1967_IMPLEMENTATION_SLOT.lower():
            return "0x" + "00" * 12 + IMPLEMENTATION[2:]
        return "0x" + "00" * 32
    if method == "eth_getLogs":
        return [LOG]
    if method == "eth_getTransactionByHash":
        return {
            "hash": TX_HASH,
            "blockNumber": "0x10",
            "from": WALLET,
            "to": CONTRACT,
            "value": "0x0",
            "nonce": "0x1",
            "gas": "0x5208",
            "gasPrice": "0x3b9aca00",
            "input": "0xa9059cbb" + "00" * 64,
        }
    if method == "eth_getTransactionReceipt":
        return {
            "status": "0x1",
            "gasUsed": "0x5208",
            "contractAddress": None,
            "logs": [LOG],
        }
    raise KeyError(method)


class RpcFixtureHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        request = json.loads(self.rfile.read(length).decode())
        try:
            result = _dispatch(request.get("method"), request.get("params") or [])
            payload = {"jsonrpc": "2.0", "id": request.get("id"), "result": result}
        except KeyError as exc:
            payload = {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {"code": -32601, "message": f"method not found: {exc.args[0]}"},
            }
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


SOLIDITY_FIXTURE = """pragma solidity ^0.8.0;

contract Vulnerable {
    mapping(address => uint256) public balances;
    address public owner;

    function withdraw(uint256 amount) public {
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }

    function setOwner(address next) public {
        owner = next;
    }

    function transferOwner(address next) public {
        require(tx.origin == owner, "not owner");
        owner = next;
    }

    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
"""


class BlockchainUnitTests(unittest.TestCase):
    def test_keccak_matches_known_vectors_and_differs_from_sha3(self):
        self.assertEqual(
            keccak_256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        self.assertEqual(
            keccak_256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )
        self.assertEqual(
            keccak_256(b"transfer(address,uint256)").hex(),
            "a9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b",
        )
        self.assertNotEqual(keccak_256(b"").hex(), hashlib.sha3_256(b"").hexdigest())
        self.assertEqual(function_selector("transfer(address,uint256)"), "0xa9059cbb")
        self.assertEqual(function_selector("balanceOf(address)"), "0x70a08231")
        self.assertEqual(
            event_topic("Transfer(address,address,uint256)"),
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
        )

    def test_abi_encode_and_decode_round_trip(self):
        encoded = encode_call("transfer(address,uint256)", ["0x" + "11" * 20, 1000])
        self.assertTrue(encoded.startswith("0xa9059cbb"))
        self.assertEqual(encoded[10:], "0" * 24 + "11" * 20 + "0" * 61 + "3e8")
        self.assertEqual(decode_abi(["address", "uint256"], encoded[10:]), ["0x" + "11" * 20, 1000])

        dynamic = encode_abi(["string", "uint256"], ["hello", 7])
        self.assertEqual(decode_abi(["string", "uint256"], dynamic), ["hello", 7])

        self.assertEqual(decode_abi(["int256"], encode_abi(["int256"], [-5])), [-5])
        self.assertEqual(
            decode_abi(["bytes32"], encode_abi(["bytes32"], ["0x" + "aa" * 32]))[0],
            "0x" + "aa" * 32,
        )
        self.assertEqual(decode_abi(["bool"], encode_abi(["bool"], [True])), [True])
        with self.assertRaises(ValueError):
            encode_call("transfer(address,uint256)", ["0x" + "11" * 20])

    def test_disassembly_handles_push0_push32_and_metadata(self):
        result = disassemble_evm("0x5f5f5b")
        self.assertEqual([item["name"] for item in result["instructions"]], ["PUSH0", "PUSH0", "JUMPDEST"])
        self.assertEqual(result["jumpdests"], [2])

        push_data = disassemble_evm("0x635b000000")
        self.assertEqual(push_data["instruction_count"], 1)
        self.assertEqual(push_data["jumpdests"], [])

        metadata = bytes.fromhex("a264697066735822") + b"\x11" * 32 + bytes.fromhex("64736f6c6343000813")
        code = bytes.fromhex("60016000") + metadata + len(metadata).to_bytes(2, "big")
        with_metadata = disassemble_evm(code)
        self.assertTrue(with_metadata["metadata_tail"]["present"])
        self.assertEqual(with_metadata["metadata_tail"]["start"], 4)
        self.assertEqual(with_metadata["analyzed_size"], 4)

    def test_bytecode_audit_flags_and_suspected_policy(self):
        flags = disassemble_evm("0xf4ff")["flags"]
        self.assertEqual(flags["DELEGATECALL"], [0])
        self.assertEqual(flags["SELFDESTRUCT"], [1])
        self.assertEqual(disassemble_evm("0x63f4ff0000")["flags"]["DELEGATECALL"], [])

        result = bytecode_audit("0x3214f4ff50")
        codes = {finding["code"] for finding in result["findings"]}
        self.assertTrue(
            {"tx_origin_authorization", "delegatecall_present", "selfdestruct_present"} <= codes
        )
        self.assertTrue(all(finding["classification"] == "suspected" for finding in result["findings"]))
        self.assertTrue(all(isinstance(finding["offset"], int) for finding in result["findings"]))

        unchecked = bytecode_audit("0xf150")
        self.assertIn("unchecked_call_result", {finding["code"] for finding in unchecked["findings"]})

    def test_selector_lookup_is_local_first_and_degrades_gracefully(self):
        local = selector_lookup("0xa9059cbb")
        self.assertEqual(local["signature"], "transfer(address,uint256)")
        self.assertEqual(local["source"], "local")
        self.assertFalse(local["ambiguous"])
        self.assertFalse(local["remote_attempted"])

        unknown = selector_lookup("0xdeadbeef")
        self.assertIsNone(unknown["signature"])
        self.assertFalse(unknown["ambiguous"])
        self.assertEqual(unknown["candidates"], [])

        with patch("requests.get", side_effect=RuntimeError("offline")):
            degraded = selector_lookup("0xdeadbeef", allow_remote=True)
        self.assertEqual(degraded["candidates"], [])
        self.assertFalse(degraded["ambiguous"])
        self.assertIn("offline", degraded["remote_error"])

    def test_selector_lookup_flags_4byte_collisions(self):
        class FakeResponse:
            def __init__(self, signatures):
                self.signatures = signatures

            def raise_for_status(self):
                return None

            def json(self):
                return {"results": [{"text_signature": sig} for sig in self.signatures]}

        colliding = ["workMyDirefulOwner(uint256,uint256)", "transfer(address,uint256)"]
        with patch("requests.get", return_value=FakeResponse(colliding)):
            ambiguous = selector_lookup("0xdeadbeef", allow_remote=True)
        self.assertIsNone(ambiguous["signature"])
        self.assertTrue(ambiguous["ambiguous"])
        self.assertEqual(ambiguous["candidates"], colliding)
        self.assertEqual(ambiguous["source"], "4byte.directory")

        with patch("requests.get", return_value=FakeResponse(["resolved(uint256)"])):
            single = selector_lookup("0xdeadbeef", allow_remote=True)
        self.assertEqual(single["signature"], "resolved(uint256)")
        self.assertFalse(single["ambiguous"])
        self.assertEqual(single["source"], "4byte.directory")


class BlockchainRpcTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if importlib.util.find_spec("requests") is None:
            raise unittest.SkipTest("requests is installed in the Drost image, not this host interpreter")
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), RpcFixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.rpc_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.patch = patch.object(engagements, "WORKSPACE", self.root)
        self.patch.start()
        self.engagement = engagements.create_engagement("Blockchain", ["127.0.0.1"])
        self.engagement_id = self.engagement["engagement_id"]

    def tearDown(self):
        self.patch.stop()
        self.temporary.cleanup()

    def test_chain_and_wallet_queries(self):
        info = chain_info(self.rpc_url)
        self.assertEqual(info["chain_id"], 1)
        self.assertEqual(info["chain_name"], "ethereum")
        self.assertEqual(info["block_number"], 16)
        self.assertEqual(info["client_version"], "FixtureRPC/v1.0.0")
        self.assertEqual(rpc_call(self.rpc_url, "eth_chainId"), "0x1")

        contract = wallet_info(self.rpc_url, CONTRACT)
        self.assertTrue(contract["is_contract"])
        self.assertEqual(contract["nonce"], 2)

        wallet = wallet_info(self.rpc_url, WALLET)
        self.assertFalse(wallet["is_contract"])
        self.assertEqual(wallet["balance_native"], "1")
        with self.assertRaises(ValueError):
            wallet_info(self.rpc_url, "not-an-address")

    def test_contract_info_detects_proxy_and_token_standard(self):
        info = contract_info(self.rpc_url, CONTRACT)
        self.assertTrue(info["is_contract"])
        self.assertTrue(info["standards"]["erc20"])
        self.assertFalse(info["standards"]["erc721"])
        self.assertIn("transfer", info["detected_functions"])
        self.assertIsNone(info["minimal_proxy"])

        proxy = contract_info(self.rpc_url, PROXY)
        self.assertEqual(proxy["minimal_proxy"], IMPLEMENTATION.lower())
        self.assertEqual(proxy["eip1967"]["implementation"], IMPLEMENTATION.lower())

        empty = contract_info(self.rpc_url, WALLET)
        self.assertFalse(empty["is_contract"])
        self.assertEqual(empty["bytecode_size"], 0)

    def test_read_contract_storage_and_logs(self):
        called = read_contract(
            self.rpc_url,
            CONTRACT,
            "balanceOf(address)",
            [WALLET],
            ["uint256"],
        )
        self.assertEqual(called["decoded"], [100])
        self.assertTrue(called["calldata"].startswith("0x70a08231"))

        storage = storage_read(self.rpc_url, PROXY, EIP1967_IMPLEMENTATION_SLOT)
        self.assertEqual(storage["words"][0]["value"], "0x" + "00" * 12 + IMPLEMENTATION[2:])

        signature = "Transfer(address,address,uint256)"
        logs = event_logs(
            self.rpc_url,
            CONTRACT,
            event_signature=signature,
            from_block=0,
            to_block="latest",
        )
        self.assertEqual(logs["log_count"], 1)
        self.assertEqual(logs["filter"]["topics"][0], event_topic(signature))
        self.assertEqual(logs["filter"]["fromBlock"], "0x0")

    def test_transaction_inspection(self):
        result = tx_inspect(self.rpc_url, TX_HASH)
        self.assertEqual(result["selector"], "0xa9059cbb")
        self.assertEqual(result["selector_signature"], "transfer(address,uint256)")
        self.assertEqual(result["receipt"]["status"], "success")
        self.assertEqual(result["receipt"]["log_count"], 1)
        with self.assertRaises(ValueError):
            tx_inspect(self.rpc_url, "0x1234")

    def test_solidity_audit_returns_line_numbered_leads(self):
        contracts = Path(self.engagement["workspace"]) / "contracts"
        contracts.mkdir()
        (contracts / "Vulnerable.sol").write_text(SOLIDITY_FIXTURE, encoding="utf-8")
        (contracts / "Empty.sol").write_text("contract Empty {}\n", encoding="utf-8")

        result = audit_solidity(self.engagement_id, "contracts")
        self.assertEqual(result["file_count"], 2)
        lines = SOLIDITY_FIXTURE.splitlines()
        codes = {finding["code"] for finding in result["findings"]}
        self.assertTrue(
            {
                "floating_pragma",
                "reentrancy_external_call_before_state_write",
                "missing_access_control",
                "tx_origin_usage",
                "selfdestruct_usage",
            }
            <= codes
        )
        self.assertTrue(all(finding["line"] >= 1 for finding in result["findings"]))
        self.assertTrue(all(finding["evidence"] for finding in result["findings"]))

        tx_origin_line = next(index for index, line in enumerate(lines, 1) if "tx.origin" in line)
        tx_origin = next(finding for finding in result["findings"] if finding["code"] == "tx_origin_usage")
        self.assertEqual(tx_origin["line"], tx_origin_line)

        selfdestruct_line = next(index for index, line in enumerate(lines, 1) if "selfdestruct" in line)
        selfdestruct = next(finding for finding in result["findings"] if finding["code"] == "selfdestruct_usage")
        self.assertEqual(selfdestruct["line"], selfdestruct_line)

        reentrancy_line = next(index for index, line in enumerate(lines, 1) if ".call{" in line)
        reentrancy = next(
            finding
            for finding in result["findings"]
            if finding["code"] == "reentrancy_external_call_before_state_write"
        )
        self.assertEqual(reentrancy["line"], reentrancy_line)

        artifact = Path(self.engagement["workspace"]) / result["artifact_path"]
        self.assertTrue(artifact.is_file())
        persisted = json.loads(artifact.read_text(encoding="utf-8"))
        self.assertEqual(persisted["finding_count"], result["finding_count"])

        single = audit_solidity(self.engagement_id, "contracts/Vulnerable.sol")
        self.assertEqual(single["file_count"], 1)
        with self.assertRaises(ValueError):
            audit_solidity(self.engagement_id, "contracts/missing")

    def test_rpc_errors_surface_as_value_errors(self):
        with self.assertRaises(ValueError):
            rpc_call(self.rpc_url, "eth_unknownMethod")


if __name__ == "__main__":
    unittest.main()
