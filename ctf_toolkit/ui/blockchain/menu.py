from __future__ import annotations

from ctf_toolkit.blockchain.calldata import parse_calldata
from ctf_toolkit.blockchain.events import decode_event_log_data
from ctf_toolkit.blockchain.protocols import (
    compute_create2_address,
    compute_create_address,
    compute_merkle_root,
    crack_keccak256_wordlist,
    resolve_4byte_selector,
    to_checksum_address,
    convert_eth_unit,
)
from ctf_toolkit.blockchain.revert import decode_revert_reason
from ctf_toolkit.blockchain.storage import (
    compute_array_storage_slot,
    compute_mapping_storage_slot,
    decode_storage_slot_string,
)
from ctf_toolkit.ui.console import render_header, render_menu_panel
from ctf_toolkit.ui.inspector import inspect_output
from ctf_toolkit.utils.io import safe_input, warn


def menu() -> None:
    from ctf_toolkit.main_cli import handle_global_hotkey

    items = [
        ("1", "Parse Calldata / ABI Decoder"),
        ("2", "Decode EVM Revert Reason (Error / Panic / Custom)"),
        ("3", "Solidity Storage Slot Calculator (Mapping / Array / String)"),
        ("4", "Decode Event Log Data"),
        ("5", "Deterministic Contract Address (CREATE & CREATE2)"),
        ("6", "Sorted-Pair Merkle Root Calculator"),
        ("7", "4-Byte Selector & Keccak-256 Wordlist Resolver"),
        ("8", "EIP-55 Address Checksum Formatter"),
        ("9", "Ethereum Denomination Unit Converter (Wei <-> Ether/Gwei)"),
        ("0", "Kembali"),
    ]

    while True:
        render_header("Blockchain & EVM Smart Contracts")
        render_menu_panel("Blockchain / EVM Workbench", items)
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return
        if handle_global_hotkey(choice):
            continue

        if choice == "1":
            raw_hex = safe_input("Calldata hex (0x...): ").strip()
            if not raw_hex:
                warn("Hex input tidak boleh kosong.")
                continue
            try:
                res = parse_calldata(raw_hex)
                inspect_output(res, title="Calldata ABI Analysis", op_name="parse_calldata")
            except Exception as e:
                warn(f"Gagal parse calldata: {e}")
        elif choice == "2":
            rev_hex = safe_input("Revert hex data (0x...): ").strip()
            try:
                inspect_output(decode_revert_reason(rev_hex), title="EVM Revert Reason", op_name="decode_revert_reason")
            except Exception as e:
                warn(f"Error: {e}")
        elif choice == "3":
            print("[1] Mapping Slot keccak256(key . slot)")
            print("[2] Dynamic Array Slot keccak256(slot) + index")
            print("[3] Decode Packed / Short Storage Slot String")
            sub = safe_input("Pilih mode [1-3]: ").strip()
            if sub == "1":
                key = safe_input("Mapping key (address/uint/hex): ").strip()
                slot = int(safe_input("Mapping slot index: ").strip() or "0", 0)
                inspect_output(compute_mapping_storage_slot(key, slot), title="Mapping Storage Slot", op_name="compute_mapping_storage_slot")
            elif sub == "2":
                slot = int(safe_input("Array base slot index: ").strip() or "0", 0)
                idx = int(safe_input("Element index: ").strip() or "0", 0)
                inspect_output(compute_array_storage_slot(slot, idx), title="Array Storage Slot", op_name="compute_array_storage_slot")
            elif sub == "3":
                slot_hex = safe_input("Storage slot 32-byte hex: ").strip()
                inspect_output(decode_storage_slot_string(slot_hex), title="Decoded Storage String", op_name="decode_storage_slot_string")
        elif choice == "4":
            log_hex = safe_input("Event log data hex (0x...): ").strip()
            inspect_output(decode_event_log_data(log_hex), title="Event Log Decoded", op_name="decode_event_log_data")
        elif choice == "5":
            mode = safe_input("[1] CREATE (sender, nonce) / [2] CREATE2 (deployer, salt, init_code_hash): ").strip()
            if mode == "1":
                sender = safe_input("Sender address (0x...): ").strip()
                nonce = int(safe_input("Nonce: ").strip() or "0", 0)
                inspect_output(compute_create_address(sender, nonce), title="CREATE Address", op_name="compute_create_address")
            else:
                dep = safe_input("Deployer address (0x...): ").strip()
                salt = safe_input("Salt hex (0x...): ").strip()
                init_h = safe_input("Init code hash hex (0x...): ").strip()
                inspect_output(compute_create2_address(dep, salt, init_h), title="CREATE2 Address", op_name="compute_create2_address")
        elif choice == "6":
            raw_leaves = safe_input("Leaves (pisahkan dengan koma): ").strip()
            leaves = [x.strip() for x in raw_leaves.split(",") if x.strip()]
            inspect_output(compute_merkle_root(leaves), title="Merkle Root", op_name="compute_merkle_root")
        elif choice == "7":
            target = safe_input("Target 4-byte selector atau 32-byte Keccak hash: ").strip()
            cands = [x.strip() for x in safe_input("Kandidat (pisahkan dengan koma): ").split(",") if x.strip()]
            if len(target.replace("0x", "")) <= 8:
                inspect_output(resolve_4byte_selector(target, cands), title="4-Byte Selector Match", op_name="resolve_4byte_selector")
            else:
                inspect_output(crack_keccak256_wordlist(target, cands), title="Keccak-256 Preimage", op_name="crack_keccak256_wordlist")
        elif choice == "8":
            addr = safe_input("Ethereum address (0x...): ").strip()
            try:
                res_cs = to_checksum_address(addr)
                inspect_output({"raw": addr, "checksummed": res_cs}, title="EIP-55 Checksum Address", op_name="to_checksum_address")
            except Exception as e:
                warn(f"Error checksum: {e}")
        elif choice == "9":
            val = safe_input("Value: ").strip()
            from_u = safe_input("From unit [wei/gwei/ether, default wei]: ").strip() or "wei"
            to_u = safe_input("To unit [ether/gwei/wei, default ether]: ").strip() or "ether"
            try:
                converted = convert_eth_unit(val, from_u, to_u)
                inspect_output({"input": f"{val} {from_u}", "result": f"{converted} {to_u}"}, title="ETH Unit Conversion", op_name="convert_eth_unit")
            except Exception as e:
                warn(f"Error unit conversion: {e}")
        else:
            warn("Pilihan tidak valid.")
