// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {SlhSigner} from "../src/SlhSigner.sol";

interface IFactory {
    function createProxyWithNonce(address singleton, bytes memory initializer, uint256 saltNonce) external returns (address);
}

interface ISafe {
    function setup(address[] calldata owners, uint256 threshold, address to, bytes calldata data, address fallbackHandler,
        address paymentToken, uint256 payment, address payable paymentReceiver) external;
    function getTransactionHash(address to, uint256 value, bytes calldata data, uint8 operation, uint256 safeTxGas,
        uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, uint256 nonce) external view returns (bytes32);
    function execTransaction(address to, uint256 value, bytes calldata data, uint8 operation, uint256 safeTxGas,
        uint256 baseGas, uint256 gasPrice, address gasToken, address payable refundReceiver, bytes memory signatures)
        external payable returns (bool);
}

/// A real Safe 1.4.1 whose only owner is an SLH-DSA key sends ETH. Needs a fork and the C signer:
///   cc -O2 -DSLH_HOST -o /tmp/slhhost ../mp/slh/slh.c
///   forge test --ffi --match-contract SafeTest --fork-url <an Alchemy URL> -vv
contract SafeTest is Test {
    address constant FACTORY = 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67;
    address constant SAFE_L2 = 0x29fcB43b46531BcA003ddC8FCB67FFE91900C762;
    address constant HANDLER = 0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99;
    string constant SK = "000102030405060708090a0b0c0d0e0f";
    string constant PRF = "101112131415161718191a1b1c1d1e1f";
    string constant SEED = "202122232425262728292a2b2c2d2e2f";

    function sign(bool fast, bytes32 hash) internal returns (bytes16 root, bytes memory sig) {
        string[] memory c = new string[](3);
        c[0] = "bash";
        c[1] = "-c";
        // root and signature, one hex string
        c[2] = string.concat("/tmp/slhhost ", fast ? "1 " : "0 ", SK, " ", PRF, " ", SEED, " $(echo 0000", vm.toString(abi.encodePacked(hash)), " | sed s/0x//) | tr -d '\\n' | sed s/0x//");
        bytes memory out = vm.ffi(c);
        root = bytes16(out);
        sig = new bytes(out.length - 16);
        for (uint256 i = 0; i < sig.length; i++) sig[i] = out[i + 16];
    }

    function send(bool fast) internal {
        if (FACTORY.code.length == 0) return;      // no fork
        (bytes16 root,) = sign(fast, bytes32(0));
        SlhSigner owner = new SlhSigner(bytes16(vm.parseBytes(string.concat("0x", SEED))), root, fast);
        address[] memory owners = new address[](1);
        owners[0] = address(owner);
        ISafe safe = ISafe(IFactory(FACTORY).createProxyWithNonce(SAFE_L2,
            abi.encodeCall(ISafe.setup, (owners, 1, address(0), "", HANDLER, address(0), 0, payable(0))), 1));
        vm.deal(address(safe), 1 ether);
        address to = address(0xBEEF);
        uint256 had = to.balance;
        bytes32 h = safe.getTransactionHash(to, 0.25 ether, "", 0, 0, 0, 0, address(0), address(0), 0);
        (, bytes memory sig) = sign(fast, h);
        // a contract owner's signature: the owner, where its bytes start (65), type 0, then the bytes
        bytes memory sigs = abi.encodePacked(uint256(uint160(address(owner))), uint256(65), uint8(0), sig.length, sig);
        bytes memory call = abi.encodeCall(ISafe.execTransaction, (to, 0.25 ether, "", 0, 0, 0, 0, address(0), payable(0), sigs));
        uint256 zeros;
        for (uint256 i = 0; i < call.length; i++) if (call[i] == 0) zeros++;
        uint256 g = gasleft();
        (bool ok,) = address(safe).call(call);
        g -= gasleft();
        assertTrue(ok);
        assertEq(to.balance - had, 0.25 ether);
        uint256 data = zeros * 4 + (call.length - zeros) * 16;
        uint256 floor = 21000 + (zeros + (call.length - zeros) * 4) * 10;
        uint256 total = 21000 + data + g;
        console.log(fast ? "128f" : "128s", "run", g);
        console.log("  whole transaction", total > floor ? total : floor);
        // the same signature can't be used again, and a wrong one is refused
        vm.expectRevert();
        safe.execTransaction(to, 0.25 ether, "", 0, 0, 0, 0, address(0), payable(0), sigs);
    }

    function test_small() public { send(false); }
    function test_fast() public { send(true); }
}
