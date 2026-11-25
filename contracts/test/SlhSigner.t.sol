// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {SlhSigner} from "../src/SlhSigner.sol";

/// Signatures in vectors.json come from the wedgie's own signer (mp/slh/slh.c), which OpenSSL also accepts.
contract SlhSignerTest is Test {
    struct V {
        bool fast;
        bytes32 hash;
        bytes16 root;
        bytes16 seed;
        bytes sig;
    }

    function vectors() internal view returns (V[] memory vs) {
        string memory j = vm.readFile("test/vectors.json");
        vs = new V[](6);
        for (uint256 i = 0; i < 6; i++) {
            string memory at = string.concat(".[", vm.toString(i), "].");
            vs[i] = V({
                fast: vm.parseJsonBool(j, string.concat(at, "fast")),
                hash: sha256(abi.encodePacked("slh vector ", i)),      // what each vector signed
                root: bytes16(vm.parseJsonBytes(j, string.concat(at, "root"))),
                seed: bytes16(vm.parseJsonBytes(j, string.concat(at, "seed"))),
                sig: vm.parseJsonBytes(j, string.concat(at, "sig"))
            });
        }
    }

    function test_good_and_bad() public {
        V[] memory vs = vectors();
        assertEq(vs.length, 6);
        for (uint256 i = 0; i < vs.length; i++) {
            V memory v = vs[i];
            SlhSigner s = new SlhSigner(v.seed, v.root, v.fast);
            uint256 g = gasleft();
            bool ok = s.verify(v.hash, v.sig);
            g -= gasleft();
            console.log(v.fast ? "128f" : "128s", v.sig.length, g);
            assertTrue(ok);
            assertEq(s.isValidSignature(v.hash, v.sig), bytes4(0x1626ba7e));
            bytes memory data = abi.encodePacked("some bytes", i);
            assertEq(s.isValidSignature(data, v.sig), bytes4(0xffffffff));
            // another hash, a short signature, the other key
            assertFalse(s.verify(bytes32(uint256(v.hash) ^ 1), v.sig));
            assertFalse(new SlhSigner(v.seed, bytes16(uint128(v.root) ^ 1), v.fast).verify(v.hash, v.sig));
            assertFalse(new SlhSigner(bytes16(uint128(v.seed) ^ 1), v.root, v.fast).verify(v.hash, v.sig));
            assertFalse(new SlhSigner(v.seed, v.root, !v.fast).verify(v.hash, v.sig));
            // one bit wrong, at 40 places across the signature
            for (uint256 n = 0; n < 40; n++) {
                uint256 at = (n * v.sig.length) / 40 + (n % 16);
                bytes memory bad = bytes.concat(v.sig);
                bad[at] = bytes1(uint8(bad[at]) ^ uint8(1 << (n % 8)));
                assertFalse(s.verify(v.hash, bad));
            }
        }
    }

    /// Too little gas must fail, never pass.
    function test_low_gas() public {
        V memory v = vectors()[0];
        SlhSigner s = new SlhSigner(v.seed, v.root, v.fast);
        for (uint256 g = 30000; g < 900000; g += 17000) {
            (bool ran, bytes memory out) = address(s).staticcall{gas: g}(abi.encodeCall(SlhSigner.verify, (v.hash, v.sig)));
            if (ran && abi.decode(out, (bool))) {
                assertGt(g, 400000);
            }
        }
    }
}
