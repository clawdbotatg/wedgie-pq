// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// A Safe owner that is an SLH-DSA key (FIPS 205, SHA2-128s or SHA2-128f) instead of an elliptic-curve key.
/// The Safe asks it "is this signature good?" (EIP-1271). It checks an SLH-DSA signature of the 32-byte
/// hash, as a plain message with no context, by the one public key it was made with. The key never changes.
/// Every hash goes through the SHA-256 precompile.
contract SlhSigner {
    bytes16 public immutable pkSeed;
    bytes16 public immutable pkRoot;
    /// True: SHA2-128f (17,088-byte signatures). False: SHA2-128s (7,856 bytes).
    bool public immutable fast;

    constructor(bytes16 seed, bytes16 root, bool fast_) {
        pkSeed = seed;
        pkRoot = root;
        fast = fast_;
    }

    /// EIP-1271.
    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        return verify(hash, sig) ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }

    /// The older form (Safe 1.3.0 and 1.4.1 call this one, with the bytes whose keccak256 is the hash).
    function isValidSignature(bytes calldata data, bytes calldata sig) external view returns (bytes4) {
        return verify(keccak256(data), sig) ? bytes4(0x20c13b0b) : bytes4(0xffffffff);
    }

    /// True if sig is this key's SLH-DSA signature of hash.
    function verify(bytes32 hash, bytes calldata sig) public view returns (bool ok) {
        // hp: tree height per layer. d: layers. a: FORS tree height. k: FORS trees.
        (uint256 hp, uint256 d, uint256 a, uint256 k) = fast ? (3, 22, 6, 33) : (9, 7, 12, 14);
        if (sig.length != 16 * (1 + k * (a + 1) + d * (35 + hp))) return false;
        bytes32 seed = pkSeed;
        bytes32 root = pkRoot;
        assembly ("memory-safe") {
            // Every 16-byte value sits in the top half of a word. What is under it is never hashed.
            // buf: PK.seed, 48 zeros, a 22-byte address, then 16 or 32 bytes: one tweaked hash.
            // big: the same start, then up to 35 values: the hash over a WOTS key or the FORS roots.
            let buf := mload(0x40)
            let big := add(buf, 160)
            let tmp := add(big, 704)
            mstore(0x40, add(tmp, 256))
            mstore(buf, seed)
            mstore(add(buf, 32), 0)
            mstore(big, seed)
            mstore(add(big, 32), 0)
            ok := 1

            // The message digest: MGF1(R, PK.seed, SHA-256(R, PK.seed, PK.root, 0, 0, hash)), 64 bytes at dig.
            let dig := add(tmp, 128)
            mstore(tmp, calldataload(sig.offset))
            mstore(add(tmp, 16), seed)
            mstore(add(tmp, 32), root)
            mstore(add(tmp, 48), 0)
            mstore(add(tmp, 50), hash)
            ok := and(ok, staticcall(gas(), 2, tmp, 82, add(tmp, 32), 32))
            mstore(add(tmp, 64), 0)
            ok := and(ok, staticcall(gas(), 2, tmp, 68, dig, 32))
            mstore8(add(tmp, 67), 1)
            ok := and(ok, staticcall(gas(), 2, tmp, 68, add(dig, 32), 32))

            // From the digest: k FORS leaves (a bits each), then which tree, then which leaf in it.
            let tree
            let leaf
            {
                let mdLen := shr(3, add(mul(k, a), 7))
                let tBits := mul(hp, sub(d, 1))
                let tLen := shr(3, add(tBits, 7))
                tree := and(shr(sub(256, shl(3, tLen)), mload(add(dig, mdLen))), sub(shl(tBits, 1), 1))
                leaf := and(shr(sub(256, shl(3, shr(3, add(hp, 7)))), mload(add(dig, add(mdLen, tLen)))), sub(shl(hp, 1), 1))
            }

            // An address is layer(1) tree(8) type(1) w1(4) w2(4) w3(4): 176 bits, written at buf + 64.
            let at := add(sig.offset, 16)
            let node

            // FORS: each tree's secret and path lead to its root; the hash of the roots is what layer 0 signs.
            {
                let base := or(shl(104, tree), or(shl(96, 3), shl(64, leaf)))
                mstore(add(big, 64), shl(80, or(shl(104, tree), or(shl(96, 4), shl(64, leaf)))))
                for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                    let bp := mul(i, a)
                    let idx := shr(sub(256, a), shl(and(bp, 7), mload(add(dig, shr(3, bp)))))
                    let ti := add(shl(a, i), idx)
                    mstore(add(buf, 64), shl(80, or(base, ti)))
                    mstore(add(buf, 86), calldataload(at))
                    ok := and(ok, staticcall(gas(), 2, buf, 102, 0, 32))
                    node := mload(0)
                    at := add(at, 16)
                    for { let j := 0 } lt(j, a) { j := add(j, 1) } {
                        ti := shr(1, ti)
                        mstore(add(buf, 64), shl(80, or(base, or(shl(32, add(j, 1)), ti))))
                        switch and(shr(j, idx), 1)
                        case 0 {
                            mstore(add(buf, 86), node)
                            mstore(add(buf, 102), calldataload(at))
                        }
                        default {
                            mstore(add(buf, 86), calldataload(at))
                            mstore(add(buf, 102), node)
                        }
                        ok := and(ok, staticcall(gas(), 2, buf, 118, 0, 32))
                        node := mload(0)
                        at := add(at, 16)
                    }
                    mstore(add(big, add(86, shl(4, i))), node)
                }
                ok := and(ok, staticcall(gas(), 2, big, add(86, shl(4, k)), 0, 32))
                node := mload(0)
            }

            // The hypertree: each layer's WOTS key signs the node below it. The top must be PK.root.
            for { let layer := 0 } lt(layer, d) { layer := add(layer, 1) } {
                let lt_ := or(shl(168, layer), shl(104, tree))
                mstore(add(big, 64), shl(80, or(lt_, or(shl(96, 1), shl(64, leaf)))))
                let csum := 0
                for { let i := 0 } lt(i, 35) { i := add(i, 1) } {
                    // digit i of the node: 32 nibbles, then the checksum's 3
                    let dg
                    switch lt(i, 32)
                    case 1 {
                        dg := and(shr(sub(252, shl(2, i)), node), 15)
                        csum := add(csum, sub(15, dg))
                    }
                    default { dg := and(shr(shl(2, sub(34, i)), csum), 15) }
                    mstore(add(buf, 64), shl(80, or(lt_, or(shl(64, leaf), shl(32, i)))))
                    mstore(add(buf, 86), calldataload(add(at, shl(4, i))))
                    // the rest of the chain, in place: only the address's last byte changes
                    for { } lt(dg, 15) { dg := add(dg, 1) } {
                        mstore8(add(buf, 85), dg)
                        ok := and(ok, staticcall(gas(), 2, buf, 102, add(buf, 86), 32))
                    }
                    mstore(add(big, add(86, shl(4, i))), mload(add(buf, 86)))
                }
                ok := and(ok, staticcall(gas(), 2, big, 646, 0, 32))
                node := mload(0)
                at := add(at, 560)
                let tb := or(lt_, shl(96, 2))
                for { let j := 0 } lt(j, hp) { j := add(j, 1) } {
                    mstore(add(buf, 64), shl(80, or(tb, or(shl(32, add(j, 1)), shr(add(j, 1), leaf)))))
                    switch and(shr(j, leaf), 1)
                    case 0 {
                        mstore(add(buf, 86), node)
                        mstore(add(buf, 102), calldataload(at))
                    }
                    default {
                        mstore(add(buf, 86), calldataload(at))
                        mstore(add(buf, 102), node)
                    }
                    ok := and(ok, staticcall(gas(), 2, buf, 118, 0, 32))
                    node := mload(0)
                    at := add(at, 16)
                }
                leaf := and(tree, sub(shl(hp, 1), 1))
                tree := shr(hp, tree)
            }
            ok := and(ok, eq(shr(128, node), shr(128, root)))
        }
    }
}
