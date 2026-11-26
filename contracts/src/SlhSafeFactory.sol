// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SlhSigner} from "./SlhSigner.sol";

interface ISafeProxyFactory {
    function createProxyWithNonce(address singleton, bytes memory initializer, uint256 saltNonce) external returns (address);
    function proxyCreationCode() external pure returns (bytes memory);
}

interface ISafeSetup {
    function setup(address[] calldata owners, uint256 threshold, address to, bytes calldata data, address fallbackHandler,
        address paymentToken, uint256 payment, address payable paymentReceiver) external;
}

/// Makes a Safe 1.4.1 whose only owner is an SLH-DSA key, in one transaction. The addresses depend only on
/// the key (and n), so anyone can work them out before anything is made, and anyone may make them.
contract SlhSafeFactory {
    address public constant SAFE_FACTORY = 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67;
    address public constant SAFE_L2 = 0x29fcB43b46531BcA003ddC8FCB67FFE91900C762;
    address public constant HANDLER = 0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99;

    event Made(bytes16 indexed seed, bytes16 indexed root, address owner, address safe);

    /// Where this key's owner contract is, or will be.
    function ownerOf(bytes16 seed, bytes16 root, bool fast) public view returns (address) {
        bytes32 code = keccak256(abi.encodePacked(type(SlhSigner).creationCode, abi.encode(seed, root, fast)));
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), bytes32(0), code)))));
    }

    function initializer(address owner) public pure returns (bytes memory) {
        address[] memory owners = new address[](1);
        owners[0] = owner;
        return abi.encodeCall(ISafeSetup.setup, (owners, 1, address(0), "", HANDLER, address(0), 0, payable(0)));
    }

    /// Where this key's Safe number n is, or will be.
    function safeOf(bytes16 seed, bytes16 root, bool fast, uint256 n) public view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer(ownerOf(seed, root, fast))), n));
        bytes32 code = keccak256(abi.encodePacked(ISafeProxyFactory(SAFE_FACTORY).proxyCreationCode(), uint256(uint160(SAFE_L2))));
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), SAFE_FACTORY, salt, code)))));
    }

    /// Makes the owner contract (if it isn't there yet) and Safe number n.
    function make(bytes16 seed, bytes16 root, bool fast, uint256 n) external returns (address owner, address safe) {
        owner = ownerOf(seed, root, fast);
        if (owner.code.length == 0) new SlhSigner{salt: 0}(seed, root, fast);
        safe = ISafeProxyFactory(SAFE_FACTORY).createProxyWithNonce(SAFE_L2, initializer(owner), n);
        emit Made(seed, root, owner, safe);
    }
}
