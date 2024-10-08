// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {BaseAuthorizationModule} from "../../../biconomy/contracts/smart-account/modules/BaseAuthorizationModule.sol";
import "@account-abstraction/contracts/interfaces/UserOperation.sol";
import "@account-abstraction/contracts/core/Helpers.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title Klaster ECDSA ownership Authorization module for Biconomy Smart Accounts compatible with the Klaster execution network.
 * @dev Compatible with Biconomy Modular Interface v 0.1
 *         - It allows to validate a part of iTx signed by EOA private key.
 *         - EIP-1271 compatible (ensures Smart Account can validate signed messages).
 *         - One owner per Smart Account.
 *         - Does not support outdated eth_sign flow for cheaper validations
 *         (see https://support.metamask.io/hc/en-us/articles/14764161421467-What-is-eth-sign-and-why-is-it-a-risk-)
 * !!!!!!! Only EOA owners supported, no Smart Account Owners
 *         For Smart Contract Owners check SmartContractOwnership module instead
 *
 */
contract KlasterEcdsaModule is BaseAuthorizationModule {
    using ECDSA for bytes32;
    using UserOperationLib for UserOperation;

    string public constant NAME = "Klaster ECDSA Module";
    string public constant VERSION = "0.1.0";
    mapping(address => address) internal _smartAccountOwners;

    event OwnershipTransferred(address indexed smartAccount, address indexed oldOwner, address indexed newOwner);

    error NoOwnerRegisteredForSmartAccount(address smartAccount);
    error AlreadyInitedForSmartAccount(address smartAccount);
    error WrongSignatureLength();
    error NotEOA(address account);
    error ZeroAddressNotAllowedAsOwner();

    /**
     * @dev Initializes the module for a Smart Account.
     * Should be used at a time of first enabling the module for a Smart Account.
     * @param eoaOwner The owner of the Smart Account. Should be EOA!
     */
    function initForSmartAccount(address eoaOwner) external returns (address) {
        if (_smartAccountOwners[msg.sender] != address(0)) {
            revert AlreadyInitedForSmartAccount(msg.sender);
        }
        if (eoaOwner == address(0)) revert ZeroAddressNotAllowedAsOwner();
        if (_isSmartContract(eoaOwner)) revert NotEOA(eoaOwner);
        _smartAccountOwners[msg.sender] = eoaOwner;
        return address(this);
    }

    /**
     * @dev Sets/changes an for a Smart Account.
     * Should be called by Smart Account itself.
     * @param owner The owner of the Smart Account.
     */
    function transferOwnership(address owner) external {
        if (_isSmartContract(owner)) revert NotEOA(owner);
        if (owner == address(0)) revert ZeroAddressNotAllowedAsOwner();
        _transferOwnership(msg.sender, owner);
    }

    /**
     * @dev Renounces ownership
     * should be called by Smart Account.
     */
    function renounceOwnership() external {
        _transferOwnership(msg.sender, address(0));
    }

    /**
     * @dev Returns the owner of the Smart Account. Reverts for Smart Accounts without owners.
     * @param smartAccount Smart Account address.
     * @return owner The owner of the Smart Account.
     */
    function getOwner(address smartAccount) external view returns (address) {
        address owner = _smartAccountOwners[smartAccount];
        if (owner == address(0)) {
            revert NoOwnerRegisteredForSmartAccount(smartAccount);
        }
        return owner;
    }

    /**
     * Calculates userOp hash. Almost works like a regular 4337 userOp hash with few fields added.
     *
     * @param userOp userOp to calculate the hash for
     * @param lowerBoundTimestamp lower bound timestamp set when constructing userOp
     * @param upperBoundTimestamp upper bound timestamp set when constructing userOp
     */
    function getUserOpHash(UserOperation calldata userOp, uint256 lowerBoundTimestamp, uint256 upperBoundTimestamp)
        public
        view
        returns (bytes32 userOpHash)
    {
        userOpHash = keccak256(
            bytes.concat(keccak256(abi.encode(userOp.hash(), lowerBoundTimestamp, upperBoundTimestamp, block.chainid)))
        );
    }

    /**
     * @dev validates userOperation
     * @param userOp User Operation to be validated.
     * @param userOpHash Not used. Here for interface compatibility. iTxHash (merkle root) is used and encoded in userOp.signature
     * @return sigValidationResult ValidationData - success if:
     *                                  1. the given userOp belongs to the merkle tree with given iTxHash
     *                                  2. the given iTxHash has been signed by the owner of this smart account
     */
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        virtual
        returns (uint256)
    {
        (bytes memory sigBytes,) = abi.decode(userOp.signature, (bytes, address));

        (
            bytes32 iTxHash,
            bytes32[] memory proof,
            uint48 lowerBoundTimestamp,
            uint48 upperBoundTimestamp,
            bytes memory userEcdsaSignature
        ) = abi.decode(sigBytes, (bytes32, bytes32[], uint48, uint48, bytes));

        bytes32 calculatedUserOpHash = getUserOpHash(userOp, lowerBoundTimestamp, upperBoundTimestamp);
        if (!_validateUserOpHash(calculatedUserOpHash, iTxHash, proof)) {
            return SIG_VALIDATION_FAILED;
        }

        if (!_verifySignature(iTxHash, userEcdsaSignature, userOp.sender)) {
            return SIG_VALIDATION_FAILED;
        }

        return _packValidationData(false, upperBoundTimestamp, lowerBoundTimestamp);
    }

    /**
     * @dev Validates a signature for a message.
     * To be called from a Smart Account.
     * @param dataHash Exact hash of the data that was signed.
     * @param moduleSignature Signature to be validated.
     * @return EIP1271_MAGIC_VALUE if signature is valid, 0xffffffff otherwise.
     */
    function isValidSignature(bytes32 dataHash, bytes memory moduleSignature)
        public
        view
        virtual
        override
        returns (bytes4)
    {
        return isValidSignatureForAddress(dataHash, moduleSignature, msg.sender);
    }

    /**
     * @dev Validates a signature for a message signed by address.
     * @dev Also try dataHash.toEthSignedMessageHash()
     * @param dataHash hash of the data
     * @param moduleSignature Signature to be validated.
     * @param smartAccount expected signer Smart Account address.
     * @return EIP1271_MAGIC_VALUE if signature is valid, 0xffffffff otherwise.
     */
    function isValidSignatureForAddress(bytes32 dataHash, bytes memory moduleSignature, address smartAccount)
        public
        view
        virtual
        returns (bytes4)
    {
        if (_verifySignature(dataHash, moduleSignature, smartAccount)) {
            return EIP1271_MAGIC_VALUE;
        }
        return bytes4(0xffffffff);
    }

    /**
     * @dev Transfers ownership for smartAccount and emits an event
     * @param newOwner Smart Account address.
     */
    function _transferOwnership(address smartAccount, address newOwner) internal {
        address _oldOwner = _smartAccountOwners[smartAccount];
        _smartAccountOwners[smartAccount] = newOwner;
        emit OwnershipTransferred(smartAccount, _oldOwner, newOwner);
    }

    function _validateUserOpHash(bytes32 userOpHash, bytes32 iTxHash, bytes32[] memory proof)
        private
        pure
        returns (bool)
    {
        return MerkleProof.verify(proof, iTxHash, userOpHash);
    }

    /**
     * @dev Validates a signature for a message.
     * @dev Check if signature was made over dataHash.toEthSignedMessageHash() or just dataHash
     * The former is for personal_sign, the latter for the typed_data sign
     * Only EOA owners supported, no Smart Account Owners
     * For Smart Contract Owners check SmartContractOwnership Module instead
     * @param dataHash Hash of the data to be validated.
     * @param signature Signature to be validated.
     * @param smartAccount expected signer Smart Account address.
     * @return true if signature is valid, false otherwise.
     */
    function _verifySignature(bytes32 dataHash, bytes memory signature, address smartAccount)
        internal
        view
        returns (bool)
    {
        address expectedSigner = _smartAccountOwners[smartAccount];
        if (expectedSigner == address(0)) {
            revert NoOwnerRegisteredForSmartAccount(smartAccount);
        }
        if (signature.length < 65) revert WrongSignatureLength();
        address recovered = (dataHash.toEthSignedMessageHash()).recover(signature);
        if (expectedSigner == recovered) {
            return true;
        }
        recovered = dataHash.recover(signature);
        if (expectedSigner == recovered) {
            return true;
        }
        return false;
    }

    /**
     * @dev Checks if the address provided is a smart contract.
     * @param account Address to be checked.
     */
    function _isSmartContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}
