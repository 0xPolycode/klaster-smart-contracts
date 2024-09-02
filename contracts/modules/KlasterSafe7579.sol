// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "account-abstraction-v7/interfaces/PackedUserOperation.sol";
import "account-abstraction-v7/core/UserOperationLib.sol";
import "account-abstraction-v7/core/Helpers.sol";
import { CheckSignatures } from "@rhinestone/checknsignatures/src/CheckNSignatures.sol";
import { LibSort } from "solady/src/utils/LibSort.sol";

import "../interfaces/IERC7579Module.sol";
import "../interfaces/ISafe.sol";

/**
 * @title Klaster Safe ERC-7579 module.
 *         - It allows to validate a part of iTx signed by the Safe multisig owners.
 *         - Exposes updateOwners function which changes ownership structure once the main Safe deployment is changed
 *         - Supports EOA signers only!
 */
contract KlasterSafeModule is IValidator {
    using UserOperationLib for PackedUserOperation;
    using LibSort for address[];
    using CheckSignatures for bytes32;

    error EmptyOwners(address smartAccount);
    error InvalidOwnersList(address smartAccount);
    error DuplicateOwner(address smartAccount);
    error InvalidThreshold(address smartAccount);
    error InvalidSignaturesList(address smartAccount);
    error NotEOA(address smartAccount, address owner);
    error InvalidSignature(address smartAccount);

    string public constant NAME = "Klaster Safe Module";
    string public constant VERSION = "0.1.0";
    address internal constant SENTINEL_OWNERS = address(0x1);

    mapping(address => bool) internal _initialized;
    mapping(address => uint256) internal _thresholds;
    mapping(address => mapping(address => address)) internal _owners;

    struct ModuleInit {
        address module;
        bytes initData;
    }
    struct InitData {
        address singleton;
        address[] owners;
        uint256 threshold;
        address setupTo;
        bytes setupData;
        address safe7579;
        ModuleInit[] validators;
        bytes callData;
    }

    function onInstall(bytes calldata data) external override {
        if (_initialized[msg.sender]) revert AlreadyInitialized(msg.sender);
        _initialized[msg.sender] = true;
    }

    function onUninstall(bytes calldata data) external override {
        if (!_initialized[msg.sender]) revert NotInitialized(msg.sender);
        _initialized[msg.sender] = false;
    }

    function isInitialized(
        address smartAccount
    ) public view override returns (bool) {
        return _initialized[smartAccount];
    }

    function isModuleType(
        uint256 moduleTypeId
    ) external view override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external override returns (uint256) {
        (bytes memory sigBytes, ) = abi.decode(
            userOp.signature,
            (bytes, address)
        );

        (
            bytes32 iTxHash,
            bytes32[] memory proof,
            uint48 lowerBoundTimestamp,
            uint48 upperBoundTimestamp,
            bytes memory signature
        ) = abi.decode(sigBytes, (bytes32, bytes32[], uint48, uint48, bytes));

        bytes32 calculatedUserOpHash = getUserOpHash(
            userOp,
            lowerBoundTimestamp,
            upperBoundTimestamp
        );

        if (!_validateUserOpHash(calculatedUserOpHash, iTxHash, proof)) {
            return VALIDATION_FAILED;
        }
        if (!_verifySignature(userOp, iTxHash, signature)) {
            return VALIDATION_FAILED;
        }

        return
            _packValidationData(
                false,
                upperBoundTimestamp,
                lowerBoundTimestamp
            );
    }

    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    ) external view override returns (bytes4) {}

    /**
     * Calculates userOp hash. Almost works like a regular 4337 userOp hash with few fields added.
     *
     * @param userOp userOp to calculate the hash for
     * @param lowerBoundTimestamp lower bound timestamp set when constructing userOp
     * @param upperBoundTimestamp upper bound timestamp set when constructing userOp
     */
    function getUserOpHash(
        PackedUserOperation calldata userOp,
        uint256 lowerBoundTimestamp,
        uint256 upperBoundTimestamp
    ) public view returns (bytes32 userOpHash) {
        userOpHash = keccak256(
            bytes.concat(
                keccak256(
                    abi.encode(
                        userOp.hash(),
                        lowerBoundTimestamp,
                        upperBoundTimestamp,
                        block.chainid
                    )
                )
            )
        );
    }

    /**
     * Validate if the given userOp is actually a part of the bigger multichain iTx merkle tree.
     *
     * @param userOpHash userOp hash to validate its membership within a multichain iTx tree
     * @param iTxHash merkle root of all the userOps contained in the multichain iTx tree
     * @param proof proof of inclusion
     */
    function _validateUserOpHash(
        bytes32 userOpHash,
        bytes32 iTxHash,
        bytes32[] memory proof
    ) private pure returns (bool) {
        return MerkleProof.verify(proof, iTxHash, userOpHash);
    }

    /**
     * @dev Validates if a given iTx root hash signature is valid and approved by the required number of owners.
     * @param userOp UserOp
     * @param dataHash Hash of the data to be validated.
     * @param signatures Signature to be validated.
     * @return true if signature is valid, false otherwise.
     */
    function _verifySignature(
        PackedUserOperation calldata userOp,
        bytes32 dataHash,
        bytes memory signatures
    ) internal view returns (bool) {
        if (!_initialized[userOp.sender]) revert NotInitialized(userOp.sender);
        if (userOp.initCode.length > 0) {
            return _verifySignatureFromInitData(userOp, dataHash, signatures);
        } else {
            ISafe(userOp.sender).checkSignatures(dataHash, "", signatures);
            return true;
        }
    }

    function _verifySignatureFromInitData(
        PackedUserOperation calldata userOp,
        bytes32 dataHash,
        bytes memory signatures
    ) internal view returns (bool) {
        InitData memory initData = abi.decode(userOp.callData[4:], (InitData));
        
        address[] memory signers = dataHash.recoverNSignatures(signatures, initData.threshold);
        signers.insertionSort();
        
        address[] memory owners = initData.owners;
        // sorting owners here instead of requiring sorted list for improved UX
        owners.insertionSort();
        owners.uniquifySorted();
        
        uint256 ownersLength = owners.length;
        uint256 validSigs;
        for (uint256 i; i < ownersLength; i++) {
            (bool found,) = signers.searchSorted(owners[i]);
            if (found) {
                validSigs++;
                if (validSigs >= initData.threshold) {
                    return true;
                }
            }
        }
        return false;
    }
}
