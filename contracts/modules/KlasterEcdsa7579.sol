// SPDX-License-Identifier: MIT

pragma solidity 0.8.23;

import "account-abstraction-v7/core/UserOperationLib.sol";
import "account-abstraction-v7/interfaces/PackedUserOperation.sol";
import "account-abstraction-v7/core/Helpers.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {
    IValidator,
    IHook,
    VALIDATION_SUCCESS,
    VALIDATION_FAILED,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK
} from "../interfaces/IERC7579Module.sol";
import {
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "../types/Constants.sol";

struct ECDSAValidatorStorage {
    address owner;
}

contract KlasterEcdsa7579 is IValidator, IHook {
    using UserOperationLib for PackedUserOperation;
    using ECDSA for bytes32;

    event OwnerRegistered(address indexed kernel, address indexed owner);

    mapping(address => ECDSAValidatorStorage) public ecdsaValidatorStorage;

    function onInstall(bytes calldata _data) external override {
        address owner = address(bytes20(_data[0:20]));
        ecdsaValidatorStorage[msg.sender].owner = owner;
        emit OwnerRegistered(msg.sender, owner);
    }

    function onUninstall(bytes calldata) external override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        delete ecdsaValidatorStorage[msg.sender];
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR || typeID == MODULE_TYPE_HOOK;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        return ecdsaValidatorStorage[smartAccount].owner != address(0);
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        override
        returns (uint256)
    {
        address owner = ecdsaValidatorStorage[msg.sender].owner;
        (
            bytes32 iTxHash,
            bytes32[] memory proof,
            uint48 lowerBoundTimestamp,
            uint48 upperBoundTimestamp,
            bytes memory userEcdsaSignature
        ) = abi.decode(userOp.signature, (bytes32, bytes32[], uint48, uint48, bytes));

        bytes32 calculatedUserOpHash = getUserOpHash(userOp, lowerBoundTimestamp, upperBoundTimestamp);
        if (!_validateUserOpHash(calculatedUserOpHash, iTxHash, proof)) {
            return VALIDATION_FAILED;
        }

        if (!_validateSignature(iTxHash, userEcdsaSignature, owner)) {
            return VALIDATION_FAILED;
        }

        return _packValidationData(false, upperBoundTimestamp, lowerBoundTimestamp);
    }

    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        address owner = ecdsaValidatorStorage[msg.sender].owner;
        if (owner == ECDSA.recover(hash, sig)) {
            return ERC1271_MAGICVALUE;
        }
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        address recovered = ECDSA.recover(ethHash, sig);
        if (owner != recovered) {
            return ERC1271_INVALID;
        }
        return ERC1271_MAGICVALUE;
    }

    function preCheck(address msgSender, uint256 value, bytes calldata)
        external
        override
        returns (bytes memory)
    {
        require(msgSender == ecdsaValidatorStorage[msg.sender].owner, "ECDSAValidator: sender is not owner");
        return hex"";
    }

    function postCheck(bytes calldata hookData) external override {}

        /**
     * Calculates userOp hash. Almost works like a regular 4337 userOp hash with few fields added.
     *
     * @param userOp userOp to calculate the hash for
     * @param lowerBoundTimestamp lower bound timestamp set when constructing userOp
     * @param upperBoundTimestamp upper bound timestamp set when constructing userOp
     */
    function getUserOpHash(PackedUserOperation calldata userOp, uint256 lowerBoundTimestamp, uint256 upperBoundTimestamp)
        public
        view
        returns (bytes32 userOpHash)
    {
        userOpHash = keccak256(
            bytes.concat(keccak256(abi.encode(userOp.hash(), lowerBoundTimestamp, upperBoundTimestamp, block.chainid)))
        );
    }

    function _validateUserOpHash(bytes32 userOpHash, bytes32 iTxHash, bytes32[] memory proof)
        private
        pure
        returns (bool)
    {
        return MerkleProof.verify(proof, iTxHash, userOpHash);
    }

    function _validateSignature(bytes32 dataHash, bytes memory signature, address expectedSigner)
        internal
        view
        returns (bool)
    {
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
}
