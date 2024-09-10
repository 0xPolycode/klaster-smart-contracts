// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;


import "@account-abstraction/contracts/interfaces/UserOperation.sol";
import "@account-abstraction/contracts/core/Helpers.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "../../interfaces/IKernelValidator.sol";
import "../../interfaces/IERC7579Module.sol";

struct ECDSAValidatorStorage {
    address owner;
}

contract KlasterEcdsaKernelValidator is IKernelValidator {
    using ECDSA for bytes32;
    using UserOperationLib for UserOperation;

    event OwnerChanged(address indexed kernel, address indexed oldOwner, address indexed newOwner);

    mapping(address => ECDSAValidatorStorage) public ecdsaValidatorStorage;

    function disable(bytes calldata) external payable override {
        delete ecdsaValidatorStorage[msg.sender];
    }

    function enable(bytes calldata _data) external payable override {
        address owner = address(bytes20(_data[0:20]));
        address oldOwner = ecdsaValidatorStorage[msg.sender].owner;
        ecdsaValidatorStorage[msg.sender].owner = owner;
        emit OwnerChanged(msg.sender, oldOwner, owner);
    }

    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256)
        external
        payable
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

    function validateSignature(bytes32 hash, bytes calldata signature) public view override returns (uint256) {
        address owner = ecdsaValidatorStorage[msg.sender].owner;
        if (!_validateSignature(hash, signature, owner)) {
            return VALIDATION_FAILED;
        }
        return VALIDATION_SUCCESS;
    }

    function validCaller(address _caller, bytes calldata) external view override returns (bool) {
        return ecdsaValidatorStorage[msg.sender].owner == _caller;
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

    function _validateUserOpHash(bytes32 userOpHash, bytes32 iTxHash, bytes32[] memory proof)
        private
        pure
        returns (bool)
    {
        return MerkleProof.verify(proof, iTxHash, userOpHash);
    }

    function _validateSignature(bytes32 dataHash, bytes memory signature, address expectedSigner)
        internal
        pure
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
