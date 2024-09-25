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
} from "../../interfaces/IERC7579Module.sol";
import {
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "../../types/Constants.sol";

// Fusion libraries - validate userOp using on-chain tx or off-chain permit
import "../../libraries/fusion/PermitValidator.sol";
import "../../libraries/fusion/TxValidator.sol";

struct ECDSAValidatorStorage {
    address owner;
}

contract FusionValidator is IValidator, IHook {
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
        uint8 sigType = uint8(userOp.signature[0]);
        bytes memory sigData = userOp.signature[1:];
        if (sigType == 0x00) { // signature[1:] is just a signed userOpHash
            if (!_validateSignature(userOpHash, sigData, owner)) {
                return VALIDATION_FAILED;
            }
        } else if (sigType == 0x01) { // signature[1:] is a fully signed serialized evm transaction
            if (!TxValidator.validate(sigData, userOpHash, owner)) { // invoke TxValidator
                return VALIDATION_FAILED;
            }
        } else if (sigType == 0x02) { // signature[1:] is a DecodedErc20PermitSig struct containing signed Permit message
            if (!PermitValidator.validate(sigData, userOp.sender, userOpHash, owner)) { // invoke PermitValidator
                return VALIDATION_FAILED;
            }
        } else { // throw; unsupported sig type
            revert("FusionValidator:: unsupported userOp.signature type");
        }

        return VALIDATION_SUCCESS;
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
