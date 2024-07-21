// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "../interfaces/IERC7579Module.sol";
import "../util/UserOperationLib.sol";
import "../util/Helpers.sol";

/**
 * @title Klaster Safe ERC-7579 module.
 *         - It allows to validate a part of iTx signed by the Safe multisig owners.
 *         - Exposes updateOwners function which changes ownership structure once the main Safe deployment is changed
 *         - Supports EOA signers only!
 */
contract KlasterSafeModule is IValidator {
    using UserOperationLib for PackedUserOperation;

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

    function onInstall(bytes calldata data) external override {
        if (_initialized[msg.sender]) revert AlreadyInitialized(msg.sender);
        (address[] memory owners, uint256 threshold) = abi.decode(
            data,
            (address[], uint256)
        );
        _updateOwners(owners, threshold);
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

    /**
     * @dev Sets the new ownership structure on the already initialized Safe module.
     *      Should be called by Smart Account itself.
     * @param owners List of the owners
     * @param threshold Threshold
     */
    function updateOwners(address[] memory owners, uint256 threshold) external {
        if (!_initialized[msg.sender]) revert NotInitialized(msg.sender);
        _updateOwners(owners, threshold);
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
        if (!_verifySignature(iTxHash, signature, userOp.sender)) {
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
     * @param dataHash Hash of the data to be validated.
     * @param signatures Signature to be validated.
     * @param smartAccount expected signer Smart Account address.
     * @return true if signature is valid, false otherwise.
     */
    function _verifySignature(
        bytes32 dataHash,
        bytes memory signatures,
        address smartAccount
    ) internal view returns (bool) {
        if (!_initialized[smartAccount]) revert NotInitialized(msg.sender);

        uint256 requiredSignatures = _thresholds[smartAccount];
        // Check that the provided signature data is not too short
        if (signatures.length < requiredSignatures * 65)
            revert InvalidSignaturesList(smartAccount);

        // There cannot be an owner with address 0.
        address lastOwner = address(0);
        address currentOwner;
        uint256 v; // Implicit conversion from uint8 to uint256 will be done for v received from signatureSplit(...).
        bytes32 r;
        bytes32 s;
        uint256 i;
        for (i = 0; i < requiredSignatures; i++) {
            (v, r, s) = _signatureSplit(signatures, i);
            if (v == 0) {
                // If v is 0 then it is a contract signature - revert. Smart contract owners not supported.
                revert InvalidSignature(smartAccount);
            } else if (v > 30) {
                // If v > 30 then default va (27,28) has been adjusted for eth_sign flow
                // To support eth_sign and similar we adjust v and hash the messageHash with the Ethereum message prefix before applying ecrecover
                currentOwner = ecrecover(
                    keccak256(
                        abi.encodePacked(
                            "\x19Ethereum Signed Message:\n32",
                            dataHash
                        )
                    ),
                    uint8(v - 4),
                    r,
                    s
                );
            } else {
                // Default is the ecrecover flow with the provided data hash
                // Use ecrecover with the messageHash for EOA signatures
                currentOwner = ecrecover(dataHash, uint8(v), r, s);
            }
            if (
                currentOwner <= lastOwner ||
                _owners[smartAccount][currentOwner] == address(0) ||
                currentOwner == SENTINEL_OWNERS
            ) {
                revert InvalidSignature(smartAccount);
            }
            lastOwner = currentOwner;
        }

        return true;
    }

    /**
     * HELPERS
     */
    function _signatureSplit(
        bytes memory signatures,
        uint256 pos
    ) public pure returns (uint8 v, bytes32 r, bytes32 s) {
        /* solhint-disable no-inline-assembly */
        /// @solidity memory-safe-assembly
        assembly {
            let signaturePos := mul(0x41, pos)
            r := mload(add(signatures, add(signaturePos, 0x20)))
            s := mload(add(signatures, add(signaturePos, 0x40)))
            v := byte(0, mload(add(signatures, add(signaturePos, 0x60))))
        }
        /* solhint-enable no-inline-assembly */
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

    function _updateOwners(
        address[] memory owners,
        uint256 threshold
    ) internal {
        if (owners.length == 0) revert EmptyOwners(msg.sender);
        if (threshold > owners.length) revert InvalidThreshold(msg.sender);
        address currentOwner = SENTINEL_OWNERS;
        for (uint256 i = 0; i < owners.length; i++) {
            // Owner address cannot be null.
            address owner = owners[i];
            if (
                owner == address(0) ||
                owner == SENTINEL_OWNERS ||
                owner == address(this) ||
                currentOwner == owner
            ) {
                revert InvalidOwnersList(msg.sender);
            }
            // No duplicate owners allowed.
            if (_owners[msg.sender][owner] != address(0)) {
                revert DuplicateOwner(msg.sender);
            }
            // No smart contract owners.
            if (_isSmartContract(owner)) {
                revert NotEOA(msg.sender, owner);
            }
            _owners[msg.sender][currentOwner] = owner;
            currentOwner = owner;
        }
        _owners[msg.sender][currentOwner] = SENTINEL_OWNERS;
        _thresholds[msg.sender] = threshold;
    }
}
