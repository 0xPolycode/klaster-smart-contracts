// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {BaseAuthorizationModule} from "../../../biconomy/contracts/smart-account/modules/BaseAuthorizationModule.sol";
import "@account-abstraction/contracts/interfaces/UserOperation.sol";
import "@account-abstraction/contracts/core/Helpers.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../../libraries/util/BytesLib.sol";
import "../../libraries/klaster/KlasterDecoder.sol";
import "../../libraries/util/MessageHashUtils.sol";
import "../../interfaces/IERC20Permit.sol";

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
contract KlasterEcdsaModuleEoaSupport is BaseAuthorizationModule {
    using ECDSA for bytes32;
    using UserOperationLib for UserOperation;
    using BytesLib for bytes;
    using KlasterDecoder for bytes;
    using KlasterDecoder for uint256;

    string public constant NAME = "Klaster ECDSA Module (EOA Support)";
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
        virtual
        returns (uint256)
    {
        (bytes memory sigBytes,) = abi.decode(userOp.signature, (bytes, address));
        
        KlasterDecoder.UserOpSignature memory klasterSig = sigBytes.decodeSignature();

        // bytes32 signedDataHash;
        // bytes32 itxHash;
        // bytes32[] memory proof;
        // uint48 lowerBoundTimestamp;
        // uint48 upperBoundTimestamp;
        // bytes memory userEcdsaSignature;

        if (klasterSig.signatureType == KlasterDecoder.UserOpSignatureType.OFF_CHAIN) {
            return _validateOffChainUserOp(userOp, klasterSig.signature);
        }
        else if (klasterSig.signatureType == KlasterDecoder.UserOpSignatureType.ON_CHAIN) {
            return _validateOnChainUserOp(userOp, klasterSig.signature);
        }
        else if (klasterSig.signatureType == KlasterDecoder.UserOpSignatureType.ERC20_PERMIT) {
            return _validateErc20PermitUserOp(userOp, klasterSig.signature);
        }
        else { revert("KlasterEcdsaModuleEoaSupport:: invalid userOp sig type"); }

        // bytes32 calculatedUserOpHash = getUserOpHash(userOp, lowerBoundTimestamp, upperBoundTimestamp);
        // if (!_validateUserOpHash(calculatedUserOpHash, itxHash, proof)) {
        //     return SIG_VALIDATION_FAILED;
        // }

        // if (!_verifySignature(signedDataHash, userEcdsaSignature, userOp.sender)) {
        //     return SIG_VALIDATION_FAILED;
        // }

        // return _packValidationData(false, upperBoundTimestamp, lowerBoundTimestamp);
    }

    function _validateOffChainUserOp(UserOperation calldata userOp, bytes memory signature) public view returns (uint256) {
        bytes32 signedDataHash;
        bytes32 itxHash;
        bytes32[] memory proof;
        uint48 lowerBoundTimestamp;
        uint48 upperBoundTimestamp;
        bytes memory userEcdsaSignature;
        (
            itxHash,
            proof,
            lowerBoundTimestamp,
            upperBoundTimestamp,
            userEcdsaSignature
        ) = abi.decode(signature, (bytes32, bytes32[], uint48, uint48, bytes));
        signedDataHash = itxHash;
        bytes32 calculatedUserOpHash = getUserOpHash(userOp, lowerBoundTimestamp, upperBoundTimestamp);
        if (!_validateUserOpHash(calculatedUserOpHash, itxHash, proof)) {
            return SIG_VALIDATION_FAILED;
        }

        if (!_verifySignature(signedDataHash, userEcdsaSignature, userOp.sender)) {
            return SIG_VALIDATION_FAILED;
        }
        return _packValidationData(false, upperBoundTimestamp, lowerBoundTimestamp);
    }

    function _validateOnChainUserOp(UserOperation calldata userOp, bytes memory signature) public view returns (uint256) {
        bytes32 signedDataHash;
        bytes32 itxHash;
        bytes32[] memory proof;
        uint48 lowerBoundTimestamp;
        uint48 upperBoundTimestamp;
        bytes memory userEcdsaSignature;

        KlasterDecoder.TxData memory txData = signature.decodeTx();
        itxHash = txData.itxHash;
        proof = txData.proof;
        lowerBoundTimestamp = txData.lowerBoundTimestamp;
        upperBoundTimestamp = txData.upperBoundTimestamp;
        userEcdsaSignature = abi.encodePacked(txData.r, txData.s, txData.v);
        signedDataHash = txData.utxHash;

        bytes32 calculatedUserOpHash = getUserOpHash(userOp, lowerBoundTimestamp, upperBoundTimestamp);
        if (!_validateUserOpHash(calculatedUserOpHash, itxHash, proof)) {
            return SIG_VALIDATION_FAILED;
        }

        if (!_verifySignature(signedDataHash, userEcdsaSignature, userOp.sender)) {
            return SIG_VALIDATION_FAILED;
        }
        return _packValidationData(false, upperBoundTimestamp, lowerBoundTimestamp);
    }
    
    function _validateErc20PermitUserOp(UserOperation calldata userOp, bytes memory signature) public returns (uint256) {
        address owner = _smartAccountOwners[userOp.sender];
        DecodedErc20PermitSig memory decodedSig = abi.decode(signature, (DecodedErc20PermitSig));
        uint8 vAdjusted = decodedSig.v._adjustV();
        uint256 deadline = uint256(decodedSig.itxHash);

        bytes32 calculatedUserOpHash = getUserOpHash(userOp, decodedSig.lowerBoundTimestamp, decodedSig.upperBoundTimestamp);
        if (!_validateUserOpHash(calculatedUserOpHash, decodedSig.itxHash, decodedSig.proof)) {
            return SIG_VALIDATION_FAILED;
        }

        bytes32 structHash = keccak256(
            abi.encode(
                decodedSig.token.PERMIT_TYPEHASH(),
                owner,
                userOp.sender,
                decodedSig.amount,
                decodedSig.nonce,
                deadline
            )
        );
        bytes32 signedDataHash = _hashTypedDataV4(structHash, decodedSig.token.DOMAIN_SEPARATOR());
        if (!_verifySignature(signedDataHash, abi.encodePacked(decodedSig.r, decodedSig.s, vAdjusted), userOp.sender)) {
            return SIG_VALIDATION_FAILED;
        }
        
        if (decodedSig.isPermitTx) {
            decodedSig.token.permit(
                owner,
                userOp.sender,
                decodedSig.amount,
                deadline,
                vAdjusted,
                decodedSig.r,
                decodedSig.s
            );
        }
        return _packValidationData(false, decodedSig.upperBoundTimestamp, decodedSig.lowerBoundTimestamp);
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

    function _hashTypedDataV4(bytes32 structHash, bytes32 domainSeparator) internal view virtual returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
    }

   struct DecodedErc20PermitSig {
        IERC20Permit token;
        uint256 amount;
        uint256 chainId;
        uint256 nonce;
        bool isPermitTx;
        bytes32 itxHash;
        bytes32[] proof;
        uint48 lowerBoundTimestamp;
        uint48 upperBoundTimestamp;
        uint256 v;
        bytes32 r;
        bytes32 s;
   }
}
