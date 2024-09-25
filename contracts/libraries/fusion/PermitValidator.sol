// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../../interfaces/IERC20Permit.sol";
import "../../libraries/util/MessageHashUtils.sol";

library PermitValidator {

    uint8 constant EIP_155_MIN_V_VALUE = 37;

    using ECDSA for bytes32;

    struct DecodedErc20PermitSig {
        IERC20Permit token;
        uint256 amount;
        uint256 chainId;
        uint256 nonce;
        bool isPermitTx;
        bytes32 appendedHash;
        uint256 v;
        bytes32 r;
        bytes32 s;
   }

    /**
     * This function parses the given userOpSignature into a DecodedErc20PermitSig data structure.
     * 
     * Once parsed, the function will check for two conditions:
     *      1. is the expected hash found in the signed Permit message's deadline field?
     *      2. is the recovered message signer equal to the expected signer?
     * 
     * If both conditions are met - outside contract can be sure that the expected signer has indeed
     * approved the given hash by signing a given Permit message.
     * 
     * NOTES: This function will revert if either of following is met:
     *    1. the userOpSignature couldn't be abi.decoded into a valid DecodedErc20PermitSig struct as defined in this contract
     *    2. extracted hash wasn't equal to the provided expected hash
     *    3. recovered Permit message signer wasn't equal to the expected signer
     * 
     * Returns true if the expected signer did indeed approve the given expectedHash by signing an on-chain transaction.
     * In that case, the function will also perform the Permit approval on the given token in case the 
     * isPermitTx flag was set to true in the decoded signature struct.
     * 
     * @param userOpSignature Signature provided as the userOp.signature parameter. Expecting to receive
     *                        fully signed serialized EVM transcaction here of type 0x00 (LEGACY) or 0x02 (EIP1556).
     *                        For LEGACY tx type the "0x00" prefix has to be added manually while the EIP1559 tx type
     *                        already contains 0x02 prefix.
     * @param userOpSender UserOp sender
     * @param expectedHash Hash expected to be found as the last 32 bytes appended to the tx data parameter.
     *                     If no hash found exception is thrown.
     * @param expectedSigner Signer expected to be recovered when decoding the signed transaction and recovering the signer.
     */
    function validate(bytes memory userOpSignature, address userOpSender, bytes32 expectedHash, address expectedSigner) external returns (bool) {
        DecodedErc20PermitSig memory decodedSig = abi.decode(userOpSignature, (DecodedErc20PermitSig));
        
        if (decodedSig.appendedHash != expectedHash) {
            revert("PermitValidator:: Extracted data hash not equal to the expected data hash.");
        }
        
        uint8 vAdjusted = _adjustV(decodedSig.v);
        uint256 deadline = uint256(decodedSig.appendedHash);
        
        bytes32 structHash = keccak256(
            abi.encode(
                decodedSig.token.PERMIT_TYPEHASH(),
                expectedSigner,
                userOpSender,
                decodedSig.amount,
                decodedSig.nonce,
                deadline
            )
        );

        bytes32 signedDataHash = _hashTypedDataV4(structHash, decodedSig.token.DOMAIN_SEPARATOR());
        bytes memory signature = abi.encodePacked(decodedSig.r, decodedSig.s, decodedSig.v);
        
        address recovered = (signedDataHash.toEthSignedMessageHash()).recover(signature);
        if (expectedSigner != recovered) {
            recovered = signedDataHash.recover(signature);
            if (expectedSigner != recovered) {
                revert("PermitValidator:: recovered signer not equal to the expected signer");
            }    
        }

        if (decodedSig.isPermitTx) {
            decodedSig.token.permit(
                expectedSigner,
                userOpSender,
                decodedSig.amount,
                deadline,
                vAdjusted,
                decodedSig.r,
                decodedSig.s
            );
        }
        
        return true;
    }

    function _hashTypedDataV4(bytes32 structHash, bytes32 domainSeparator) private pure returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
    }

    function _adjustV(uint256 v) private pure returns (uint8) {
        if (v >= EIP_155_MIN_V_VALUE) {
            return uint8((v - 2 * _extractChainIdFromV(v) - 35) + 27);
        } else if (v <= 1) {
            return uint8(v + 27);
        } else {
            return uint8(v);
        }
    }

    function _extractChainIdFromV(uint256 v) private pure returns (uint256 chainId) {
        chainId = (v - 35) / 2;
    }

}
