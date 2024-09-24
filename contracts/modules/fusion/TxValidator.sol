// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "../../libraries/RLPDecoder.sol";
import "../../libraries/RLPEncoder.sol";
import "../../libraries/BytesLib.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

library TxValidator {

    uint8 constant LEGACY_TX_TYPE = 0x00;
    uint8 constant EIP1559_TX_TYPE = 0x02;

    uint8 constant RLP_ENCODED_R_S_BYTE_SIZE = 66; // 2 * 33bytes (for r, s components)
    uint8 constant EIP_155_MIN_V_VALUE = 37;
    uint8 constant HASH_BYTE_SIZE = 32;

    using RLPDecoder for RLPDecoder.RLPItem;
    using RLPDecoder for bytes;
    using RLPEncoder for uint;
    using BytesLib for bytes;
    using ECDSA for bytes32;

    struct TxData {
        uint8 txType;
        uint8 v;
        bytes32 r;
        bytes32 s;
        bytes32 utxHash; // unsigned tx hash
        bytes32 appendedHash; // extracted bytes32 hash from tx.data
    }

    struct TxParams {
        uint256 v;
        bytes32 r;
        bytes32 s;
        bytes callData;
    }

    /**
     * This function parses the given userOpSignature into a valid fully signed EVM transaction.
     * Once parsed, the function will check for two conditions:
     *      1. is the expected hash found in the tx.data as the last 32bytes?
     *      2. is the recovered tx signer equal to the expected signer?
     * 
     * If both conditions are met - outside contract can be sure that the expected signer has indeed
     * approved the given hash by performing given on-chain transaction.
     * 
     * NOTES: This function will revert if either of following is met:
     *    1. the userOpSignature couldn't be parsed to a valid fully signed EVM transaction
     *    2. hash couldn't be extracted from the tx.data
     *    3. extracted hash wasn't equal to the provided expected hash
     *    4. recovered signer wasn't equal to the expected signer
     * 
     * Returns true if the expected signer did indeed approve the given expectedHash by signing an on-chain transaction.
     * 
     * @param userOpSignature Signature provided as the userOp.signature parameter. Expecting to receive
     *                        fully signed serialized EVM transcaction here of type 0x00 (LEGACY) or 0x02 (EIP1556).
     *                        For LEGACY tx type the "0x00" prefix has to be added manually while the EIP1559 tx type
     *                        already contains 0x02 prefix.
     * @param expectedHash Hash expected to be found as the last 32 bytes appended to the tx data parameter.
     *                     If no hash found exception is thrown.
     * @param expectedSigner Signer expected to be recovered when decoding the signed transaction and recovering the signer.
     */
    function validate(bytes memory userOpSignature, bytes32 expectedHash, address expectedSigner) external pure returns (bool) {
        TxData memory decodedTx = decodeTx(userOpSignature);
        
        if (decodedTx.appendedHash != expectedHash) {
            revert("TxValidator:: Extracted hash not equal to the expected appended hash");
        }

        bytes memory signature = abi.encodePacked(decodedTx.r, decodedTx.s, decodedTx.v);
        
        address recovered = (decodedTx.utxHash.toEthSignedMessageHash()).recover(signature);
        if (expectedSigner != recovered) {
            recovered = decodedTx.utxHash.recover(signature);
            if (expectedSigner != recovered) {
                revert("TxValidator:: Recovered signer not equal to the expected signer.");
            }
        }

        return true;
    }

    function decodeTx(bytes memory self) private pure returns (TxData memory) {
        uint8 txType = uint8(self[0]); //first byte is tx type
        bytes memory rlpEncodedTx = self.slice(1, self.length - 1);
        RLPDecoder.RLPItem memory parsedRlpEncodedTx = rlpEncodedTx.toRlpItem();
        RLPDecoder.RLPItem[] memory parsedRlpEncodedTxItems = parsedRlpEncodedTx.toList();
        TxParams memory params = extractParams(txType, parsedRlpEncodedTxItems);        

        return TxData(
            txType,
            _adjustV(params.v),
            params.r,
            params.s,
            calculateUnsignedTxHash(txType, rlpEncodedTx, parsedRlpEncodedTx.payloadLen(), params.v),
            extractAppendedHash(params.callData)
        );
    }

    function extractParams(uint8 txType, RLPDecoder.RLPItem[] memory items) private pure returns (TxParams memory params) {
        uint8 dataPos;
        uint8 vPos;
        uint8 rPos;
        uint8 sPos;
        
        if (txType == LEGACY_TX_TYPE) {
            dataPos = 5;
            vPos = 6;
            rPos = 7;
            sPos = 8;
        } else if (txType == EIP1559_TX_TYPE) {
            dataPos = 7;
            vPos = 9;
            rPos = 10;
            sPos = 11;
        } else { revert("TxValidator:: unsupported evm tx type"); }

        return TxParams(
            items[vPos].toUint(),
            bytes32(items[rPos].toUint()),
            bytes32(items[sPos].toUint()),
            items[dataPos].toBytes()
        );
    }

    function extractAppendedHash(bytes memory callData) private pure returns (bytes32 appendedHash) {
        if (callData.length < HASH_BYTE_SIZE) { revert("TxValidator:: callData length too short"); }
        appendedHash = bytes32(callData.slice(callData.length - HASH_BYTE_SIZE, HASH_BYTE_SIZE));
    }

    function calculateUnsignedTxHash(uint8 txType, bytes memory rlpEncodedTx, uint256 rlpEncodedTxPayloadLen, uint256 v) private pure returns (bytes32 hash) {
        uint256 totalSignatureSize = RLP_ENCODED_R_S_BYTE_SIZE + v.encodeUint().length;
        uint256 totalPrefixSize = rlpEncodedTx.length - rlpEncodedTxPayloadLen;
        bytes memory rlpEncodedTxNoSigAndPrefix = rlpEncodedTx.slice(totalPrefixSize, rlpEncodedTx.length - totalSignatureSize - totalPrefixSize);
        if (txType == EIP1559_TX_TYPE) {
            return keccak256(abi.encodePacked(txType, prependRlpContentSize(rlpEncodedTxNoSigAndPrefix, "")));    
        } else if (txType == LEGACY_TX_TYPE) {
            if (v >= EIP_155_MIN_V_VALUE) {
                return keccak256(
                    prependRlpContentSize(
                        rlpEncodedTxNoSigAndPrefix,
                        abi.encodePacked(
                            uint256(_extractChainIdFromV(v)).encodeUint(),
                            uint256(0).encodeUint(),
                            uint256(0).encodeUint()
                        )    
                    ));
            } else {
                return keccak256(prependRlpContentSize(rlpEncodedTxNoSigAndPrefix, ""));
            }
        } else {
            revert("TxValidator:: unsupported tx type");
        }
    }

    function prependRlpContentSize(bytes memory content, bytes memory extraData) private pure returns (bytes memory) {
        bytes memory combinedContent = abi.encodePacked(content, extraData);
        return abi.encodePacked(combinedContent.length.encodeLength(RLPDecoder.LIST_SHORT_START), combinedContent);
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
