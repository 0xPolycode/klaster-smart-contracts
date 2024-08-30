// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.17;

import "./RLPDecoder.sol";
import "./RLPEncoder.sol";
import "./BytesLib.sol";

library KlasterDecoder {

    enum UserOpSignatureType {
        OFF_CHAIN,
        ON_CHAIN
    }

    uint8 constant SIG_TYPE_OFF_CHAIN = 0x00;
    uint8 constant SIG_TYPE_ON_CHAIN = 0x01;

    uint8 constant LEGACY_TX_TYPE = 0x00;
    uint8 constant EIP1559_TX_TYPE = 0x02;

    uint8 constant TIMESTAMP_BYTE_SIZE = 6;
    uint8 constant PROOF_ITEM_BYTE_SIZE = 32;
    uint8 constant ITX_HASH_BYTE_SIZE = 32;

    uint8 constant RLP_ENCODED_R_S_BYTE_SIZE = 66; // 2 * 33bytes (for r, s components)

    uint8 constant EIP_155_MIN_V_VALUE = 37;

    using RLPDecoder for RLPDecoder.RLPItem;
    using RLPDecoder for bytes;
    using RLPEncoder for uint;
    using BytesLib for bytes;

    struct UserOpSignature {
        UserOpSignatureType signatureType;
        bytes signature;
    }
    
    struct TxData {
        uint8 txType;
        uint8 v;
        bytes32 r;
        bytes32 s;
        bytes32 utxHash;
        bytes32 itxHash;
        bytes32[] proof;
        uint48 lowerBoundTimestamp;
        uint48 upperBoundTimestamp;
    }

    struct TxParams {
        uint256 v;
        bytes32 r;
        bytes32 s;
        bytes callData;
    }

    function decodeSignature(bytes memory self) internal pure returns (UserOpSignature memory) {
        bytes memory sig = self.slice(1, self.length - 1);
        if (uint8(self[0]) == SIG_TYPE_OFF_CHAIN) {
            return UserOpSignature(
                UserOpSignatureType.OFF_CHAIN,
                sig
            );
        } else if (uint8(self[0]) == SIG_TYPE_ON_CHAIN) {
            return UserOpSignature(
                UserOpSignatureType.ON_CHAIN,
                sig
            );
        } else {
            revert("KlasterDecoder:: invalid userOp sig type. Expected 0x00 for off-chain or 0x01");
        }
    }

    function decodeTx(bytes memory self) internal pure returns (TxData memory) {
        uint8 txType = uint8(self[0]); //first byte is tx type
        uint48 lowerBoundTimestamp = uint48(bytes6((self.slice(self.length - 2 * TIMESTAMP_BYTE_SIZE, TIMESTAMP_BYTE_SIZE))));
        uint48 upperBoundTimestamp = uint48(bytes6(self.slice(self.length - TIMESTAMP_BYTE_SIZE, TIMESTAMP_BYTE_SIZE)));
        uint8 proofItemsCount = uint8(self[self.length - 2 * TIMESTAMP_BYTE_SIZE - 1]);
        uint256 appendedDataLen = (uint256(proofItemsCount) * PROOF_ITEM_BYTE_SIZE + 1) + 2 * TIMESTAMP_BYTE_SIZE;
        bytes memory rlpEncodedTx = self.slice(1, self.length - appendedDataLen - 1);
        RLPDecoder.RLPItem memory parsedRlpEncodedTx = rlpEncodedTx.toRlpItem();
        RLPDecoder.RLPItem[] memory parsedRlpEncodedTxItems = parsedRlpEncodedTx.toList();
        TxParams memory params = extractParams(txType, parsedRlpEncodedTxItems);        

        return TxData(
            txType,
            _adjustV(params.v),
            params.r,
            params.s,
            calculateUnsignedTxHash(txType, rlpEncodedTx, parsedRlpEncodedTx.payloadLen(), params.v),
            extractItxHash(params.callData),
            extractItxProof(self, proofItemsCount),
            lowerBoundTimestamp,
            upperBoundTimestamp
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
        } else { revert("TxDecoder:: unsupported evm tx type"); }

        return TxParams(
            items[vPos].toUint(),
            bytes32(items[rPos].toUint()),
            bytes32(items[sPos].toUint()),
            items[dataPos].toBytes()
        );
    }

    function extractItxHash(bytes memory callData) private pure returns (bytes32 iTxHash) {
        if (callData.length < ITX_HASH_BYTE_SIZE) { revert("TxDecoder:: callData length too short"); }
        iTxHash = bytes32(callData.slice(callData.length - ITX_HASH_BYTE_SIZE, ITX_HASH_BYTE_SIZE));
    }

    function extractItxProof(bytes memory signedTx, uint8 proofItemsCount) private pure returns (bytes32[] memory proof) {
        proof = new bytes32[](proofItemsCount);
        uint256 pos = signedTx.length - 2 * TIMESTAMP_BYTE_SIZE - 1;
        for (proofItemsCount; proofItemsCount > 0; proofItemsCount--) {
            proof[proofItemsCount - 1] = bytes32(signedTx.slice(pos - PROOF_ITEM_BYTE_SIZE, PROOF_ITEM_BYTE_SIZE));
        }
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
            revert("TxDecoder:: unsupported tx type");
        }
    }

    function prependRlpContentSize(bytes memory content, bytes memory extraData) public pure returns (bytes memory) {
        bytes memory combinedContent = abi.encodePacked(content, extraData);
        return abi.encodePacked(combinedContent.length.encodeLength(RLPDecoder.LIST_SHORT_START), combinedContent);
    }

    function _adjustV(uint256 v) internal pure returns (uint8) {
        if (v >= EIP_155_MIN_V_VALUE) {
            return uint8((v - 2 * _extractChainIdFromV(v) - 35) + 27);
        } else if (v <= 1) {
            return uint8(v + 27);
        } else {
            return uint8(v);
        }
    }

    function _extractChainIdFromV(uint256 v) internal pure returns (uint256 chainId) {
        chainId = (v - 35) / 2;
    }
}
