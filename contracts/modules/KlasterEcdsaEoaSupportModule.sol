// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.17;

import "../dependencies/RLPReader.sol";
import "../dependencies/RLPEncode.sol";

contract KlasterEcdsaEoaSupportModule {

    struct ExtractedTxData {
        uint8 v;
        bytes32 r;
        bytes32 s;
        bytes32 itxHash;
        bytes32[] proof;
        uint256 txDataLen;
        uint256 proofLen;
    }

    using RLPReader for RLPReader.RLPItem;
    using RLPReader for RLPReader.Iterator;
    using RLPReader for bytes;
    using RLPEncode for uint;

    function validateEthereumTx(bytes calldata signedTx) external view returns (address) {
        ExtractedTxData memory extractedTxData = extractDataFromTx(signedTx);
        bytes32 unsignedTxHash = calculateUnsignedTxHash(signedTx, extractedTxData.txDataLen, extractedTxData.proofLen, extractedTxData.v);
        return ecrecover(unsignedTxHash, extractedTxData.v, extractedTxData.r, extractedTxData.s);
    }

    function calculateUnsignedTxHash(bytes calldata signedTx, uint256 txDataLen, uint256 proofLen, uint8 v) public pure returns (bytes32 hash) {
        uint256 totalSignatureSize = 67;
        
        uint8 txType = uint8(bytes1(signedTx[:1]));

        bytes calldata rlpEncodedTxContentUnsigned = signedTx[
            signedTx.length - proofLen - txDataLen : 
            signedTx.length - proofLen - totalSignatureSize
        ];
        if (txType == 0x02) {
            return keccak256(abi.encodePacked(txType, prependRlpContentSize(rlpEncodedTxContentUnsigned)));    
        } else if (txType == 0x00) {
            if (v >= 37) {
                
                return keccak256(prependRlpContentSize(rlpEncodedTxContentUnsigned));
            } else {
                return keccak256(prependRlpContentSize(rlpEncodedTxContentUnsigned));
            }
        } else {
            revert("calculateUnsignedTxHash: unsupported tx type");
        }
    }

    function prependRlpContentSize(bytes calldata content) public pure returns (bytes memory) {
        bytes memory prefix = encodeLength(content.length);
        return abi.encodePacked(prefix, content);
    }

    function extractDataFromTx(bytes calldata signedTx) public view returns (ExtractedTxData memory) {

        uint8 dataPos;
        uint8 vPos;
        uint8 rPos;
        uint8 sPos;
        
        if (bytes1(signedTx[:1]) == 0x00) {
            dataPos = 5;
            vPos = 6;
            rPos = 7;
            sPos = 8;
        } else if (bytes1(signedTx[:1]) == 0x02) {
            dataPos = 7;
            vPos = 9;
            rPos = 10;
            sPos = 11;
        } else { revert("extractDataFromTx: unsupported evm tx type"); }


        uint256 proofLen = uint256(uint8(bytes1(signedTx[signedTx.length - 1 :]))) * 32 + 1;
        bytes calldata rlpEncodedTx = signedTx[1: signedTx.length - proofLen];
        RLPReader.RLPItem memory parsedRlpEncodedTx = rlpEncodedTx.toRlpItem();
        RLPReader.RLPItem[] memory parsedRlpEncodedTxItems = parsedRlpEncodedTx.toList();

        return ExtractedTxData(
            uint8(parsedRlpEncodedTxItems[vPos].toUint()),
            bytes32(parsedRlpEncodedTxItems[rPos].toUint()),
            bytes32(parsedRlpEncodedTxItems[sPos].toUint()),
            this.extractItxHash(parsedRlpEncodedTxItems[dataPos].toBytes()),
            this.extractItxProof(signedTx),
            payloadLen(parsedRlpEncodedTx),
            proofLen
        );
    }

    function extractDataFrom1559Tx(bytes calldata signedTx) public view returns (uint8 v, bytes32 r, bytes32 s, bytes32 itxHash, bytes32[] memory proof, uint256 txDataLen, uint256 proofLen) {
        proofLen = uint256(uint8(bytes1(signedTx[signedTx.length - 1 :]))) * 32 + 1;
        bytes calldata rlpEncodedTx = signedTx[1: signedTx.length - proofLen];
        RLPReader.RLPItem memory parsedRlpEncodedTx = rlpEncodedTx.toRlpItem();
        RLPReader.RLPItem[] memory parsedRlpEncodedTxItems = parsedRlpEncodedTx.toList();
        itxHash = this.extractItxHash(parsedRlpEncodedTxItems[7].toBytes());
        proof = this.extractItxProof(signedTx);
        v = uint8(parsedRlpEncodedTxItems[9].toUint());
        r = bytes32(parsedRlpEncodedTxItems[10].toUint());
        s = bytes32(parsedRlpEncodedTxItems[11].toUint());
        txDataLen = payloadLen(parsedRlpEncodedTx);
    }

    function extractItxHash(bytes calldata callData) public pure returns (bytes32 iTxHash) {
        if (callData.length < 32) { revert("extractItxHash: callData length too short"); }
        iTxHash = bytes32(callData[callData.length - 32 :]);
    }

    function extractItxProof(bytes calldata signedTx) public pure returns (bytes32[] memory proof) {
        if (signedTx.length == 0) { revert ("extractItxProof: invalid signed transaction length"); }
        uint8 proofSize = uint8(bytes1(signedTx[signedTx.length - 1 : ]));
        if (signedTx.length < proofSize * 32 + 1) { revert ("extractItxProof: invalid signed transaction length"); }
        proof = new bytes32[](proofSize);
        uint256 pos = signedTx.length - 1;
        for (proofSize; proofSize > 0; proofSize--) {
            proof[proofSize - 1] = bytes32(signedTx[pos - 32 : pos]);
        }
    }

    function encodeLength(uint len) private pure returns (bytes memory) {
        uint offset = 0xc0;
        bytes memory encoded;
        if (len < 56) {
            encoded = new bytes(1);
            encoded[0] = bytes32(len + offset)[31];
        } else {
            uint lenLen;
            uint i = 1;
            while (len / i != 0) {
                lenLen++;
                i *= 256;
            }

            encoded = new bytes(lenLen + 1);
            encoded[0] = bytes32(lenLen + offset + 55)[31];
            for(i = 1; i <= lenLen; i++) {
                encoded[i] = bytes32((len / (256**(lenLen-i))) % 256)[31];
            }
        }
        return encoded;
    }
    
    
    /*
     * @param the RLP item.
     */
    function payloadLen(RLPReader.RLPItem memory item) internal pure returns (uint256) {
        (, uint256 len) = payloadLocation(item);
        return len;
    }

    /*
     * @param the RLP item.
     * @return (memPtr, len) pair: location of the item's payload in memory.
     */
    function payloadLocation(RLPReader.RLPItem memory item) internal pure returns (uint256, uint256) {
        uint256 offset = _payloadOffset(item.memPtr);
        uint256 memPtr = item.memPtr + offset;
        uint256 len = item.len - offset; // data length
        return (memPtr, len);
    }

        // @return number of bytes until the data
    function _payloadOffset(uint256 memPtr) private pure returns (uint256) {
        uint256 byte0;
        assembly {
            byte0 := byte(0, mload(memPtr))
        }

        if (byte0 < RLPReader.STRING_SHORT_START) {
            return 0;
        } else if (byte0 < RLPReader.STRING_LONG_START || (byte0 >= RLPReader.LIST_SHORT_START && byte0 < RLPReader.LIST_LONG_START)) {
            return 1;
        } else if (byte0 < RLPReader.LIST_SHORT_START) {
            // being explicit
            return byte0 - (RLPReader.STRING_LONG_START - 1) + 1;
        } else {
            return byte0 - (RLPReader.LIST_LONG_START - 1) + 1;
        }
    }




    // function toHex16 (bytes16 data) internal pure returns (bytes32 result) {
    //     result = bytes32 (data) & 0xFFFFFFFFFFFFFFFF000000000000000000000000000000000000000000000000 |
    //         (bytes32 (data) & 0x0000000000000000FFFFFFFFFFFFFFFF00000000000000000000000000000000) >> 64;
    //     result = result & 0xFFFFFFFF000000000000000000000000FFFFFFFF000000000000000000000000 |
    //         (result & 0x00000000FFFFFFFF000000000000000000000000FFFFFFFF0000000000000000) >> 32;
    //     result = result & 0xFFFF000000000000FFFF000000000000FFFF000000000000FFFF000000000000 |
    //         (result & 0x0000FFFF000000000000FFFF000000000000FFFF000000000000FFFF00000000) >> 16;
    //     result = result & 0xFF000000FF000000FF000000FF000000FF000000FF000000FF000000FF000000 |
    //         (result & 0x00FF000000FF000000FF000000FF000000FF000000FF000000FF000000FF0000) >> 8;
    //     result = (result & 0xF000F000F000F000F000F000F000F000F000F000F000F000F000F000F000F000) >> 4 |
    //         (result & 0x0F000F000F000F000F000F000F000F000F000F000F000F000F000F000F000F00) >> 8;
    //     result = bytes32 (0x3030303030303030303030303030303030303030303030303030303030303030 +
    //         uint256 (result) +
    //         (uint256 (result) + 0x0606060606060606060606060606060606060606060606060606060606060606 >> 4 &
    //         0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F) * 7);
    // }

    // function toHex (bytes32 data) public pure returns (string memory) {
    //     return string (abi.encodePacked ("0x", toHex16 (bytes16 (data)), toHex16 (bytes16 (data << 128))));
    // }


}

