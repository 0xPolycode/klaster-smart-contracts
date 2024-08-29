// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface ISafe {
    function checkSignatures(
        bytes32 dataHash,
        bytes memory data,
        bytes memory signatures
    ) external view;
}
