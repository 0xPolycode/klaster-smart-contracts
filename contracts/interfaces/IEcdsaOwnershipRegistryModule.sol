// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface IEcdsaOwnershipRegistryModule {
    function initForSmartAccount(address eoaOwner) external returns (address);
}
