// SPDX-License-Identifier: MIT
// Source file: https://github.com/bcnmy/scw-contracts/blob/main/contracts/smart-account/interfaces/IAuthorizationModule.sol
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/UserOperation.sol";

// interface for modules to verify singatures signed over userOpHash
interface IAuthorizationModule {
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256 validationData);
}
