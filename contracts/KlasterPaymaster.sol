// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@account-abstraction/contracts/core/BasePaymaster.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@account-abstraction/contracts/core/Helpers.sol";

contract KlasterPaymaster is BasePaymaster, ReentrancyGuard {

    constructor(
        IEntryPoint _entryPoint
    ) payable BasePaymaster(_entryPoint) { }

    function handleOps(
        UserOperation[] calldata ops
    ) payable public {
        entryPoint.depositTo{value: msg.value}(address(this));
        entryPoint.handleOps(ops, payable(msg.sender));        
        entryPoint.withdrawTo(payable(msg.sender), entryPoint.getDepositInfo(address(this)).deposit);
    }

    function simulateHandleOp(UserOperation calldata op, address target, bytes calldata callData) external payable {
        entryPoint.depositTo{value: msg.value}(address(this));
        entryPoint.simulateHandleOp(op, target, callData);
    }

    function simulateValidation(UserOperation calldata op) external payable {
        entryPoint.depositTo{value: msg.value}(address(this));
        entryPoint.simulateValidation(op);
    }

    // accept all userOps
    function _validatePaymasterUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
    internal virtual override returns (bytes memory context, uint256 validationData) {
        (uint256 maxGasLimit, uint256 nodeOperatorPremium) = abi.decode(userOp.paymasterAndData[20:], (uint256, uint256));
        return (abi.encode(userOp.sender, userOp.maxFeePerGas, maxGasLimit, nodeOperatorPremium), 0);
    }

    /**
     * post-operation handler.
     * (verified to be called only through the entryPoint)
     * @dev if subclass returns a non-empty context from validatePaymasterUserOp, it must also implement this method.
     * @param mode enum with the following options:
     *      opSucceeded - user operation succeeded.
     *      opReverted  - user op reverted. still has to pay for gas.
     *      postOpReverted - user op succeeded, but caused postOp (in mode=opSucceeded) to revert.
     *                       Now this is the 2nd call, after user's op was deliberately reverted.
     * @param context - the context value returned by validatePaymasterUserOp
     * @param actualGasCost - actual gas used so far (without this postOp call).
     */
    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) internal virtual override {
        (
            address sender,
            uint256 maxFeePerGas,
            uint256 maxGasLimit,
            uint256 nodeOperatorPremium
        ) = abi.decode(context, (address, uint256, uint256, uint256));

        uint256 costWithPremium = actualGasCost * (100 + nodeOperatorPremium) / 100;
        uint256 maxCost = maxGasLimit * maxFeePerGas;
        uint256 totalUserCost = min(costWithPremium, maxCost);
        
        if (totalUserCost < maxCost) {
            entryPoint.withdrawTo(
                payable(sender),
                maxCost - totalUserCost
            );
        }
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}
