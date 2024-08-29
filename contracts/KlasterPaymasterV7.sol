// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "account-abstraction-v7/core/Helpers.sol";
import "account-abstraction-v7/core/BasePaymaster.sol";
import "account-abstraction-v7/interfaces/IEntryPoint.sol";
import "account-abstraction-v7/interfaces/IEntryPointSimulations.sol";

contract KlasterPaymasterV7 is BasePaymaster, ReentrancyGuard {
    using UserOperationLib for PackedUserOperation;

    error EmptyMessageValue();
    error InsufficientBalance();

    constructor(IEntryPoint _entryPoint) payable BasePaymaster(_entryPoint) {}

    function handleOps(PackedUserOperation[] calldata ops) public payable {
        if (msg.value == 0) {
            revert EmptyMessageValue();
        }
        entryPoint.depositTo{value: msg.value}(address(this));
        entryPoint.handleOps(ops, payable(msg.sender));
        entryPoint.withdrawTo(payable(msg.sender), entryPoint.getDepositInfo(address(this)).deposit);
    }

    function simulateHandleOp(PackedUserOperation calldata op, address target, bytes calldata callData)
        external
        payable
        returns (IEntryPointSimulations.ExecutionResult memory)
    {
        if (msg.value == 0) {
            revert EmptyMessageValue();
        }
        IEntryPointSimulations entryPointWithSimulations = IEntryPointSimulations(address(entryPoint));
        entryPointWithSimulations.depositTo{value: msg.value}(address(this));
        return entryPointWithSimulations.simulateHandleOp(op, target, callData);
    }

    function simulateValidation(PackedUserOperation calldata op)
        external
        payable
        returns (IEntryPointSimulations.ValidationResult memory)
    {
        if (msg.value == 0) {
            revert EmptyMessageValue();
        }
        IEntryPointSimulations entryPointWithSimulations = IEntryPointSimulations(address(entryPoint));
        entryPointWithSimulations.depositTo{value: msg.value}(address(this));
        return entryPointWithSimulations.simulateValidation(op);
    }

    // accept all userOps
    function _validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        internal
        virtual
        override
        returns (bytes memory context, uint256 validationData)
    {
        if (entryPoint.getDepositInfo(address(this)).deposit < maxCost) {
            revert InsufficientBalance();
        }
        (uint256 maxGasLimit, uint256 nodeOperatorPremium) =
            abi.decode(userOp.paymasterAndData[PAYMASTER_DATA_OFFSET:], (uint256, uint256));

        return (abi.encode(userOp.sender, userOp.unpackMaxFeePerGas(), maxGasLimit, nodeOperatorPremium), 0);
    }

    /**
     * Post-operation handler.
     * (verified to be called only through the entryPoint)
     * executes userOp and gives back refund to the userOp.sender if userOp.sender has overpaid for execution.
     * @dev if subclass returns a non-empty context from validatePaymasterUserOp, it must also implement this method.
     * @param mode enum with the following options:
     *      opSucceeded - user operation succeeded.
     *      opReverted  - user op reverted. still has to pay for gas.
     *      postOpReverted - user op succeeded, but caused postOp (in mode=opSucceeded) to revert.
     *                       Now this is the 2nd call, after user's op was deliberately reverted.
     * @param context - the context value returned by validatePaymasterUserOp
     * @param actualGasCost - actual gas used so far (without this postOp call).
     */
    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost, uint256 actualUserOpFeePerGas)
        internal
        virtual
        override
    {
        if (mode == PostOpMode.postOpReverted) {
            return;
        }
        (address sender, uint256 maxFeePerGas, uint256 maxGasLimit, uint256 nodeOperatorPremium) =
            abi.decode(context, (address, uint256, uint256, uint256));

        uint256 refund = calculateRefund(maxGasLimit, maxFeePerGas, actualGasCost, nodeOperatorPremium);
        if (refund > 0) {
            entryPoint.withdrawTo(payable(sender), refund);
        }
    }

    function calculateRefund(
        uint256 maxGasLimit,
        uint256 maxFeePerGas,
        uint256 actualGasCost,
        uint256 nodeOperatorPremium
    ) public pure returns (uint256 refund) {
        uint256 costWithPremium = (actualGasCost * (100 + nodeOperatorPremium)) / 100;

        uint256 maxCost = maxGasLimit * maxFeePerGas;
        if (costWithPremium < maxCost) {
            refund = maxCost - costWithPremium;
        }
    }
}
