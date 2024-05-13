/**
 ** Account-Abstraction (EIP-4337) singleton EntryPoint implementation.
 ** Only one instance required on each chain.
 **/
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */


import "@account-abstraction/contracts/interfaces/IAccount.sol";
import "@account-abstraction/contracts/utils/Exec.sol";
import "@account-abstraction/contracts/core/SenderCreator.sol";
import "@account-abstraction/contracts/core/Helpers.sol";
import "@account-abstraction/contracts/core/NonceManager.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

import "../interfaces/IKlasterEntrypoint.sol";

contract KlasterEntryPoint is IKlasterEntryPoint, NonceManager, ReentrancyGuard {

    using UserOperationLib for UserOperation;

    SenderCreator private immutable senderCreator = new SenderCreator();

    // internal value used during simulation: need to query aggregator.
    address private constant SIMULATE_FIND_AGGREGATOR = address(1);

    // marker for inner call revert on out of gas
    bytes32 private constant INNER_OUT_OF_GAS = hex'deaddead';

    uint256 private constant REVERT_REASON_MAX_LEN = 2048;

    /**
     * for simulation purposes, validateUserOp (and validatePaymasterUserOp) must return this value
     * in case of signature failure, instead of revert.
     */
    uint256 public constant SIG_VALIDATION_FAILED = 1;

    /**
     * compensate the caller's beneficiary address with the collected fees of all UserOperations.
     * @param beneficiary the address to receive the fees
     * @param amount amount to transfer.
     */
    function _compensate(address payable beneficiary, uint256 amount) internal {
        require(beneficiary != address(0), "AA90 invalid beneficiary");
        (bool success,) = beneficiary.call{value : amount}("");
        require(success, "AA91 failed send to beneficiary");
    }

    /**
     * execute a user op
     * @param opIndex index into the opInfo array
     * @param userOp the userOp to execute
     * @param opInfo the opInfo filled by validatePrepayment for this userOp.
     */
    function _executeUserOp(uint256 opIndex, UserOperation calldata userOp, UserOpInfo memory opInfo) private returns (uint256 totalGasCast, uint256 innerOpGas) {
        uint256 preGas = gasleft();

        try this.innerHandleOp(userOp.callData, opInfo) returns (uint256 _totalGasCost, uint256 _innerOpGas) {
            innerOpGas = _innerOpGas;
            totalGasCast = _totalGasCost;
        } catch {
            bytes32 innerRevertCode;
            assembly {
                returndatacopy(0, 0, 32)
                innerRevertCode := mload(0)
            }
            // handleOps was called with gas limit too low. abort entire bundle.
            if (innerRevertCode == INNER_OUT_OF_GAS) {
                //report paymaster, since if it is not deliberately caused by the bundler,
                // it must be a revert caused by paymaster.
                revert FailedOp(opIndex, "AA95 out of gas");
            }

            innerOpGas = preGas - gasleft();
            totalGasCast = _handlePostOp(opInfo, innerOpGas + opInfo.preOpGas);
        }
    }

    /**
     * Execute a batch of UserOperations.
     * no signature aggregator is used.
     * if any account requires an aggregator (that is, it returned an aggregator when
     * performing simulateValidation), then handleAggregatedOps() must be used instead.
     * @param ops the operations to execute
     * @param chains the chains
     */
    function handleOps(UserOperation[][] calldata ops, uint256[][] calldata chains) public nonReentrant {

        uint256 opslen = ops.length;
        UserOpInfo[] memory opInfos = new UserOpInfo[](opslen);

    unchecked {
        for (uint256 i = 0; i < opslen; i++) {
            UserOpInfo memory opInfo = opInfos[i];
            uint256 validationData = _validateData(i, ops[i], chains[i], opInfo);
            _validateAccountValidationData(i, validationData, address(0));
        }

        uint256 collected = 0;
        emit BeforeExecution();

        for (uint256 i = 0; i < opslen; i++) {
            (uint256 _collected, ) = _executeUserOp(i, ops[i][opInfos[i].userOpIndex], opInfos[i]);
            collected += _collected;
        }
    } //unchecked
    }

    /// @inheritdoc IKlasterEntryPoint
    function simulateHandleOp(
        UserOperation[] calldata userOps,
        uint256[] calldata chainIds,
        address target,
        bytes calldata targetCallData
    ) external override {

        UserOpInfo memory opInfo;
        uint256 validationData = _validateData(0, userOps, chainIds, opInfo);
        _simulationOnlyValidations(userOps[opInfo.userOpIndex]);
        ValidationData memory data = _parseValidationData(validationData);

        numberMarker();
        (uint256 paid, uint256 opGas) = _executeUserOp(0, userOps[opInfo.userOpIndex], opInfo); 
        numberMarker();
        bool targetSuccess;
        bytes memory targetResult;
        if (target != address(0)) {
            (targetSuccess, targetResult) = target.call(targetCallData);
        }
        revert ExecutionResult(opInfo.preOpGas, opGas, paid, data.validAfter, data.validUntil, targetSuccess, targetResult);
    }

    function simulateHandleOpNoSigCheck(
        UserOperation[] calldata userOps,
        uint256[] calldata chainIds,
        address target,
        bytes calldata targetCallData
    ) external override {

        UserOpInfo memory opInfo;
        uint256 validationData = _validateDataNoSigCheck(0, userOps, chainIds, opInfo);
        _simulationOnlyValidations(userOps[opInfo.userOpIndex]);
        ValidationData memory data = _parseValidationData(validationData);

        numberMarker();
        (uint256 paid, uint256 opGas) = _executeUserOp(0, userOps[opInfo.userOpIndex], opInfo); 
        numberMarker();
        bool targetSuccess;
        bytes memory targetResult;
        if (target != address(0)) {
            (targetSuccess, targetResult) = target.call(targetCallData);
        }
        revert ExecutionResult(opInfo.preOpGas, opGas, paid, data.validAfter, data.validUntil, targetSuccess, targetResult);
    }


    // A memory copy of UserOp static fields only.
    // Excluding: callData, initCode and signature. Replacing paymasterAndData with paymaster.
    struct MemoryUserOp {
        address sender;
        uint256 nonce;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
    }

    struct UserOpInfo {
        MemoryUserOp mUserOp;
        bytes32 userOpHash;
        uint256 preOpGas;
        uint256 userOpIndex;
    }

    /**
     * inner function to handle a UserOperation.
     * Must be declared "external" to open a call context, but it can only be called by handleOps.
     */
    function innerHandleOp(bytes memory callData, UserOpInfo memory opInfo) external returns (uint256 totalGasCost, uint256 innerOpGas) {
        uint256 preGas = gasleft();
        require(msg.sender == address(this), "AA92 internal call only");
        MemoryUserOp memory mUserOp = opInfo.mUserOp;

        uint callGasLimit = mUserOp.callGasLimit;
    unchecked {
        // handleOps was called with gas limit too low. abort entire bundle.
        if (gasleft() < callGasLimit + mUserOp.verificationGasLimit + 5000) {
            assembly {
                mstore(0, INNER_OUT_OF_GAS)
                revert(0, 32)
            }
        }
    }

        if (callData.length > 0) {
            bool success = Exec.call(mUserOp.sender, 0, callData, callGasLimit);
            if (!success) {
                bytes memory result = Exec.getReturnData(REVERT_REASON_MAX_LEN);
                if (result.length > 0) {
                    emit UserOperationRevertReason(opInfo.userOpHash, mUserOp.sender, mUserOp.nonce, result);
                }
            }
        }

        unchecked {
            innerOpGas = preGas - gasleft();
            totalGasCost = _handlePostOp(opInfo, innerOpGas + opInfo.preOpGas);
            //note: opIndex is ignored (relevant only if mode==postOpReverted, which is only possible outside of innerHandleOp)
        }
    }

    /**
     * generate a request Id - unique identifier for this request.
     * the request ID is a hash over the content of the userOp (except the signature), the entrypoint and the chainid.
     */
    function getUserOpHash(
        UserOperation[] calldata userOps, uint256[] calldata chainIds
    ) public view override returns (bytes32 userOpHash) {
        for (uint256 i = 0; i < userOps.length; i++) {
            userOpHash = keccak256(abi.encode(userOpHash, userOps[i].hash(), address(this), chainIds[i]));
        }
    }

    /**
     * copy general fields from userOp into the memory opInfo structure.
     */
    function _copyUserOpToMemory(UserOperation calldata userOp, MemoryUserOp memory mUserOp) internal pure {
        mUserOp.sender = userOp.sender;
        mUserOp.nonce = userOp.nonce;
        mUserOp.callGasLimit = userOp.callGasLimit;
        mUserOp.verificationGasLimit = userOp.verificationGasLimit;
        mUserOp.preVerificationGas = userOp.preVerificationGas;
        mUserOp.maxFeePerGas = userOp.maxFeePerGas;
        mUserOp.maxPriorityFeePerGas = userOp.maxPriorityFeePerGas;
    }

    /// @inheritdoc IKlasterEntryPoint
    function simulateValidation(UserOperation[] calldata userOps, uint256[] calldata chainIds) external {
        UserOpInfo memory outOpInfo;

        uint256 validationData = _validateData(0, userOps, chainIds, outOpInfo);
        _simulationOnlyValidations(userOps[outOpInfo.userOpIndex]);

        ValidationData memory data = _parseValidationData(validationData);
        address aggregator = data.aggregator;
        bool sigFailed = aggregator == address(1);
        ReturnInfo memory returnInfo = ReturnInfo(
            outOpInfo.preOpGas,
            sigFailed,
            data.validAfter,
            data.validUntil
        );

        revert ValidationResult(returnInfo);
    }

    // create the sender's contract if needed.
    function _createSenderIfNeeded(uint256 opIndex, UserOpInfo memory opInfo, bytes calldata initCode) internal {
        if (initCode.length != 0) {
            address sender = opInfo.mUserOp.sender;
            if (sender.code.length != 0) revert FailedOp(opIndex, "AA10 sender already constructed");
            address sender1 = senderCreator.createSender{gas : opInfo.mUserOp.verificationGasLimit}(initCode);
            if (sender1 == address(0)) revert FailedOp(opIndex, "AA13 initCode failed or OOG");
            if (sender1 != sender) revert FailedOp(opIndex, "AA14 initCode must return sender");
            if (sender1.code.length == 0) revert FailedOp(opIndex, "AA15 initCode must create sender");
            address factory = address(bytes20(initCode[0 : 20]));
            emit AccountDeployed(opInfo.userOpHash, sender, factory, address(0));
        }
    }

    /**
     * Get counterfactual sender address.
     *  Calculate the sender contract address that will be generated by the initCode and salt in the UserOperation.
     * this method always revert, and returns the address in SenderAddressResult error
     * @param initCode the constructor code to be passed into the UserOperation.
     */
    function getSenderAddress(bytes calldata initCode) public {
        address sender = senderCreator.createSender(initCode);
        revert SenderAddressResult(sender);
    }

    function _simulationOnlyValidations(UserOperation calldata userOp) internal view {
        // solhint-disable-next-line no-empty-blocks
        try this._validateSender(userOp.initCode, userOp.sender) {}
        catch Error(string memory revertReason) {
            if (bytes(revertReason).length != 0) {
                revert FailedOp(0, revertReason);
            }
        }
    }

    /**
    * Called only during simulation.
    * This function always reverts to prevent warm/cold storage differentiation in simulation vs execution.
    */
    function _validateSender(bytes calldata initCode, address sender) external view {
        if (initCode.length == 0 && sender.code.length == 0) {
            // it would revert anyway. but give a meaningful message
            revert("AA20 account not deployed");
        }
        // always revert
        revert("");
    }

    /**
     * call account.validateUserOp.
     * no sig check. used only in simulations.
     * revert (with FailedOp) in case validateUserOp reverts, or account didn't send required prefund.
     * decrement account's deposit if needed
     */
    function _validateAccountDataNoSigCheck(uint256 opIndex, UserOperation calldata op, UserOpInfo memory opInfo)
    internal returns (uint256 gasUsedByValidateAccountPrepayment, uint256 validationData) {
    unchecked {
        uint256 preGas = gasleft();
        _createSenderIfNeeded(opIndex, opInfo, op.initCode);
        validationData = 0;
        gasUsedByValidateAccountPrepayment = preGas - gasleft();
    }
    }

    /**
     * call account.validateUserOp.
     * revert (with FailedOp) in case validateUserOp reverts, or account didn't send required prefund.
     * decrement account's deposit if needed
     */
    function _validateAccountData(uint256 opIndex, UserOperation calldata op, UserOpInfo memory opInfo)
    internal returns (uint256 gasUsedByValidateAccountPrepayment, uint256 validationData) {
    unchecked {
        uint256 preGas = gasleft();
        MemoryUserOp memory mUserOp = opInfo.mUserOp;
        address sender = mUserOp.sender;
        _createSenderIfNeeded(opIndex, opInfo, op.initCode);
        numberMarker();
        try IAccount(sender).validateUserOp{gas : mUserOp.verificationGasLimit}(op, opInfo.userOpHash, 0)
        returns (uint256 _validationData) {
            validationData = _validationData;
        } catch Error(string memory revertReason) {
            revert FailedOp(opIndex, string.concat("AA23 reverted: ", revertReason));
        } catch {
            revert FailedOp(opIndex, "AA23 reverted (or OOG)");
        }
        gasUsedByValidateAccountPrepayment = preGas - gasleft();
    }
    }

    /**
     * revert if either account validationData or paymaster validationData is expired
     */
    function _validateAccountValidationData(uint256 opIndex, uint256 validationData, address expectedAggregator) internal view {
        (address aggregator, bool outOfTimeRange) = _getValidationData(validationData);
        if (expectedAggregator != aggregator) {
            revert FailedOp(opIndex, "AA24 signature error");
        }
        if (outOfTimeRange) {
            revert FailedOp(opIndex, "AA22 expired or not due");
        }
    }

    function _getValidationData(uint256 validationData) internal view returns (address aggregator, bool outOfTimeRange) {
        if (validationData == 0) {
            return (address(0), false);
        }
        ValidationData memory data = _parseValidationData(validationData);
        // solhint-disable-next-line not-rely-on-time
        outOfTimeRange = block.timestamp > data.validUntil || block.timestamp < data.validAfter;
        aggregator = data.aggregator;
    }

    /**
     * validate account and paymaster (if defined).
     * skip sig check. used only in simulation.
     * also make sure total validation doesn't exceed verificationGasLimit
     * this method is called off-chain (simulateValidation()) and on-chain (from handleOps)
     * @param opIndex the index of this userOp into the "opInfos" array
     * @param userOps the userOp to validate
     */
    function _validateDataNoSigCheck(uint256 opIndex, UserOperation[] calldata userOps, uint256[] calldata chainIds, UserOpInfo memory outOpInfo)
    private returns (uint256 validationData) {

        uint256 preGas = gasleft();
        (
            UserOperation calldata userOp,
            uint256 userOpIndex
        ) = _extractForThisChain(userOps, chainIds);
        MemoryUserOp memory mUserOp = outOpInfo.mUserOp;
        _copyUserOpToMemory(userOp, mUserOp);
        outOpInfo.userOpHash = getUserOpHash(userOps, chainIds);
        outOpInfo.userOpIndex = userOpIndex;

        // validate all numeric values in userOp are well below 128 bit, so they can safely be added
        // and multiplied without causing overflow
        uint256 maxGasValues = mUserOp.preVerificationGas | mUserOp.verificationGasLimit | mUserOp.callGasLimit |
        userOp.maxFeePerGas | userOp.maxPriorityFeePerGas;
        require(maxGasValues <= type(uint120).max, "AA94 gas values overflow");

        uint256 gasUsedByValidateAccountPrepayment;
        (gasUsedByValidateAccountPrepayment, validationData) = _validateAccountDataNoSigCheck(opIndex, userOp, outOpInfo);

        if (!_validateAndUpdateNonce(mUserOp.sender, mUserOp.nonce)) {
            revert FailedOp(opIndex, "AA25 invalid account nonce");
        }
    unchecked {
        uint256 gasUsed = preGas - gasleft();

        if (userOp.verificationGasLimit < gasUsed) {
            revert FailedOp(opIndex, "AA40 over verificationGasLimit");
        }
        outOpInfo.preOpGas = preGas - gasleft() + userOp.preVerificationGas;
    }
    }

    /**
     * validate account and paymaster (if defined).
     * also make sure total validation doesn't exceed verificationGasLimit
     * this method is called off-chain (simulateValidation()) and on-chain (from handleOps)
     * @param opIndex the index of this userOp into the "opInfos" array
     * @param userOps the userOp to validate
     */
    function _validateData(uint256 opIndex, UserOperation[] calldata userOps, uint256[] calldata chainIds, UserOpInfo memory outOpInfo)
    private returns (uint256 validationData) {

        uint256 preGas = gasleft();
        (
            UserOperation calldata userOp,
            uint256 userOpIndex
        ) = _extractForThisChain(userOps, chainIds);
        MemoryUserOp memory mUserOp = outOpInfo.mUserOp;
        _copyUserOpToMemory(userOp, mUserOp);
        outOpInfo.userOpHash = getUserOpHash(userOps, chainIds);
        outOpInfo.userOpIndex = userOpIndex;

        // validate all numeric values in userOp are well below 128 bit, so they can safely be added
        // and multiplied without causing overflow
        uint256 maxGasValues = mUserOp.preVerificationGas | mUserOp.verificationGasLimit | mUserOp.callGasLimit |
        userOp.maxFeePerGas | userOp.maxPriorityFeePerGas;
        require(maxGasValues <= type(uint120).max, "AA94 gas values overflow");

        uint256 gasUsedByValidateAccountPrepayment;
        (gasUsedByValidateAccountPrepayment, validationData) = _validateAccountData(opIndex, userOp, outOpInfo);

        if (!_validateAndUpdateNonce(mUserOp.sender, mUserOp.nonce)) {
            revert FailedOp(opIndex, "AA25 invalid account nonce");
        }
    unchecked {
        uint256 gasUsed = preGas - gasleft();

        if (userOp.verificationGasLimit < gasUsed) {
            revert FailedOp(opIndex, "AA40 over verificationGasLimit");
        }
        outOpInfo.preOpGas = preGas - gasleft() + userOp.preVerificationGas;
    }
    }

    /**
     * process post-operation.
     * called just after the callData is executed.
     * if a paymaster is defined and its validation returned a non-empty context, its postOp is called.
     * the excess amount is refunded to the account (or paymaster - if it was used in the request)
     * @param opInfo userOp fields and info collected during validation
     * @param actualGas the gas used so far by this user operation
     */
    function _handlePostOp(
        UserOpInfo memory opInfo,
        uint256 actualGas
    ) private returns (uint256 actualGasCost) {
        uint256 preGas = gasleft();
        unchecked {
            MemoryUserOp memory mUserOp = opInfo.mUserOp;
            uint256 gasPrice = getUserOpGasPrice(mUserOp);
            actualGas += preGas - gasleft();
            actualGasCost = actualGas * gasPrice;
            emit UserOperationEvent(
                opInfo.userOpHash,
                mUserOp.sender,
                address(0),
                mUserOp.nonce,
                true,
                actualGasCost,
                actualGas
            );
        } // unchecked
    }

    function _extractForThisChain(
        UserOperation[] calldata userOps,
        uint256[] calldata chainIds
    ) internal view returns (UserOperation calldata userOp, uint256 index) {
        for (uint256 i = 0; i < userOps.length; i++) {
            if (chainIds[i] == block.chainid) { return (userOps[i], i); }
        }

        revert("User's multichain intent doesn't target this blockchain network.");
    }

    /**
     * the gas price this UserOp agrees to pay.
     * relayer/block builder might submit the TX with higher priorityFee, but the user should not
     */
    function getUserOpGasPrice(MemoryUserOp memory mUserOp) internal view returns (uint256) {
    unchecked {
        uint256 maxFeePerGas = mUserOp.maxFeePerGas;
        uint256 maxPriorityFeePerGas = mUserOp.maxPriorityFeePerGas;
        if (maxFeePerGas == maxPriorityFeePerGas) {
            //legacy mode (for networks that don't support basefee opcode)
            return maxFeePerGas;
        }
        return min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
    }
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function getOffsetOfMemoryBytes(bytes memory data) internal pure returns (uint256 offset) {
        assembly {offset := data}
    }

    function getMemoryBytesFromOffset(uint256 offset) internal pure returns (bytes memory data) {
        assembly {data := offset}
    }

    //place the NUMBER opcode in the code.
    // this is used as a marker during simulation, as this OP is completely banned from the simulated code of the
    // account and paymaster.
    function numberMarker() internal view {
        assembly {mstore(0, number())}
    }
}
