// /**
//  ** Account-Abstraction (EIP-4337) singleton EntryPoint implementation.
//  ** Only one instance required on each chain.
//  **/
// // SPDX-License-Identifier: GPL-3.0
// pragma solidity ^0.8.12;

// /* solhint-disable avoid-low-level-calls */
// /* solhint-disable no-inline-assembly */

// import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
// import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
// // import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
// import "@account-abstraction/contracts/core/NonceManager.sol";
// import "@account-abstraction/contracts/utils/Exec.sol";
// import "@account-abstraction/contracts/interfaces/IAccount.sol";
// import "@account-abstraction/contracts/core/SenderCreator.sol";
// // import "@account-abstraction/contracts/core/Helpers.sol";
// import "./Helpers.sol";
// // import "@account-abstraction/contracts/core/UserOperationLib.sol";
// import "../interfaces/IKlasterEntrypoint.sol";
// // import "../interfaces/UserOperation.sol";

// /*
//  * Account-Abstraction (EIP-4337) singleton EntryPoint implementation.
//  * Only one instance required on each chain.
//  */

// /// @custom:security-contact https://bounty.ethereum.org
// contract KlasterEntryPointV2 is IKlasterEntryPoint, NonceManager, ReentrancyGuard, ERC165 {

//     // using UserOperationLib for PackedUserOperation;

//     SenderCreator private immutable _senderCreator = new SenderCreator();

//     function senderCreator() internal view virtual returns (SenderCreator) {
//         return _senderCreator;
//     }

//     //compensate for innerHandleOps' emit message and deposit refund.
//     // allow some slack for future gas price changes.
//     uint256 private constant INNER_GAS_OVERHEAD = 10000;

//     // Marker for inner call revert on out of gas
//     bytes32 private constant INNER_OUT_OF_GAS = hex"deaddead";
//     bytes32 private constant INNER_REVERT_LOW_PREFUND = hex"deadaa51";

//     uint256 private constant REVERT_REASON_MAX_LEN = 2048;

//     /// @inheritdoc IERC165
//     function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
//         // note: solidity "type(IEntryPoint).interfaceId" is without inherited methods but we want to check everything
//         return interfaceId == (type(IKlasterEntryPoint).interfaceId ^ type(INonceManager).interfaceId) ||
//             interfaceId == type(IKlasterEntryPoint).interfaceId ||
//             interfaceId == type(INonceManager).interfaceId ||
//             super.supportsInterface(interfaceId);
//     }

//     /**
//      * Execute a user operation.
//      * @param opIndex    - Index into the opInfo array.
//      * @param userOp     - The userOp to execute.
//      * @param opInfo     - The opInfo filled by validatePrepayment for this userOp.
//      * @return collected - The total amount this userOp paid.
//      */
//     function _executeUserOp(
//         uint256 opIndex,
//         PackedUserOperation calldata userOp,
//         UserOpInfo memory opInfo
//     )
//     internal
//     returns
//     (uint256 collected) {
//         uint256 preGas = gasleft();
//         bool success;
//         {
//             uint256 saveFreePtr;
//             assembly ("memory-safe") {
//                 saveFreePtr := mload(0x40)
//             }
//             bytes calldata callData = userOp.callData;
//             bytes memory innerCall = abi.encodeCall(this.innerHandleOp, (callData, opInfo));
//             assembly ("memory-safe") {
//                 success := call(gas(), address(), 0, add(innerCall, 0x20), mload(innerCall), 0, 32)
//                 collected := mload(0)
//                 mstore(0x40, saveFreePtr)
//             }
//         }
//         if (!success) {
//             bytes32 innerRevertCode;
//             assembly ("memory-safe") {
//                 let len := returndatasize()
//                 if eq(32,len) {
//                     returndatacopy(0, 0, 32)
//                     innerRevertCode := mload(0)
//                 }
//             }
//             if (innerRevertCode == INNER_OUT_OF_GAS) {
//                 // handleOps was called with gas limit too low. abort entire bundle.
//                 //can only be caused by bundler (leaving not enough gas for inner call)
//                 revert FailedOp(opIndex, "AA95 out of gas");
//             } else {
//                 emit PostOpRevertReason(
//                     opInfo.userOpHash,
//                     opInfo.mUserOp.sender,
//                     opInfo.mUserOp.nonce,
//                     Exec.getReturnData(REVERT_REASON_MAX_LEN)
//                 );

//                 uint256 actualGas = preGas - gasleft();
//                 collected = _postExecution(opInfo, actualGas);
//             }
//         }
//     }

//     function emitUserOperationEvent(UserOpInfo memory opInfo, bool success, uint256 actualGasCost, uint256 actualGas) internal virtual {
//         emit UserOperationEvent(
//             opInfo.userOpHash,
//             opInfo.mUserOp.sender,
//             address(0),
//             opInfo.mUserOp.nonce,
//             success,
//             actualGasCost,
//             actualGas
//         );
//     }

//     /// @inheritdoc IKlasterEntryPoint
//     function handleOps(
//         PackedUserOperation[][] calldata ops,
//         uint256[][] calldata chains
//     ) public nonReentrant {
//         uint256 opslen = ops.length;
//         UserOpInfo[] memory opInfos = new UserOpInfo[](opslen);
//         unchecked {
//             for (uint256 i = 0; i < opslen; i++) {
//                 UserOpInfo memory opInfo = opInfos[i];
//                 uint256 validationData = _validateData(i, ops[i], chains[i], opInfo);
//                 _validateAccountValidationData(
//                     i,
//                     validationData,
//                     address(0)
//                 );
//             }

//             uint256 collected = 0;
//             emit BeforeExecution();

//             for (uint256 i = 0; i < opslen; i++) {
//                 collected += _executeUserOp(i, ops[i][opInfos[i].userOpIndex], opInfos[i]);
//             }
//         }
//     }

//     /// @inheritdoc IKlasterEntryPoint
//     function simulateHandleOp(
//         PackedUserOperation[] calldata userOps,
//         uint256[] calldata chainIds,
//         address target,
//         bytes calldata targetCallData
//     ) external override {
//         UserOpInfo memory opInfo;
//         uint256 validationData = _validateData(0, userOps, chainIds, opInfo);
//         _simulationOnlyValidations(userOps[opInfo.userOpIndex]);
        
//         ValidationData memory data = _intersectTimeRange(validationData);

//         numberMarker();
//         uint256 paid = _executeUserOp(0, userOps[opInfo.userOpIndex], opInfo);
//         numberMarker();
//         bool targetSuccess;
//         bytes memory targetResult;
//         if (target != address(0)) {
//             (targetSuccess, targetResult) = target.call(targetCallData);
//         }
//         revert ExecutionResult(0, paid, data.validAfter, data.validUntil, targetSuccess, targetResult);
//     }

//     /// @inheritdoc IKlasterEntryPoint
//     function simulateValidation(PackedUserOperation[] calldata userOps, uint256[] calldata chainIds) external {
//         UserOpInfo memory outOpInfo;

//         uint256 validationData = _validateData(0, userOps, chainIds, outOpInfo);
//         _simulationOnlyValidations(userOps[outOpInfo.userOpIndex]);

//         ValidationData memory data = _intersectTimeRange(validationData);
//         address aggregator = data.aggregator;
//         bool sigFailed = aggregator == address(1);
//         ReturnInfo memory returnInfo = ReturnInfo(
//             outOpInfo.preOpGas,
//             sigFailed,
//             data.validAfter,
//             data.validUntil
//         );

//         revert ValidationResult(returnInfo);
//     }


//     /**
//      * A memory copy of UserOp static fields only.
//      * Excluding: callData, initCode and signature. Replacing paymasterAndData with paymaster.
//      */
//     struct MemoryUserOp {
//         address sender;
//         uint256 nonce;
//         uint256 verificationGasLimit;
//         uint256 callGasLimit;
//         uint256 maxFeePerGas;
//         uint256 maxPriorityFeePerGas;
//     }

//     struct UserOpInfo {
//         MemoryUserOp mUserOp;
//         bytes32 userOpHash;
//         uint256 userOpIndex;
//         uint256 preOpGas;
//     }

//     /**
//      * Inner function to handle a UserOperation.
//      * Must be declared "external" to open a call context, but it can only be called by handleOps.
//      * @param callData - The callData to execute.
//      * @param opInfo   - The UserOpInfo struct.
//      * @return actualGasCost - the actual cost in eth this UserOperation paid for gas
//      */
//     function innerHandleOp(
//         bytes memory callData,
//         UserOpInfo memory opInfo
//     ) external returns (uint256 actualGasCost) {
//         uint256 preGas = gasleft();
//         require(msg.sender == address(this), "AA92 internal call only");
//         MemoryUserOp memory mUserOp = opInfo.mUserOp;

//         uint256 callGasLimit = mUserOp.callGasLimit;
//         unchecked {
//             // handleOps was called with gas limit too low. abort entire bundle.
//             if (
//                 gasleft() * 63 / 64 <
//                 callGasLimit +
//                 INNER_GAS_OVERHEAD
//             ) {
//                 assembly ("memory-safe") {
//                     mstore(0, INNER_OUT_OF_GAS)
//                     revert(0, 32)
//                 }
//             }
//         }

//         if (callData.length > 0) {
//             bool success = Exec.call(mUserOp.sender, 0, callData, callGasLimit);
//             if (!success) {
//                 bytes memory result = Exec.getReturnData(REVERT_REASON_MAX_LEN);
//                 if (result.length > 0) {
//                     emit UserOperationRevertReason(
//                         opInfo.userOpHash,
//                         mUserOp.sender,
//                         mUserOp.nonce,
//                         result
//                     );
//                 }
//             }
//         }

//         unchecked {
//             uint256 actualGas = preGas - gasleft();
//             return _postExecution(opInfo, actualGas);
//         }
//     }

//     /// @inheritdoc IKlasterEntryPoint
//     function getUserOpHash(
//         PackedUserOperation[] calldata userOps, uint256[] calldata chainIds
//     ) public view override returns (bytes32 userOpHash) {
//         for (uint256 i = 0; i < userOps.length; i++) {
//             userOpHash = keccak256(abi.encode(userOpHash, userOps[i].hash(), address(this), chainIds[i]));
//         }
//     }

//     /**
//      * Copy general fields from userOp into the memory opInfo structure.
//      * @param userOp  - The user operation.
//      * @param mUserOp - The memory user operation.
//      */
//     function _copyUserOpToMemory(
//         PackedUserOperation calldata userOp,
//         MemoryUserOp memory mUserOp
//     ) internal pure {
//         mUserOp.sender = userOp.sender;
//         mUserOp.nonce = userOp.nonce;
//         (mUserOp.verificationGasLimit, mUserOp.callGasLimit) = UserOperationLib.unpackUints(userOp.accountGasLimits);
//         (mUserOp.maxPriorityFeePerGas, mUserOp.maxFeePerGas) = UserOperationLib.unpackUints(userOp.gasFees);        
//     }

//     /**
//      * Create sender smart contract account if init code is provided.
//      * @param opIndex  - The operation index.
//      * @param opInfo   - The operation info.
//      * @param initCode - The init code for the smart contract account.
//      */
//     function _createSenderIfNeeded(
//         uint256 opIndex,
//         UserOpInfo memory opInfo,
//         bytes calldata initCode
//     ) internal {
//         if (initCode.length != 0) {
//             address sender = opInfo.mUserOp.sender;
//             if (sender.code.length != 0)
//                 revert FailedOp(opIndex, "AA10 sender already constructed");
//             address sender1 = senderCreator().createSender{
//                 gas: opInfo.mUserOp.verificationGasLimit
//             }(initCode);
//             if (sender1 == address(0))
//                 revert FailedOp(opIndex, "AA13 initCode failed or OOG");
//             if (sender1 != sender)
//                 revert FailedOp(opIndex, "AA14 initCode must return sender");
//             if (sender1.code.length == 0)
//                 revert FailedOp(opIndex, "AA15 initCode must create sender");
//             address factory = address(bytes20(initCode[0:20]));
//             emit AccountDeployed(
//                 opInfo.userOpHash,
//                 sender,
//                 factory,
//                 address(0)
//             );
//         }
//     }

//     /// @inheritdoc IKlasterEntryPoint
//     function getSenderAddress(bytes calldata initCode) public {
//         address sender = senderCreator().createSender(initCode);
//         revert SenderAddressResult(sender);
//     }

//     function _simulationOnlyValidations(PackedUserOperation calldata userOp) internal view {
//         // solhint-disable-next-line no-empty-blocks
//         try this._validateSender(userOp.initCode, userOp.sender) {}
//         catch Error(string memory revertReason) {
//             if (bytes(revertReason).length != 0) {
//                 revert FailedOp(0, revertReason);
//             }
//         }
//     }

//     /**
//     * Called only during simulation.
//     * This function always reverts to prevent warm/cold storage differentiation in simulation vs execution.
//     */
//     function _validateSender(bytes calldata initCode, address sender) external view {
//         if (initCode.length == 0 && sender.code.length == 0) {
//             // it would revert anyway. but give a meaningful message
//             revert("AA20 account not deployed");
//         }
//         // always revert
//         revert("");
//     }

//     /**
//      * Call account.validateUserOp.
//      * Revert (with FailedOp) in case validateUserOp reverts, or account didn't send required prefund.
//      * Decrement account's deposit if needed.
//      * @param opIndex         - The operation index.
//      * @param op              - The user operation.
//      * @param opInfo          - The operation info.
//      */
//     function _validateAccountData(
//         uint256 opIndex,
//         PackedUserOperation calldata op,
//         UserOpInfo memory opInfo,
//         uint256 verificationGasLimit
//     )
//         internal
//         returns (
//             uint256 validationData
//         )
//     {
//         unchecked {
//             MemoryUserOp memory mUserOp = opInfo.mUserOp;
//             address sender = mUserOp.sender;
//             _createSenderIfNeeded(opIndex, opInfo, op.initCode);
//             uint256 missingAccountFunds = 0;
//             try
//                 IAccount(sender).validateUserOp{
//                     gas: verificationGasLimit
//                 }(op, opInfo.userOpHash, missingAccountFunds)
//             returns (uint256 _validationData) {
//                 validationData = _validationData;
//             } catch {
//                 revert FailedOpWithRevert(opIndex, "AA23 reverted", Exec.getReturnData(REVERT_REASON_MAX_LEN));
//             }
//         }
//     }

//     /**
//      * Revert if either account validationData or paymaster validationData is expired.
//      * @param opIndex                 - The operation index.
//      * @param validationData          - The account validationData.
//      * @param expectedAggregator      - The expected aggregator.
//      */
//     function _validateAccountValidationData(
//         uint256 opIndex,
//         uint256 validationData,
//         address expectedAggregator
//     ) internal view {
//         (address aggregator, bool outOfTimeRange) = _getValidationData(
//             validationData
//         );
//         if (expectedAggregator != aggregator) {
//             revert FailedOp(opIndex, "AA24 signature error");
//         }
//         if (outOfTimeRange) {
//             revert FailedOp(opIndex, "AA22 expired or not due");
//         }
//     }

//     /**
//      * Parse validationData into its components.
//      * @param validationData - The packed validation data (sigFailed, validAfter, validUntil).
//      * @return aggregator the aggregator of the validationData
//      * @return outOfTimeRange true if current time is outside the time range of this validationData.
//      */
//     function _getValidationData(
//         uint256 validationData
//     ) internal view returns (address aggregator, bool outOfTimeRange) {
//         if (validationData == 0) {
//             return (address(0), false);
//         }
//         ValidationData memory data = _parseValidationData(validationData);
//         // solhint-disable-next-line not-rely-on-time
//         outOfTimeRange = block.timestamp > data.validUntil || block.timestamp < data.validAfter;
//         aggregator = data.aggregator;
//     }

//     /**
//      * Validate account and paymaster (if defined) and
//      * also make sure total validation doesn't exceed verificationGasLimit.
//      * This method is called off-chain (simulateValidation()) and on-chain (from handleOps)
//      * @param opIndex - The index of this userOp into the "opInfos" array.
//      * @param userOps  - The userOps to validate.
//      */
//     function _validateData(
//         uint256 opIndex,
//         PackedUserOperation[] calldata userOps,
//         uint256[] calldata chainIds,
//         UserOpInfo memory outOpInfo
//     )
//         internal
//         returns (uint256 validationData)
//     {
//         uint256 preGas = gasleft();
//         (
//             PackedUserOperation calldata userOp,
//             uint256 userOpIndex
//         ) = _extractForThisChain(userOps, chainIds);
//         MemoryUserOp memory mUserOp = outOpInfo.mUserOp;
//         _copyUserOpToMemory(userOp, mUserOp);
//         outOpInfo.userOpHash = getUserOpHash(userOps, chainIds);
//         outOpInfo.userOpIndex = userOpIndex;

//         // Validate all numeric values in userOp are well below 128 bit, so they can safely be added
//         // and multiplied without causing overflow.
//         uint256 verificationGasLimit = mUserOp.verificationGasLimit;
//         uint256 maxGasValues = verificationGasLimit |
//             mUserOp.callGasLimit |
//             mUserOp.maxFeePerGas |
//             mUserOp.maxPriorityFeePerGas;
//         require(maxGasValues <= type(uint120).max, "AA94 gas values overflow");

//         validationData = _validateAccountData(
//             opIndex,
//             userOp,
//             outOpInfo,
//             verificationGasLimit
//         );

//         if (!_validateAndUpdateNonce(mUserOp.sender, mUserOp.nonce)) {
//             revert FailedOp(opIndex, "AA25 invalid account nonce");
//         }

//         unchecked {
//             if (preGas - gasleft() > verificationGasLimit) {
//                 revert FailedOp(opIndex, "AA26 over verificationGasLimit");
//             }
//             outOpInfo.preOpGas = preGas - gasleft() + userOp.preVerificationGas;
//         }
//     }

//     function _extractForThisChain(
//         PackedUserOperation[] calldata userOps,
//         uint256[] calldata chainIds
//     ) internal view returns (PackedUserOperation calldata userOp, uint256 index) {
//         for (uint256 i = 0; i < userOps.length; i++) {
//             if (chainIds[i] == block.chainid) { return (userOps[i], i); }
//         }

//         revert("User's multichain intent doesn't target this blockchain network.");
//     }

//     function _postExecution(
//         UserOpInfo memory opInfo,
//         uint256 actualGas
//     ) private returns (uint256 actualGasCost) {
//         uint256 preGas = gasleft();
//         MemoryUserOp memory mUserOp = opInfo.mUserOp;
//         uint256 gasPrice = getUserOpGasPrice(mUserOp);
//         actualGas += preGas - gasleft();
//         actualGasCost = actualGas * gasPrice;
//         emitUserOperationEvent(opInfo, true, actualGasCost, actualGas);
//     }

//     /**
//      * The gas price this UserOp agrees to pay.
//      * Relayer/block builder might submit the TX with higher priorityFee, but the user should not.
//      * @param mUserOp - The userOp to get the gas price from.
//      */
//     function getUserOpGasPrice(
//         MemoryUserOp memory mUserOp
//     ) internal view returns (uint256) {
//         unchecked {
//             uint256 maxFeePerGas = mUserOp.maxFeePerGas;
//             uint256 maxPriorityFeePerGas = mUserOp.maxPriorityFeePerGas;
//             if (maxFeePerGas == maxPriorityFeePerGas) {
//                 //legacy mode (for networks that don't support basefee opcode)
//                 return maxFeePerGas;
//             }
//             return min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
//         }
//     }

//     /**
//      * The offset of the given bytes in memory.
//      * @param data - The bytes to get the offset of.
//      */
//     function getOffsetOfMemoryBytes(
//         bytes memory data
//     ) internal pure returns (uint256 offset) {
//         assembly {
//             offset := data
//         }
//     }

//     /**
//      * The bytes in memory at the given offset.
//      * @param offset - The offset to get the bytes from.
//      */
//     function getMemoryBytesFromOffset(
//         uint256 offset
//     ) internal pure returns (bytes memory data) {
//         assembly ("memory-safe") {
//             data := offset
//         }
//     }

//     /// @inheritdoc IKlasterEntryPoint
//     function delegateAndRevert(address target, bytes calldata data) external {
//         (bool success, bytes memory ret) = target.delegatecall(data);
//         revert DelegateAndRevert(success, ret);
//     }

//     //place the NUMBER opcode in the code.
//     // this is used as a marker during simulation, as this OP is completely banned from the simulated code of the
//     // account and paymaster.
//     function numberMarker() internal view {
//         assembly {mstore(0, number())}
//     }
// }
