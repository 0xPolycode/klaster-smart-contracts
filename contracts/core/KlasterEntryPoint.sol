// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.0;

// import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
// import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
// import "@account-abstraction/contracts/core/NonceManager.sol";
// import "@account-abstraction/contracts/utils/Exec.sol";
// import "@account-abstraction/contracts/interfaces/IAccount.sol";
// import "@account-abstraction/contracts/interfaces/IAccountExecute.sol";
// import "@account-abstraction/contracts/core/SenderCreator.sol";
// import "@account-abstraction/contracts/core/Helpers.sol";
// import "@account-abstraction/contracts/core/UserOperationLib.sol";
// import "../interfaces/IKlasterEntrypoint.sol";

// contract KlasterEntryPoint is IKlasterEntryPoint, ReentrancyGuard, NonceManager {

//     using UserOperationLib for PackedUserOperation;

//     SenderCreator private immutable _senderCreator = new SenderCreator();

//     function senderCreator() internal view virtual returns (SenderCreator) {
//         return _senderCreator;
//     }

//     uint256 private constant INNER_GAS_OVERHEAD = 10000;

//     // Marker for inner call revert on out of gas
//     bytes32 private constant INNER_OUT_OF_GAS = hex"deaddead";
    
//     uint256 private constant REVERT_REASON_MAX_LEN = 2048;

//     /**
//      * Klaster Node calls this function with bundle of multichain intents.
//      * Can bundle multiple user's intents all in the same call.
//      * One user intent contains two lists -> txs (UserOp) & chain ids for every tx.
//      * We need all txs data to calculate full multichain intent operation hash and validate against SCA,
//      * while only the txs targeting this chain are actually going to be executed.
//      * 
//      * @param ops List of lists - each representing user's multichain intent (multiple txs on different chains)
//      * @param chains List of lists - each representing chain ids for user's list of multichain transactions
//      */
//     function handleOps(
//         PackedUserOperation[][] calldata ops,
//         uint256[][] calldata chains
//     ) public override nonReentrant {
//         require(ops.length == chains.length, "KlasterEntryPoint:: UserOps & ChainIds list sizes not equal.");

//         unchecked {
//             bytes32[] memory userOpsHashes = new bytes32[](ops.length);
    
//             for (uint256 i = 0; i < ops.length; i++) {
//                 userOpsHashes[i] = getUserOpHash(ops[i], chains[i]);
//                 uint256[] memory validationData = _validateData(i, ops[i], chains[i], userOpsHashes[i]);
//                 _validateAccountValidationData(
//                     i,
//                     validationData,
//                     address(0)
//                 );
//             }

//             emit BeforeExecution();

//             for (uint256 i = 0; i < ops.length; i++) {
//                 _executeUserOp(i, ops[i], chains[i], userOpsHashes[i]);
//             }
//         }
//     }

//     /// @inheritdoc IKlasterEntryPoint
//     function simulateHandleOps(
//         PackedUserOperation[] calldata ops,
//         uint256[] calldata chains,
//         address target,
//         bytes calldata targetCallData
//     ) external override {
//         _simulationOnlyValidations(ops);
//         bytes32 userOpsHash = getUserOpHash(ops, chains);
//         uint256[] validationData = _validateData(0, ops, chains, userOpsHash);
//         ValidationData[] memory data = _intersectTimeRange(validationData, paymasterValidationData);

//         numberMarker();
//         uint256 paid = _executeUserOp(0, op, opInfo);
//         numberMarker();
//         bool targetSuccess;
//         bytes memory targetResult;
//         if (target != address(0)) {
//             (targetSuccess, targetResult) = target.call(targetCallData);
//         }
//         revert ExecutionResult(opInfo.preOpGas, paid, data.validAfter, data.validUntil, targetSuccess, targetResult);
//     }

//     function _simulationOnlyValidations(
//         PackedUserOperation[] calldata userOps,
//         uint256[] calldata chains
//     ) internal view {
//         // solhint-disable-next-line no-empty-blocks
//         for (uint256 i = 0; i < userOps.length; i++) {
//             if (chains[i] == block.chainid) {
//                 try this._validateSenderAndPaymaster(userOps[i].initCode, userOps[i].sender, userOps[i].paymasterAndData) {}
//                 catch Error(string memory revertReason) {
//                     if (bytes(revertReason).length != 0) {
//                         revert FailedOp(0, revertReason);
//                     }
//                 }
//             }
//         }
//     }

//     /**
//     * Called only during simulation.
//     * This function always reverts to prevent warm/cold storage differentiation in simulation vs execution.
//     */
//     function _validateSenderAndPaymaster(bytes calldata initCode, address sender, bytes calldata paymasterAndData) external view {
//         if (initCode.length == 0 && sender.code.length == 0) {
//             // it would revert anyway. but give a meaningful message
//             revert("AA20 account not deployed");
//         }
//         if (paymasterAndData.length >= 20) {
//             address paymaster = address(bytes20(paymasterAndData[0 : 20]));
//             if (paymaster.code.length == 0) {
//                 // it would revert anyway. but give a meaningful message
//                 revert("AA30 paymaster not deployed");
//             }
//         }
//         // always revert
//         revert("");
//     }

//     /// @inheritdoc IKlasterEntryPoint
//     function getSenderAddress(bytes calldata initCode) public {
//         address sender = senderCreator().createSender(initCode);
//         revert SenderAddressResult(sender);
//     }

//     /**
//      * Execute a user operation.
//      * @param opIndex    - Index into the opInfo array.
//      * @param userOps    - The userOps list to execute.
//      * @param chainIds   - The chainIds for every userOps list item. Execute only ops targeting this chain id
//      * @param userOpsHash - Full user's multichain intent hash
//      */
//     function _executeUserOp(
//         uint256 opIndex,
//         PackedUserOperation[] calldata userOps,
//         uint256[] calldata chainIds,
//         bytes32 userOpsHash
//     )
//     internal {
//         for (uint256 i = 0; i < userOps.length; i++) {
//             if (chainIds[i] == block.chainid) {
//                 bool success;
//                 {
//                     uint256 saveFreePtr;
//                     assembly ("memory-safe") {
//                         saveFreePtr := mload(0x40)
//                     }
//                     bytes calldata callData = userOps[i].callData;
//                     bytes memory innerCall;
//                     bytes4 methodSig;
//                     assembly {
//                         let len := callData.length
//                         if gt(len, 3) {
//                             methodSig := calldataload(callData.offset)
//                         }
//                     }
//                     if (methodSig == IAccountExecute.executeUserOp.selector) {
//                         bytes memory executeUserOp = abi.encodeCall(IAccountExecute.executeUserOp, (userOps[i], userOpsHash));
//                         innerCall = abi.encodeCall(this.innerHandleOp, (executeUserOp, userOps[i], userOpsHash));
//                     } else
//                     {
//                         innerCall = abi.encodeCall(this.innerHandleOp, (callData, userOps[i], userOpsHash));
//                     }
//                     assembly ("memory-safe") {
//                         success := call(gas(), address(), 0, add(innerCall, 0x20), mload(innerCall), 0, 32)
//                         mstore(0x40, saveFreePtr)
//                     }
//                 }
//                 if (!success) {
//                     bytes32 innerRevertCode;
//                     assembly ("memory-safe") {
//                         let len := returndatasize()
//                         if eq(32,len) {
//                             returndatacopy(0, 0, 32)
//                             innerRevertCode := mload(0)
//                         }
//                     }
//                     if (innerRevertCode == INNER_OUT_OF_GAS) {
//                         // handleOps was called with gas limit too low. abort entire bundle.
//                         //can only be caused by bundler (leaving not enough gas for inner call)
//                         revert FailedOp(opIndex, "AA95 out of gas");
//                     } else {
//                         emit PostOpRevertReason(
//                             userOpsHash,
//                             userOps[i].sender,
//                             userOps[i].nonce,
//                             Exec.getReturnData(REVERT_REASON_MAX_LEN)
//                         );
//                     }
//                 }
//             }
//         }
//     }

//     /**
//      * Inner function to handle a UserOperation.
//      * Must be declared "external" to open a call context, but it can only be called by handleOps.
//      * @param callData - The callData to execute.
//      * @param userOp   - The UserOp struct.
//      * @param userOpsHash - User's multichain intent hash
//      */
//     function innerHandleOp(
//         bytes memory callData,
//         PackedUserOperation memory userOp,
//         bytes32 userOpsHash
//     ) external {
//         require(msg.sender == address(this), "AA92 internal call only");

//         (, uint256 callGasLimit) = UserOperationLib.unpackUints(userOp.accountGasLimits);
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
//             bool success = Exec.call(userOp.sender, 0, callData, callGasLimit);
//             if (!success) {
//                 bytes memory result = Exec.getReturnData(REVERT_REASON_MAX_LEN);
//                 if (result.length > 0) {
//                     emit UserOperationRevertReason(
//                         userOpsHash,
//                         userOp.sender,
//                         userOp.nonce,
//                         result
//                     );
//                 }
//             }
//         }
//     }

//     /**
//      * Validate account and
//      * also make sure total validation doesn't exceed verificationGasLimit.
//      * This method is called off-chain (simulateValidation()) and on-chain (from handleOps)
//      * @param opIndex - The index of this userOps into the "opInfos" array.
//      * @param userOps  - The userOps to validate.
//      * @param chainIds - The chainIds for every userOp.
//      */
//     function _validateData(
//         uint256 opIndex,
//         PackedUserOperation calldata userOp,
//         bytes32 userOpsHash
//     )
//         internal
//         returns (uint256 validationData)
//     {
//         uint256 preGas = gasleft();

//         // Validate all numeric values in userOp are well below 128 bit, so they can safely be added
//         // and multiplied without causing overflow.
//         (uint256 verificationGasLimit, uint256 callGasLimit) = UserOperationLib.unpackUints(userOps[i].accountGasLimits);
//         (uint256 maxPriorityFeePerGas, uint256 maxFeePerGas) = UserOperationLib.unpackUints(userOps[i].gasFees);
//         uint256 maxGasValues = userOps[i].preVerificationGas |
//             verificationGasLimit |
//             callGasLimit |
//             maxFeePerGas |
//             maxPriorityFeePerGas;
//         require(maxGasValues <= type(uint120).max, "AA94 gas values overflow");

//         validationData[i] = _validateAccount(
//             opIndex,
//             userOps[i],
//             userOpsHash
//         );

//         if (!_validateAndUpdateNonce(userOps[i].sender, userOps[i].nonce)) {
//             revert FailedOp(opIndex, "AA25 invalid account nonce");
//         }

//         unchecked {
//             if (preGas - gasleft() > verificationGasLimit) {
//                 revert FailedOp(opIndex, "AA26 over verificationGasLimit");
//             }
//         }
//     }

//     /**
//      * Call account.validateUserMultichainOp.
//      * Revert (with FailedOp) in case validateUserMultichainOp reverts
//      * @param opIndex         - The operation index.
//      * @param userOp          - UserOp
//      * @param opsHash         - Full multichain ops hash
//      */
//     function _validateAccount(
//         uint256 opIndex,
//         PackedUserOperation calldata userOp,
//         bytes32 opsHash
//     )
//         internal
//         returns (
//             uint256 validationData
//         )
//     {
//         unchecked {
//             address sender = userOp.sender;
//             (uint256 verificationGasLimit,) = UserOperationLib.unpackUints(userOp.accountGasLimits);
//             _createSenderIfNeeded(opIndex, sender, userOp.initCode, verificationGasLimit, opsHash);
//             try
//                 IAccount(sender).validateUserOp{
//                     gas: verificationGasLimit
//                 }(userOp, opsHash, 0)
//             returns (uint256 _validationData) {
//                 validationData = _validationData;
//             } catch {
//                 revert FailedOpWithRevert(opIndex, "AA23 reverted", Exec.getReturnData(REVERT_REASON_MAX_LEN));
//             }
//         }
//     }

//     /**
//      * Revert if validationData is expired.
//      * @param opIndex                 - The operation index.
//      * @param validationData          - The account validationData.
//      * @param expectedAggregator      - The expected aggregator.
//      */
//     function _validateAccountValidationData(
//         uint256 opIndex,
//         uint256[] memory validationData,
//         address expectedAggregator
//     ) internal view {
//         for (uint256 i = 0; i < validationData.length; i++) {
//             (address aggregator, bool outOfTimeRange) = _getValidationData(
//                 validationData[i]
//             );
//             if (expectedAggregator != aggregator) {
//                 revert FailedOp(opIndex, "AA24 signature error");
//             }
//             if (outOfTimeRange) {
//                 revert FailedOp(opIndex, "AA22 expired or not due");
//             }
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
//      * Create sender smart contract account if init code is provided.
//      * @param opIndex  - The operation index.
//      * @param sender   - The operation sender.
//      * @param initCode - The init code for the smart contract account.
//      * @param verificationGasLimit - The operation verifcationGasLimit
//      * @param userOpsHash - User's multichain intent hash
//      */
//     function _createSenderIfNeeded(
//         uint256 opIndex,
//         address sender,
//         bytes calldata initCode,
//         uint256 verificationGasLimit,
//         bytes32 userOpsHash
//     ) internal {
//         if (initCode.length != 0) {
//             if (sender.code.length != 0)
//                 revert FailedOp(opIndex, "AA10 sender already constructed");
//             address sender1 = senderCreator().createSender{
//                 gas: verificationGasLimit
//             }(initCode);
//             if (sender1 == address(0))
//                 revert FailedOp(opIndex, "AA13 initCode failed or OOG");
//             if (sender1 != sender)
//                 revert FailedOp(opIndex, "AA14 initCode must return sender");
//             if (sender1.code.length == 0)
//                 revert FailedOp(opIndex, "AA15 initCode must create sender");
//             address factory = address(bytes20(initCode[0:20]));
//             emit AccountDeployed(
//                 userOpsHash,
//                 sender,
//                 factory,
//                 address(0)
//             );
//         }
//     }

//     /// @inheritdoc IKlasterEntryPoint
//     function delegateAndRevert(address target, bytes calldata data) external {
//         (bool success, bytes memory ret) = target.delegatecall(data);
//         revert DelegateAndRevert(success, ret);
//     }

//     /// @inheritdoc IKlasterEntryPoint
//     function getUserOpHash(
//         PackedUserOperation[] calldata userOps, uint256[] calldata chainIds
//     ) public view override returns (bytes32 userOpHash) {
//         for (uint256 i = 0; i < userOps.length; i++) {
//             userOpHash = keccak256(abi.encode(userOpHash, userOps[i].hash(), address(this), chainIds[i]));
//         }
//     }

// }
