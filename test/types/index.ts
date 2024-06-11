import { BigNumberish, BytesLike } from "ethers";

export type KlasterUserOp = {
  userOp: UserOp;
  lowerBoundTimestamp: uint256;
  upperBoundTimestamp: uint256;
  chainId: uint256;
};

export type UserOpSignature = {
  itxHash: bytes32;
  proof: bytes32[];
  lowerBoundTimestamp: uint256;
  upperBoundTimestamp: uint256;
  signature: bytes;
};

/**
 * ERC-4337 Types
 */

// KlasterPaymaster
export type PaymasterAndData = {
  paymaster: address;
  maxGasLimit: uint256;
  nodePremium: uint256;
};

// IEntryPoint ValidationData
export type ValidationData = {
  validAfter: uint48;
  validUntil: uint48;
  status: uint256;
};

// IEntryPoint UserOperation
export type UserOp = {
  sender: address;
  nonce: uint256;
  initCode: bytes;
  callData: bytes;
  callGasLimit: uint256;
  verificationGasLimit: uint256;
  preVerificationGas: uint256;
  maxFeePerGas: uint256;
  maxPriorityFeePerGas: uint256;
  paymasterAndData: bytes;
};

export type SignedUserOp = UserOp & {
  signature: bytes;
};

/**
 * Solidity Types
 */
export type address = string;
export type uint256 = BigNumberish;
export type uint = BigNumberish;
export type uint48 = BigNumberish;
export type uint64 = BigNumberish;
export type uint192 = BigNumberish;
export type bytes = BytesLike;
export type bytes32 = BytesLike;
