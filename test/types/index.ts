import { BigNumberish, BytesLike } from "ethers";

export type KlasterUserOp = {
  userOp: UserOp;
  lowerBoundTimestamp: string;
  upperBoundTimestamp: string;
  chainId: string;
};

/**
 * ERC-4337 Types
 */
export type PaymasterAndData = {
  paymaster: string;
  maxGasLimit: string;
  nodePremium: string;
};

export type ValidationData = {
  validAfter: number;
  validUntil: number;
  status: number;
};

export type UserOp = {
  sender: string;
  nonce: string;
  initCode: string;
  callData: string;
  callGasLimit: string;
  verificationGasLimit: string;
  preVerificationGas: string;
  maxFeePerGas: string;
  maxPriorityFeePerGas: string;
  paymasterAndData: string;
};

export type SignedUserOp = UserOp & {
  signature: string;
};

/**
 * Solidity Types
 */
export type address = string;
export type uint256 = BigNumberish;
export type uint = BigNumberish;
export type uint64 = BigNumberish;
export type bytes = BytesLike;
export type bytes32 = BytesLike;
