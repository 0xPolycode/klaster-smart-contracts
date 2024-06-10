export type KlasterUserOp = {
  userOp: UserOp;
  lowerBoundTimestamp: string;
  upperBoundTimestamp: string;
  chainId: string;
};

export type SignedKlasterUserOp = {
  userOp: SignedUserOp;
  lowerBoundTimestamp: string;
  upperBoundTimestamp: string;
  chainId: string;
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
