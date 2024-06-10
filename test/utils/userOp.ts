import { concat, ethers } from "ethers";
import {
  getEntryPoint,
  getKlasterModule,
  getKlasterPaymaster,
  getSmartAccountFactory,
  getSmartAccountImplementation,
} from "./setupHelper";
import {
  PaymasterAndData,
  SignedUserOp,
  UserOp,
  ValidationData,
} from "../types";
import {
  getKlasterUserOpHash,
  getMerkleTree,
  klasterUserOpToMerkleLeaf,
} from "./merkleTree";

export function parseValidationData(
  validateUserOpResult: bigint,
): ValidationData {
  const validateUserOpResultPadded = ethers.toBeHex(validateUserOpResult, 32);
  const validAfter = ethers.toNumber(
    ethers.dataSlice(validateUserOpResultPadded, 0, 6),
  );
  const validUntil = ethers.toNumber(
    ethers.dataSlice(validateUserOpResultPadded, 6, 12),
  );
  const status = ethers.toNumber(
    ethers.dataSlice(validateUserOpResultPadded, 12),
  );
  return {
    validAfter,
    validUntil,
    status,
  };
}

export async function fillUserOp(
  masterWallet: string,
  salt: number,
  to: string,
  value: bigint,
  data: string,
  createSender: boolean,
  userOpOverrides: Partial<UserOp>,
  signer: ethers.Signer,
  nonceKey = 0,
): Promise<SignedUserOp> {
  const scaImpl = await getSmartAccountImplementation();
  const scaFactory = await getSmartAccountFactory();
  const entryPoint = await getEntryPoint();
  const klasterModule = await getKlasterModule();
  const klasterPaymaster = await getKlasterPaymaster();

  const moduleSetupData = klasterModule.interface.encodeFunctionData(
    "initForSmartAccount",
    [masterWallet],
  );

  const sender = await scaFactory.getAddressForCounterFactualAccount(
    klasterModule.target,
    moduleSetupData,
    salt,
  );
  const initCode = createSender
    ? concat([
        await scaFactory.getAddress(),
        scaFactory.interface.encodeFunctionData("deployCounterFactualAccount", [
          klasterModule.target,
          moduleSetupData,
          salt,
        ]),
      ])
    : "0x";

  const preVerificationGas = "50000";
  const createSenderCost =
    initCode == "0x"
      ? 0
      : await estimateCreateSenderCost(
          await entryPoint.getAddress(),
          ethers.dataSlice(initCode, 0, 20),
          ethers.dataSlice(initCode, 20),
          signer.provider!,
        );
  const verificationGasLimit = (createSenderCost + 250000).toString();
  const callGasLimit = "50000";

  const feeData = await signer.provider!.getFeeData();
  const maxFeePerGas = feeData.maxFeePerGas!.toString();
  const maxPriorityFeePerGas = feeData.maxPriorityFeePerGas!.toString();

  const nonce = (await entryPoint.getNonce(sender, nonceKey)).toString();
  const callData = scaImpl.interface.encodeFunctionData("execute", [
    to,
    value,
    data,
  ]);

  let maxGasLimit = (
    Number(preVerificationGas) + Number(callGasLimit)
  ).toString();
  let nodeFee = 10;
  let paymasterAndData = concat([
    await klasterPaymaster.getAddress(),
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "uint256"],
      [maxGasLimit, nodeFee],
    ),
  ]);

  const signature = await encodeSig({
    itxHash:
      "0x0000000000000000000000000000000000000000000000000000000000000000",
    proof: [
      "0x0000000000000000000000000000000000000000000000000000000000000000",
    ],
    lowerBoundTimestamp: "0",
    upperBoundTimestamp: "0",
    signature:
      "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  });

  let userOp = {
    sender,
    callData,
    callGasLimit,
    initCode,
    maxFeePerGas,
    maxPriorityFeePerGas,
    nonce,
    preVerificationGas,
    verificationGasLimit,
    paymasterAndData,
    signature,
    ...userOpOverrides,
  };

  return userOp;
}

export async function fillAndSignMany(
  masterWallet: string,
  salt: number,
  to: string[],
  value: bigint[],
  data: string[],
  createSender: boolean[],
  lowerBoundTimestamp: string,
  upperBoundTimestamp: string,
  signer: ethers.Signer,
  chainId: string,
  nonceKey: number[],
) {
  let userOps: UserOp[] = [];
  for (let i = 0; i < to.length; i++) {
    userOps.push(
      await fillUserOp(
        masterWallet,
        salt,
        to[i],
        value[i],
        data[i],
        createSender[i],
        {},
        signer,
        nonceKey[i],
      ),
    );
  }

  let merkleTree = getMerkleTree(
    userOps.map((it, i) => {
      return {
        userOp: it,
        lowerBoundTimestamp: lowerBoundTimestamp,
        upperBoundTimestamp: upperBoundTimestamp,
        chainId,
      };
    }),
  );

  let itxHash = merkleTree.root;
  let itxHashSigned = await signer.signMessage(ethers.getBytes(itxHash));

  let signedUserOps: SignedUserOp[] = await Promise.all(
    userOps.map(async (it) => {
      return {
        ...it,
        signature: await encodeSig({
          itxHash: itxHash,
          proof: merkleTree.getProof(
            klasterUserOpToMerkleLeaf({
              userOp: it,
              lowerBoundTimestamp: lowerBoundTimestamp,
              upperBoundTimestamp: upperBoundTimestamp,
              chainId,
            }),
          ),
          lowerBoundTimestamp: lowerBoundTimestamp,
          upperBoundTimestamp: upperBoundTimestamp,
          signature: itxHashSigned,
        }),
      };
    }),
  );

  return signedUserOps;
}

export async function fillAndSign(
  masterWallet: string,
  salt: number,
  to: string,
  value: bigint,
  data: string,
  createSender: boolean,
  lowerBoundTimestamp: string,
  upperBoundTimestamp: string,
  signer: ethers.Signer,
  chainId: string,
  userOpOverrides: Partial<UserOp> = {},
): Promise<SignedUserOp> {
  const op = await fillUserOp(
    masterWallet,
    salt,
    to,
    value,
    data,
    createSender,
    userOpOverrides,
    signer,
  );

  const merkleTree = getMerkleTree([
    {
      userOp: op,
      chainId,
      lowerBoundTimestamp,
      upperBoundTimestamp,
    },
  ]);

  let itxHash = merkleTree.root;
  let itxHashSigned = await signer.signMessage(ethers.getBytes(itxHash));
  let proof = merkleTree.getProof(
    klasterUserOpToMerkleLeaf({
      userOp: op,
      lowerBoundTimestamp,
      upperBoundTimestamp,
      chainId,
    }),
  );

  return {
    ...op,
    signature: await encodeSig({
      itxHash,
      proof,
      lowerBoundTimestamp,
      upperBoundTimestamp,
      signature: itxHashSigned,
    }),
  };
}

export async function updatePaymasterData(
  userOp: SignedUserOp,
  overrides: Partial<PaymasterAndData>,
): Promise<SignedUserOp> {
  const parsedPaymasterData = await decodePaymasterData(userOp);
  const updatedPaymasterData = {
    ...parsedPaymasterData,
    ...overrides,
  };
  return {
    ...userOp,
    paymasterAndData: await encodePaymasterData(updatedPaymasterData),
  };
}

export async function decodePaymasterData(
  userOp: SignedUserOp,
): Promise<PaymasterAndData> {
  const defaultCoder = ethers.AbiCoder.defaultAbiCoder();
  const paymaster = ethers.dataSlice(userOp.paymasterAndData, 0, 20);
  const decodedData = defaultCoder.decode(
    ["uint256", "uint256"],
    ethers.dataSlice(userOp.paymasterAndData, 20),
  );
  return {
    paymaster,
    maxGasLimit: decodedData[0].toString(),
    nodePremium: decodedData[1].toString(),
  };
}

async function encodePaymasterData(
  paymasterData: PaymasterAndData,
): Promise<string> {
  const defaultCoder = ethers.AbiCoder.defaultAbiCoder();
  const encodedData = defaultCoder.encode(
    ["uint256", "uint256"],
    [paymasterData.maxGasLimit, paymasterData.nodePremium],
  );
  return ethers.concat([paymasterData.paymaster, encodedData]);
}

type UserOpSignature = {
  itxHash: string;
  proof: string[];
  lowerBoundTimestamp: string;
  upperBoundTimestamp: string;
  signature: string;
};

export async function updateSignature(
  userOp: SignedUserOp,
  overrides: Partial<UserOpSignature>,
): Promise<SignedUserOp> {
  const currentSig = await decodeSig(userOp);
  const newSig = {
    ...currentSig,
    ...overrides,
  };
  const signature = await encodeSig(newSig);
  return {
    ...userOp,
    signature,
  };
}

export async function encodeSig(sig: UserOpSignature): Promise<string> {
  const defaultCoder = ethers.AbiCoder.defaultAbiCoder();
  const klasterModule = await getKlasterModule();
  const encodedSig = defaultCoder.encode(
    ["bytes32", "bytes32[]", "uint48", "uint48", "bytes"],
    [
      sig.itxHash,
      sig.proof,
      sig.lowerBoundTimestamp,
      sig.upperBoundTimestamp,
      sig.signature,
    ],
  );

  return defaultCoder.encode(
    ["bytes", "address"],
    [encodedSig, klasterModule.target],
  );
}

export async function decodeSig(
  userOp: SignedUserOp,
): Promise<UserOpSignature> {
  const defaultCoder = ethers.AbiCoder.defaultAbiCoder();
  const decodedData = defaultCoder.decode(
    ["bytes", "address"],
    userOp.signature,
  );
  const decodedSig = defaultCoder.decode(
    ["bytes32", "bytes32[]", "uint48", "uint48", "bytes"],
    decodedData[0],
  );

  return {
    itxHash: decodedSig[0],
    proof: decodedSig[1],
    lowerBoundTimestamp: decodedSig[2],
    upperBoundTimestamp: decodedSig[3],
    signature: decodedSig[4],
  };
}

async function estimateCreateSenderCost(
  entryPoint: string,
  factory: string,
  callData: string,
  provider: ethers.Provider,
): Promise<number> {
  try {
    return Number(
      await provider.estimateGas({
        from: entryPoint,
        to: factory,
        data: callData,
        gasLimit: 10e6,
      }),
    );
  } catch (err) {
    return 1_000_000;
  }
}
