import {
    concat,
    keccak256,
    ethers
  } from "ethers";
  import {
    AddressZero,
  } from "../utils/testUtils";
  import { UserOperation } from "./userOperation";
  // import { Deployer } from "../../src/Create2Factory";
import { getEntryPoint, getKlasterModule, getKlasterPaymaster, getSmartAccountFactory, getSmartAccountImplementation } from "./setupHelper";
import { SignedUserOp, UserOp } from "../types";
import { getMerkleTree, klasterUserOpToMerkleLeaf } from "./merkleTree";
import hre from "hardhat";

type ValidationData = {
  validAfter: number;
  validUntil: number;
  status: number;
}
export function parseValidationData(validateUserOpResult: bigint): ValidationData {
  const validateUserOpResultPadded = ethers.toBeHex(validateUserOpResult, 32);
  const validAfter = ethers.toNumber(ethers.dataSlice(validateUserOpResultPadded, 0, 6));
  const validUntil = ethers.toNumber(ethers.dataSlice(validateUserOpResultPadded, 6, 12));
  const status = ethers.toNumber(ethers.dataSlice(validateUserOpResultPadded, 12));
  return {
    validAfter,
    validUntil,
    status
  }
}

  export async function fillUserOp(
    masterWallet: string,
    salt: number,
    to: string,
    value: bigint,
    data: string,
    createSender: boolean,
    userOpOverrides: Partial<UserOp>,
    signer: ethers.Signer
  ): Promise<SignedUserOp> {
    const scaImpl = await getSmartAccountImplementation();
    const scaFactory = await getSmartAccountFactory();
    const entryPoint = await getEntryPoint();
    const klasterModule = await getKlasterModule();
    const klasterPaymaster = await getKlasterPaymaster();

    const moduleSetupData = klasterModule.interface.encodeFunctionData("initForSmartAccount", [
      masterWallet
    ]);
    
    const sender = await scaFactory.getAddressForCounterFactualAccount(
      klasterModule.target,
      moduleSetupData,
      salt
    );
    const initCode = createSender ? concat([await scaFactory.getAddress(), scaFactory.interface.encodeFunctionData("deployCounterFactualAccount", [
      klasterModule.target,
      moduleSetupData,
      salt
    ])]) : "0x";

    const preVerificationGas = "50000";
    const createSenderCost = initCode == "0x" ? 0 : (
      await estimateCreateSenderCost(
        await entryPoint.getAddress(),
        ethers.dataSlice(initCode, 0, 20),
        ethers.dataSlice(initCode, 20),
        signer.provider!
      )
    );
    const verificationGasLimit = (createSenderCost + 250000).toString();
    const callGasLimit = "50000";

    const feeData = await signer.provider!.getFeeData();
    const maxFeePerGas = feeData.maxFeePerGas!.toString();
    const maxPriorityFeePerGas = feeData.maxPriorityFeePerGas!.toString();

    const nonce = (await entryPoint.getNonce(sender, 0)).toString();
    const callData = scaImpl.interface.encodeFunctionData("execute", [
      to, value, data
    ]);

    let maxGasLimit = (Number(preVerificationGas) + Number(callGasLimit)).toString();
    let nodeFee = 10;
    let paymasterAndData = concat([
      await klasterPaymaster.getAddress(),
      ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [
        maxGasLimit, nodeFee
      ])
    ]);

    let signaturePlaceholder =
    "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let dummyProofHash =
      "0x0000000000000000000000000000000000000000000000000000000000000000";
    let itxHashPlaceholder =
      "0x0000000000000000000000000000000000000000000000000000000000000000";
    let inclusionProofPlaceholder = [dummyProofHash];
    let lowerBoundTimestamp = 0;
    let upperBoundTimestamp = 0;

    let signatureBytes = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32[]", "uint48", "uint48", "bytes"],
      [
        itxHashPlaceholder,
        inclusionProofPlaceholder,
        lowerBoundTimestamp,
        upperBoundTimestamp,
        signaturePlaceholder
      ],
    );
    let signature = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes", "address"],
      [ signatureBytes, klasterModule.target ]
    )

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
      ...userOpOverrides
    }

    return userOp;
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
      signer
    );
        
    const merkleTree = getMerkleTree([
      {
        userOp: op,
        chainId,
        lowerBoundTimestamp,
        upperBoundTimestamp
      }
    ]);

    let itxHash = merkleTree.root;
    let itxHashSigned = await signer.signMessage(ethers.getBytes(itxHash));
    let proof = merkleTree.getProof(klasterUserOpToMerkleLeaf(
      {
        userOp: op,
        lowerBoundTimestamp,
        upperBoundTimestamp,
        chainId
      }
    ));

    return {
      ...op,
      signature: await encodeSig({
        itxHash,
        proof,
        lowerBoundTimestamp,
        upperBoundTimestamp,
        signature: itxHashSigned
      })
    };
  }

  type PaymasterAndData = {
    paymaster: string;
    maxGasLimit: string;
    nodePremium: string;
  }

  export async function updatePaymasterData(
    userOp: SignedUserOp,
    overrides: Partial<PaymasterAndData>
  ): Promise<SignedUserOp> {
    const parsedPaymasterData = await decodePaymasterData(userOp);
    const updatedPaymasterData = {
      ...parsedPaymasterData,
      ...overrides
    };
    return {
      ...userOp,
      paymasterAndData: await encodePaymasterData(updatedPaymasterData)
    };
  }

  export async function decodePaymasterData(userOp: SignedUserOp): Promise<PaymasterAndData> {
    const defaultCoder = ethers.AbiCoder.defaultAbiCoder();
    const paymaster = ethers.dataSlice(userOp.paymasterAndData, 0, 20);
    const decodedData = defaultCoder.decode(["uint256", "uint256"], ethers.dataSlice(userOp.paymasterAndData, 20));
    return {
      paymaster,
      maxGasLimit: decodedData[0].toString(),
      nodePremium: decodedData[1].toString()
    }
  }

  async function encodePaymasterData(paymasterData: PaymasterAndData): Promise<string> {
    const defaultCoder = ethers.AbiCoder.defaultAbiCoder();
    const encodedData = defaultCoder.encode(
      ["uint256", "uint256"],
      [paymasterData.maxGasLimit, paymasterData.nodePremium]
    );
    return ethers.concat([paymasterData.paymaster, encodedData]);
  }

  type UserOpSignature = {
    itxHash: string;
    proof: string[];
    lowerBoundTimestamp: string;
    upperBoundTimestamp: string;
    signature: string;
  }

  export async function updateSignature(userOp: SignedUserOp, overrides: Partial<UserOpSignature>): Promise<SignedUserOp> {
    const currentSig = await decodeSig(userOp);
    const newSig = {
      ...currentSig,
      ...overrides
    };
    const signature = await encodeSig(newSig);
    return {
      ...userOp,
      signature
    }
  }

  export async function encodeSig(sig: UserOpSignature): Promise<string> {
    const defaultCoder = ethers.AbiCoder.defaultAbiCoder();
    const klasterModule = await getKlasterModule();
    const encodedSig = defaultCoder.encode(["bytes32", "bytes32[]", "uint48", "uint48", "bytes"], [
      sig.itxHash,
      sig.proof,
      sig.lowerBoundTimestamp,
      sig.upperBoundTimestamp,
      sig.signature
    ]);
    
    return defaultCoder.encode(["bytes", "address"], [
      encodedSig,
      klasterModule.target
    ]);
  }

  export async function decodeSig(userOp: SignedUserOp): Promise<UserOpSignature> {
    const defaultCoder = ethers.AbiCoder.defaultAbiCoder();
    const decodedData = defaultCoder.decode(["bytes", "address"], userOp.signature);
    const decodedSig = defaultCoder.decode(["bytes32", "bytes32[]", "uint48", "uint48", "bytes"], decodedData[0]);
    
    return {
      itxHash: decodedSig[0],
      proof: decodedSig[1],
      lowerBoundTimestamp: decodedSig[2],
      upperBoundTimestamp: decodedSig[3],
      signature: decodedSig[4]
    }
  }

  async function estimateCreateSenderCost(
    entryPoint: string,
    factory: string,
    callData: string,
    provider: ethers.Provider
  ): Promise<number> {
    try {
      return Number(await provider.estimateGas({
        from: entryPoint,
        to: factory,
        data: callData,
        gasLimit: 10e6
      }))
    } catch (err) {
      return 1_000_000;
    }
  }
  
  // export async function makeEcdsaModuleUserOp(
  //   functionName: string,
  //   functionParams: any,
  //   userOpSender: string,
  //   userOpSigner: Signer,
  //   entryPoint: EntryPoint,
  //   moduleAddress: string,
  //   options?: {
  //     preVerificationGas?: number;
  //   },
  //   nonceKey = 0
  // ): Promise<UserOperation> {
  //   const SmartAccount = await ethers.getContractFactory("SmartAccount");
  
  //   const txnDataAA1 = SmartAccount.interface.encodeFunctionData(
  //     functionName,
  //     functionParams
  //   );
  
  //   const userOp = await fillAndSign(
  //     {
  //       sender: userOpSender,
  //       callData: txnDataAA1,
  //       ...options,
  //     },
  //     userOpSigner,
  //     entryPoint,
  //     "nonce",
  //     true,
  //     nonceKey,
  //     0
  //   );
  
  //   // add validator module address to the signature
  //   const signatureWithModuleAddress = ethers.utils.defaultAbiCoder.encode(
  //     ["bytes", "address"],
  //     [userOp.signature, moduleAddress]
  //   );
  
  //   userOp.signature = signatureWithModuleAddress;
  //   return userOp;
  // }
  
  // export async function makeEcdsaModuleUserOpWithPaymaster(
  //   functionName: string,
  //   functionParams: any,
  //   userOpSender: string,
  //   userOpSigner: Signer,
  //   entryPoint: EntryPoint,
  //   moduleAddress: string,
  //   paymaster: Contract,
  //   verifiedSigner: Wallet | SignerWithAddress,
  //   validUntil: number,
  //   validAfter: number,
  //   options?: {
  //     preVerificationGas?: number;
  //   },
  //   nonceKey = 0
  // ): Promise<UserOperation> {
  //   const SmartAccount = await ethers.getContractFactory("SmartAccount");
  
  //   const txnDataAA1 = SmartAccount.interface.encodeFunctionData(
  //     functionName,
  //     functionParams
  //   );
  
  //   const userOp = await fillAndSign(
  //     {
  //       sender: userOpSender,
  //       callData: txnDataAA1,
  //       ...options,
  //     },
  //     userOpSigner,
  //     entryPoint,
  //     "nonce",
  //     true,
  //     nonceKey,
  //     0
  //   );
  
  //   const hash = await paymaster.getHash(
  //     userOp,
  //     verifiedSigner.address,
  //     validUntil,
  //     validAfter
  //   );
  //   const paymasterSig = await verifiedSigner.signMessage(arrayify(hash));
  //   const userOpWithPaymasterData = await fillAndSign(
  //     {
  //       // eslint-disable-next-line node/no-unsupported-features/es-syntax
  //       ...userOp,
  //       paymasterAndData: hexConcat([
  //         paymaster.address,
  //         ethers.utils.defaultAbiCoder.encode(
  //           ["address", "uint48", "uint48", "bytes"],
  //           [verifiedSigner.address, validUntil, validAfter, paymasterSig]
  //         ),
  //       ]),
  //     },
  //     userOpSigner,
  //     entryPoint,
  //     "nonce",
  //     true,
  //     nonceKey,
  //     0
  //   );
  
  //   // add validator module address to the signature
  //   const signatureWithModuleAddress = ethers.utils.defaultAbiCoder.encode(
  //     ["bytes", "address"],
  //     [userOpWithPaymasterData.signature, moduleAddress]
  //   );
  
  //   userOpWithPaymasterData.signature = signatureWithModuleAddress;
  
  //   return userOpWithPaymasterData;
  // }
  
  // export async function makeSARegistryModuleUserOp(
  //   functionName: string,
  //   functionParams: any,
  //   userOpSender: string,
  //   userOpSigner: Signer,
  //   entryPoint: EntryPoint,
  //   saRegistryModuleAddress: string,
  //   ecdsaModuleAddress: string,
  //   options?: {
  //     preVerificationGas?: number;
  //   },
  //   nonceKey = 0
  // ): Promise<UserOperation> {
  //   const SmartAccount = await ethers.getContractFactory("SmartAccount");
  
  //   const txnDataAA1 = SmartAccount.interface.encodeFunctionData(
  //     functionName,
  //     functionParams
  //   );
  
  //   const userOp = await fillAndSign(
  //     {
  //       sender: userOpSender,
  //       callData: txnDataAA1,
  //       ...options,
  //     },
  //     userOpSigner,
  //     entryPoint,
  //     "nonce",
  //     true,
  //     nonceKey,
  //     0
  //   );
  
  //   const signatureForSAOwnershipRegistry = ethers.utils.defaultAbiCoder.encode(
  //     ["bytes", "address"],
  //     [userOp.signature, ecdsaModuleAddress]
  //   );
  
  //   const signatureForECDSAOwnershipRegistry =
  //     ethers.utils.defaultAbiCoder.encode(
  //       ["bytes", "address"],
  //       [signatureForSAOwnershipRegistry, saRegistryModuleAddress]
  //     );
  
  //   userOp.signature = signatureForECDSAOwnershipRegistry;
  //   return userOp;
  // }
  
  // export async function makeMultichainEcdsaModuleUserOp(
  //   functionName: string,
  //   functionParams: any,
  //   userOpSender: string,
  //   userOpSigner: Signer,
  //   entryPoint: EntryPoint,
  //   moduleAddress: string,
  //   leaves: string[],
  //   options?: {
  //     preVerificationGas?: number;
  //   },
  //   validUntil = 0,
  //   validAfter = 0,
  //   nonceKey = 0
  // ): Promise<UserOperation> {
  //   const SmartAccount = await ethers.getContractFactory("SmartAccount");
  
  //   const txnDataAA1 = SmartAccount.interface.encodeFunctionData(
  //     functionName,
  //     functionParams
  //   );
  
  //   const userOp = await fillAndSign(
  //     {
  //       sender: userOpSender,
  //       callData: txnDataAA1,
  //       ...options,
  //     },
  //     userOpSigner,
  //     entryPoint,
  //     "nonce",
  //     true,
  //     nonceKey,
  //     0
  //   );
  
  //   const leafOfThisUserOp = hexConcat([
  //     hexZeroPad(ethers.utils.hexlify(validUntil), 6),
  //     hexZeroPad(ethers.utils.hexlify(validAfter), 6),
  //     hexZeroPad(await entryPoint.getUserOpHash(userOp), 32),
  //   ]);
  
  //   leaves.push(leafOfThisUserOp);
  //   leaves = leaves.map((x) => ethers.utils.keccak256(x));
  
  //   const chainMerkleTree = new MerkleTree(leaves, keccak256, {
  //     sortPairs: true,
  //   });
  
  //   // user only signs once
  //   const multichainSignature = await userOpSigner.signMessage(
  //     ethers.utils.arrayify(chainMerkleTree.getHexRoot())
  //   );
  
  //   // but still required to pad the signature with the required data (unsigned) for every chain
  //   // this is done by dapp automatically
  //   const merkleProof = chainMerkleTree.getHexProof(leaves[leaves.length - 1]);
  //   const moduleSignature = defaultAbiCoder.encode(
  //     ["uint48", "uint48", "bytes32", "bytes32[]", "bytes"],
  //     [
  //       validUntil,
  //       validAfter,
  //       chainMerkleTree.getHexRoot(),
  //       merkleProof,
  //       multichainSignature,
  //     ]
  //   );
  
  //   // add validator module address to the signature
  //   const signatureWithModuleAddress = defaultAbiCoder.encode(
  //     ["bytes", "address"],
  //     [moduleSignature, moduleAddress]
  //   );
  
  //   // =================== put signature into userOp and execute ===================
  //   userOp.signature = signatureWithModuleAddress;
  
  //   return userOp;
  // }
  
  // export function serializeUserOp(op: UserOperation) {
  //   return {
  //     sender: op.sender,
  //     nonce: hexValue(op.nonce),
  //     initCode: op.initCode,
  //     callData: op.callData,
  //     callGasLimit: hexValue(op.callGasLimit),
  //     verificationGasLimit: hexValue(op.verificationGasLimit),
  //     preVerificationGas: hexValue(op.preVerificationGas),
  //     maxFeePerGas: hexValue(op.maxFeePerGas),
  //     maxPriorityFeePerGas: hexValue(op.maxPriorityFeePerGas),
  //     paymasterAndData: op.paymasterAndData,
  //     signature: op.signature,
  //   };
  // }
  