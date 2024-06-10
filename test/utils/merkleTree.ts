import { ethers } from "ethers";
import { StandardMerkleTree } from "@openzeppelin/merkle-tree";
import { KlasterUserOp, UserOp } from "../types";

export function getMerkleTree(
  klasterUserOps: KlasterUserOp[]
): StandardMerkleTree<string[]> {
  return StandardMerkleTree.of(
    klasterUserOps.map((it) => {
      return klasterUserOpToMerkleLeaf(it);
    }),
    ["bytes32", "uint256", "uint256", "uint256"],
  );
}

export function klasterUserOpToMerkleLeaf(
  klasterUserOp: KlasterUserOp
): string[] {
  return [
    get4337UserOpHash(klasterUserOp.userOp),
    klasterUserOp.lowerBoundTimestamp,
    klasterUserOp.upperBoundTimestamp,
    klasterUserOp.chainId,
  ];
}

export function getKlasterUserOpHash(klasterUserOp: KlasterUserOp): string {
  return ethers.keccak256(
    ethers.keccak256(encodeKlasterUserOp(klasterUserOp)),
  );
}

function encodeKlasterUserOp(klasterUserOp: KlasterUserOp): string {
  return ethers.AbiCoder.defaultAbiCoder()
    .encode(
      ["bytes32", "uint256", "uint256", "uint256"],
      klasterUserOpToMerkleLeaf(klasterUserOp),
    )
    .toString();
}

function get4337UserOpHash(userOp: UserOp): string {
  let packedUserOp = ethers.AbiCoder.defaultAbiCoder().encode(
    [
      "address",
      "uint256",
      "bytes32",
      "bytes32",
      "uint256",
      "uint256",
      "uint256",
      "uint256",
      "uint256",
      "bytes32",
    ],
    [
      userOp.sender,
      userOp.nonce,
      ethers.keccak256(userOp.initCode),
      ethers.keccak256(userOp.callData),
      userOp.callGasLimit,
      userOp.verificationGasLimit,
      userOp.preVerificationGas,
      userOp.maxFeePerGas,
      userOp.maxPriorityFeePerGas,
      ethers.keccak256(userOp.paymasterAndData),
    ],
  );
  return ethers.keccak256(packedUserOp).toString();
}
