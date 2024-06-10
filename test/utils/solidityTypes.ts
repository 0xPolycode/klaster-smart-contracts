// define the same export types as used by export typechain/ethers
import { BigNumberish, BytesLike } from "ethers";

export type address = string;
export type uint256 = BigNumberish;
export type uint = BigNumberish;
export type uint64 = BigNumberish;
export type bytes = BytesLike;
export type bytes32 = BytesLike;
