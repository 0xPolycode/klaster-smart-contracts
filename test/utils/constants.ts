import { ethers } from "hardhat";
import { parseEther } from "ethers";
import { getUnixTimestamp } from "./timeUtils";

export const AddressZero = ethers.ZeroAddress;
export const HashZero = ethers.ZeroHash;
export const ONE_ETH = parseEther("1");
export const TWO_ETH = parseEther("2");
export const FIVE_ETH = parseEther("5");
export const NOW = getUnixTimestamp(0);
export const FAR_FUTURE = getUnixTimestamp(1000);
export const ZERO_VALUE = 0n;
export const EMPTY_CALLDATA = "0x";
export const SIG_VALIDATION_SUCCESS = 0; // sigFailed = false (erc4337 validation data)
export const SIG_VALIDATION_FAILED = 1; // sigFailed = true (erc4337 validation data)
export const EIP1271_INVALID_SIGNATURE = "0xffffffff";
export const EIP1271_MAGIC_VALUE = "0x1626ba7e";
export const MAX_GAS_LIMIT = 10_000_000;
