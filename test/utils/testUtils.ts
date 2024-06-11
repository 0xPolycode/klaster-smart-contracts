import hre, { deployments, ethers } from "hardhat";
import {
  deployContract,
  getEntryPoint,
  getKlasterModule,
  getKlasterPaymaster,
  getSmartAccountFactory,
  getSmartAccountImplementation,
} from "./setupHelper";
import * as fs from "fs";

export async function getSigners() {
  const [deployer, klasterNode, smartAccountOwner, alice, bob, charlie] =
    await hre.ethers.getSigners();
  return {
    deployer,
    klasterNode,
    smartAccountOwner,
    alice,
    bob,
    charlie,
  };
}

export async function setupTests() {
  await deployments.fixture();

  const [deployer] = await hre.ethers.getSigners();

  const entryPoint = await getEntryPoint();
  const scaImpl = await getSmartAccountImplementation();
  const scaFactory = await getSmartAccountFactory();
  const klasterModule = await getKlasterModule();
  const klasterPaymaster = await getKlasterPaymaster();

  const randomContractCode = `
            contract random {
                function returnAddress() public view returns(address){
                    return address(this);
                }
            }
            `;
  const randomContract = await deployContract(
    deployer,
    "random",
    randomContractCode,
  );

  const maliciousPaymasterCode = fs
    .readFileSync(__dirname + "/../contracts/MaliciousPaymaster.test.sol")
    .toString();
  const maliciousPaymaster = await deployContract(
    deployer,
    "MaliciousPaymaster",
    maliciousPaymasterCode,
    ethers.AbiCoder.defaultAbiCoder().encode(["address"], [entryPoint.target]),
  );

  return {
    entryPoint,
    scaImpl,
    scaFactory,
    klasterModule,
    klasterPaymaster,
    randomContract,
    maliciousPaymaster,
  };
}
