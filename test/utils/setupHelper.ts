import hre, { deployments } from "hardhat";
import { Wallet, Contract, Signer } from "ethers";
import {
  EntryPoint,
  KlasterEcdsaModule,
  KlasterPaymaster,
  SmartAccount,
} from "../../typechain-types";
import { SmartAccountFactory } from "../../typechain-types";
const solc = require("solc");

export const getEntryPoint = async () => {
  const EntryPointDeployment = await deployments.get("EntryPoint");
  const EntryPoint = await hre.ethers.getContractFactory("EntryPoint");
  return EntryPoint.attach(EntryPointDeployment.address) as EntryPoint;
};

export const getSmartAccountImplementation = async () => {
  const SmartAccountImplDeployment = await deployments.get("SmartAccount");
  const SmartAccountImpl = await hre.ethers.getContractFactory("SmartAccount");
  return SmartAccountImpl.attach(
    SmartAccountImplDeployment.address,
  ) as SmartAccount;
};

export const getSmartAccountFactory = async () => {
  const SAFactoryDeployment = await deployments.get("SmartAccountFactory");
  const SmartAccountFactory = await hre.ethers.getContractFactory(
    "SmartAccountFactory",
  );
  return SmartAccountFactory.attach(
    SAFactoryDeployment.address,
  ) as SmartAccountFactory;
};

export const getKlasterModule = async () => {
  const KlasterModuleDeployment = await deployments.get("KlasterEcdsaModule");
  const KlasterModule =
    await hre.ethers.getContractFactory("KlasterEcdsaModule");
  return KlasterModule.attach(
    KlasterModuleDeployment.address,
  ) as KlasterEcdsaModule;
};

export const getKlasterPaymaster = async () => {
  const KlasterPaymasterDeployment = await deployments.get("KlasterPaymaster");
  const KlasterPaymaster =
    await hre.ethers.getContractFactory("KlasterPaymaster");
  return KlasterPaymaster.attach(
    KlasterPaymasterDeployment.address,
  ) as KlasterPaymaster;
};

export const getKlasterAccount = async (owner: string, index: number = 0) => {
  const factory = await getSmartAccountFactory();
  const klasterModule = await getKlasterModule();
  const klasterModuleSetupData = klasterModule.interface.encodeFunctionData(
    "initForSmartAccount",
    [owner],
  );
  const expectedSmartAccountAddress =
    await factory.getAddressForCounterFactualAccount(
      klasterModule.target,
      klasterModuleSetupData,
      index,
    );
  await factory.deployCounterFactualAccount(
    klasterModule.target,
    klasterModuleSetupData,
    index,
  );
  return (await hre.ethers.getContractAt(
    "SmartAccount",
    expectedSmartAccountAddress,
  )) as SmartAccount;
};

export const compile = async (
  source: string,
  settingsOverrides?: { evmVersion?: string },
) => {
  const input = JSON.stringify({
    language: "Solidity",
    settings: {
      outputSelection: {
        "*": {
          "*": ["abi", "evm.bytecode"],
        },
      },
      ...settingsOverrides,
    },
    sources: {
      "tmp.sol": {
        content: source,
      },
    },
  });
  const solcData = await solc.compile(input);
  const output = JSON.parse(solcData);
  if (!output.contracts) {
    console.log(output);
    throw Error("Could not compile contract");
  }
  const fileOutput = output.contracts["tmp.sol"];
  const contractOutput = fileOutput[Object.keys(fileOutput)[0]];
  const abi = contractOutput.abi;
  const data = "0x" + contractOutput.evm.bytecode.object;
  return {
    data: data,
    interface: abi,
  };
};

export const deployContract = async (
  deployer: Wallet | Signer,
  source: string,
  settingsOverrides?: { evmVersion?: string },
): Promise<Contract> => {
  const output = await compile(source, settingsOverrides);
  const transaction = await deployer.sendTransaction({
    data: output.data,
    gasLimit: 6000000,
  });
  const receipt = await transaction.wait();
  return new Contract(receipt!.contractAddress!, output.interface, deployer);
};

export const computeWalletAddress = async (
  smartAccountOwner: string,
  smartAccountIndex: number,
): Promise<string> => {
  const scaFactory = await getSmartAccountFactory();
  const klasterModule = await getKlasterModule();
  return scaFactory.getAddressForCounterFactualAccount(
    klasterModule.target,
    klasterModule.interface.encodeFunctionData("initForSmartAccount", [
      smartAccountOwner,
    ]),
    smartAccountIndex,
  );
};
