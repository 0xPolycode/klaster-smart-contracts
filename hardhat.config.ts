import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "hardhat-deploy";
import "hardhat-dependency-compiler";
import "@typechain/hardhat";
import "@nomicfoundation/hardhat-ethers";
import "@nomicfoundation/hardhat-chai-matchers";

const config: HardhatUserConfig = {
  solidity: {
    compilers: [
      {
        version: "0.8.17",
      }
    ],
  },
  dependencyCompiler: {
    paths: [
      '@account-abstraction/contracts/core/EntryPoint.sol'
    ],
  },
  networks: {
    hardhat: {
      // accounts: {
      //   accountsBalance: "10000000000000000000000000",
      //   //   mnemonic: MNEMONIC,
      // },
      allowUnlimitedContractSize: true,
      // chainId: 31337,
    }
  },
  namedAccounts: {
		deployer: 0
	}
};

export default config;
