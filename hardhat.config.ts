import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "hardhat-deploy";
import "hardhat-dependency-compiler";
import "@typechain/hardhat";
import "@nomicfoundation/hardhat-ethers";
import "@nomicfoundation/hardhat-chai-matchers";
import "@nomicfoundation/hardhat-ledger";

const config: HardhatUserConfig = {
  solidity: {
    compilers: [
      {
        version: "0.8.17",
        settings: {
          optimizer: {
            enabled: true,
            runs: 800,
          },
        },
      },
      {
        version: "0.8.24",
        settings: {
          optimizer: {
            enabled: true,
            runs: 800,
          },
        },
      },
    ],
    overrides: {
      "contracts/deployer/DeterministicDeployFactory.sol": {
        version: "0.8.19",
      },
    },
  },
  dependencyCompiler: {
    paths: ["@account-abstraction/contracts/core/EntryPoint.sol"],
  },
  networks: {
    ethereum: {
      url: "https://eth.llamarpc.com",
      ledgerAccounts: [""],
    },
    arbitrum: {
      url: "https://arb1.arbitrum.io/rpc",
      ledgerAccounts: [""],
    },
    optimism: {
      url: "https://mainnet.optimism.io",
      ledgerAccounts: [""],
    },
    polygon: {
      url: "https://polygon.rpc.blxrbdn.com",
      ledgerAccounts: [""],
    },
    base: {
      url: "https://base.llamarpc.com",
      ledgerAccounts: [""],
    },
    avax: {
      url: "https://api.avax.network/ext/bc/C/rpc",
      ledgerAccounts: [""],
    },
    bsc: {
      url: "https://binance.llamarpc.com",
      ledgerAccounts: [""],
    },
    scroll: {
      url: "https://rpc.scroll.io/",
      ledgerAccounts: [""],
    },
    hardhat: {
      allowUnlimitedContractSize: true,
    },
  },
  namedAccounts: {
    deployer: 0,
  },
};

export default config;
