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
        version: "0.8.23",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
    ],
    overrides: {
      "contracts/deployer/DeterministicDeployFactory.sol": {
        version: "0.8.19",
      },
      "contracts/modules/KlasterSafeModule.sol": {
        version: "0.8.23",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200
          }
        }
      }
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
    sepolia: {
      url: "https://ultra-greatest-vineyard.ethereum-sepolia.quiknode.pro/8e37f80f63e2ddb56463719c8ae0fbdedb026f5a",
      ledgerAccounts: ["0x5B2E0b8403d0653994A2024DB133FF92aCa05e2E"],
    },
    arbitrumsepolia: {
      url: "https://young-ancient-frost.arbitrum-sepolia.quiknode.pro/a43c4c762a12440a6ce414e99bb8fc46166a5ce6/",
      ledgerAccounts: ["0x5B2E0b8403d0653994A2024DB133FF92aCa05e2E"],
    },
    optimismsepolia: {
      url: "https://alpha-bitter-shadow.optimism-sepolia.quiknode.pro/48c3a410694655fe21e903d21c7f75fec0d2f605/",
      ledgerAccounts: ["0x5B2E0b8403d0653994A2024DB133FF92aCa05e2E"],
    },
    basesepolia: {
      url: "https://wiser-tame-hexagon.base-sepolia.quiknode.pro/dcdad68e2c7491110f6eceafc041c7ff980de6e4",
      ledgerAccounts: ["0x5B2E0b8403d0653994A2024DB133FF92aCa05e2E"],
    },
    kamenjak: {
      url: "https://rpc-kamenjak-vseathpd2d.t.conduit.xyz",
      ledgerAccounts: ["0x5B2E0b8403d0653994A2024DB133FF92aCa05e2E"],
    },
    hardhat: {
      allowUnlimitedContractSize: true,
    },
  },
  etherscan: {

  }
};

export default config;
