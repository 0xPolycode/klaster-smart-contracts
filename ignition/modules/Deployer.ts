import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("Deployer", (m) => {
  const deployer = m.contract("DeterministicDeployFactory", []);
  return { deployer };
});
