import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { getEntryPoint } from "../test/utils/setupHelper";

const deploy: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
    const { deployments, getNamedAccounts } = hre;
    const { deploy } = deployments;
    const { deployer } = await getNamedAccounts();

    const entryPoint = await getEntryPoint();

    await deploy("KlasterPaymaster", {
        from: deployer,
        args: [entryPoint.target],
        log: true,
        deterministicDeployment: true,
        autoMine: true,
    });
};

deploy.tags = ["klaster-paymaster"];
export default deploy;
