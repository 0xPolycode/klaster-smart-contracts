import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { getSmartAccountImplementation } from "../test/utils/setupHelper";

const deploy: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
    const { deployments, getNamedAccounts } = hre;
    const { deploy } = deployments;
    const { deployer } = await getNamedAccounts();

    const smartAccountImplementation = await getSmartAccountImplementation();
    await deploy("SmartAccountFactory", {
        from: deployer,
        args: [smartAccountImplementation.target, deployer],
        log: true,
        deterministicDeployment: true,
        autoMine: true,
    });
};

deploy.tags = ["smart-account-factory"];
export default deploy;
