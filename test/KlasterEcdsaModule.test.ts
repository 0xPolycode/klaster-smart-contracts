import { expect } from "chai";
import hre, { deployments, ethers, getChainId } from "hardhat";
import { hashMessage } from "ethers";
import {
  decodePaymasterData,
  decodeSig,
  fillAndSign,
  fillAndSignMany,
  parseValidationData,
  updatePaymasterData,
  updateSignature,
} from "./utils/userOp";
import {
  getEntryPoint,
  getSmartAccountFactory,
  deployContract,
  getKlasterModule,
  getSmartAccountImplementation,
  getKlasterPaymaster,
  getKlasterAccount,
  computeWalletAddress,
} from "./utils/setupHelper";
import { HashZero, ONE_ETH } from "./utils/constants";
import { AddressZero } from "@ethersproject/constants";
import { getUnixTimestamp } from "./utils/timeUtils";

describe("KlasterEcdsaModule: ", async () => {
  const smartAccountDeploymentIndex = 0;
  const SIG_VALIDATION_SUCCESS = 0; // sigFailed = false (erc4337 validation data)
  const SIG_VALIDATION_FAILED = 1; // sigFailed = true (erc4337 validation data)
  const EIP1271_INVALID_SIGNATURE = "0xffffffff";
  const EIP1271_MAGIC_VALUE = "0x1626ba7e";
  const NOW = getUnixTimestamp(0);
  const FAR_FUTURE = getUnixTimestamp(1000);
  const ZERO_VALUE = 0n;
  const EMPTY_CALLDATA = "0x";

  async function getSigners() {
    const [deployer, smartAccountOwner, alice, bob, charlie] =
      await hre.ethers.getSigners();
    return {
      deployer,
      smartAccountOwner,
      alice,
      bob,
      charlie,
    };
  }

  async function setupTests() {
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
    const randomContract = await deployContract(deployer, randomContractCode);

    return {
      entryPoint,
      scaImpl,
      scaFactory,
      klasterModule,
      klasterPaymaster,
      randomContract,
    };
  }

  describe("initForSmartAccount: ", async () => {
    it("Reverts when trying to set Smart Contract as owner of the Smart Account via deployment userOp", async () => {
      // DISCLAIMER:
      // In theory it is still possible to set smart contractd address as owner of a SA via initForSmartAccount,
      // if factory has been called directly, not via userOp.
      // In Biconomy SDK will will perform an additional off-chain verification that address provided as owner is EOA
      // Also the initForSmartAccount method's parameter is now called `eoaOwner` instead of just `owner` to
      // highlight it should be EOA.
      // Assuming this, the explicit check for eoaOwner is not smart contract can be removed because of this
      // issue: https://github.com/eth-infinitism/bundler/issues/137

      // const { scaFactory, klasterModule, randomContract, entryPoint } =
      //   await deployContracts();

      const {
        entryPoint,
        scaFactory,
        klasterModule,
        klasterPaymaster,
        randomContract,
      } = await setupTests();
      const { smartAccountOwner } = await getSigners();
      const chainId = await getChainId();

      const klasterModuleSetupData = klasterModule.interface.encodeFunctionData(
        "initForSmartAccount",
        [randomContract.target],
      );

      const expectedSmartAccountAddress =
        await scaFactory.getAddressForCounterFactualAccount(
          klasterModule.target,
          klasterModuleSetupData,
          smartAccountDeploymentIndex,
        );

      const deploymentUserOp = await fillAndSign(
        await randomContract.getAddress(),
        smartAccountDeploymentIndex,
        AddressZero,
        ZERO_VALUE,
        EMPTY_CALLDATA,
        true,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
        {
          verificationGasLimit: "1000000",
        },
      );

      await expect(
        klasterPaymaster.handleOps([deploymentUserOp], {
          value: ONE_ETH,
        }),
      )
        .to.be.revertedWithCustomError(entryPoint, "FailedOp")
        .withArgs(0, "AA24 signature error");

      await expect(
        klasterModule.getOwner(expectedSmartAccountAddress),
      ).to.be.revertedWithCustomError(
        klasterModule,
        "NoOwnerRegisteredForSmartAccount",
      );
    });

    it("Reverts when calling again after initialization", async () => {
      const { klasterModule, klasterPaymaster, entryPoint } =
        await setupTests();
      const { smartAccountOwner, bob } = await getSigners();
      const chainId = await getChainId();

      // first create smart account manually
      const smartAccountIndex = 0;
      await getKlasterAccount(smartAccountOwner.address, smartAccountIndex);

      // then try to recreate smart account (should fail)
      const userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        await klasterModule.getAddress(),
        ZERO_VALUE,
        klasterModule.interface.encodeFunctionData("initForSmartAccount", [
          bob.address,
        ]),
        false,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
      );

      const tx = await klasterPaymaster.handleOps([userOp], {
        value: ONE_ETH,
      });
      await expect(tx).to.emit(entryPoint, "UserOperationRevertReason");
    });
  });

  describe("transferOwnership: ", async () => {
    it("Call transferOwnership() and it successfully changes owner", async () => {
      const smartAccountIndex = 0;
      const { smartAccountOwner, bob } = await getSigners();
      const { klasterModule, klasterPaymaster } = await setupTests();
      const chainId = await getChainId();

      // create account
      const klasterAccount = await getKlasterAccount(
        smartAccountOwner.address,
        0,
      );
      const previousOwner = await klasterModule.getOwner(klasterAccount);
      expect(previousOwner).to.be.equal(smartAccountOwner.address);

      // generate transferOwnership userOp
      const userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        await klasterModule.getAddress(),
        ZERO_VALUE,
        klasterModule.interface.encodeFunctionData("transferOwnership", [
          bob.address,
        ]),
        false,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
      );

      await klasterPaymaster.handleOps([userOp], {
        value: ONE_ETH,
      });
      expect(await klasterModule.getOwner(klasterAccount)).to.be.equal(
        bob.address,
      );
    });

    it("Reverts when trying to set Smart Contract Address as owner via transferOwnership() ", async () => {
      const smartAccountIndex = 0;
      const { smartAccountOwner } = await getSigners();
      const { klasterModule, entryPoint, randomContract, klasterPaymaster } =
        await setupTests();
      const chainId = await getChainId();

      // create account
      const klasterAccount = await getKlasterAccount(
        smartAccountOwner.address,
        smartAccountIndex,
      );
      const previousOwner = await klasterModule.getOwner(klasterAccount);
      expect(previousOwner).to.be.equal(smartAccountOwner.address);

      // generate transferOwnership userOp
      const userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        await klasterModule.getAddress(),
        ZERO_VALUE,
        klasterModule.interface.encodeFunctionData("transferOwnership", [
          randomContract.target,
        ]),
        false,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
      );

      const tx = await klasterPaymaster.handleOps([userOp], {
        value: ONE_ETH,
      });
      await expect(tx).to.emit(entryPoint, "UserOperationRevertReason");
      expect(await klasterModule.getOwner(klasterAccount)).to.be.equal(
        previousOwner,
      );
    });

    it("Reverts when trying to set address(0) as owner", async () => {
      const smartAccountIndex = 0;
      const { smartAccountOwner } = await getSigners();
      const { klasterModule, entryPoint, klasterPaymaster } =
        await setupTests();
      const chainId = await getChainId();

      // create account
      const klasterAccount = await getKlasterAccount(
        smartAccountOwner.address,
        smartAccountIndex,
      );
      const previousOwner = await klasterModule.getOwner(klasterAccount);
      expect(previousOwner).to.be.equal(smartAccountOwner.address);

      // generate transferOwnership userOp
      const userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        await klasterModule.getAddress(),
        ZERO_VALUE,
        klasterModule.interface.encodeFunctionData("transferOwnership", [
          AddressZero,
        ]),
        false,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
      );

      const tx = await klasterPaymaster.handleOps([userOp], {
        value: ONE_ETH,
      });
      await expect(tx).to.emit(entryPoint, "UserOperationRevertReason");
      expect(await klasterModule.getOwner(klasterAccount)).to.be.equal(
        previousOwner,
      );
    });
  });

  describe("renounceOwnership(): ", async () => {
    it("Should be able to renounce ownership and the new owner should be address(0)", async () => {
      const smartAccountIndex = 0;
      const { smartAccountOwner } = await getSigners();
      const { klasterModule, klasterPaymaster } = await setupTests();
      const chainId = await getChainId();

      // create account
      const klasterAccount = await getKlasterAccount(
        smartAccountOwner.address,
        smartAccountIndex,
      );
      const previousOwner = await klasterModule.getOwner(klasterAccount);
      expect(previousOwner).to.be.equal(smartAccountOwner.address);

      // generate transferOwnership userOp
      const userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        await klasterModule.getAddress(),
        ZERO_VALUE,
        klasterModule.interface.encodeFunctionData("renounceOwnership"),
        false,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
      );

      await klasterPaymaster.handleOps([userOp], {
        value: ONE_ETH,
      });
      await expect(
        klasterModule.getOwner(klasterAccount.target),
      ).to.be.revertedWithCustomError(
        klasterModule,
        "NoOwnerRegisteredForSmartAccount",
      );
    });
  });

  describe("validateUserOp(): ", async () => {
    it("Returns SIG_VALIDATION_SUCCESS for a valid UserOp and valid itxHash", async () => {
      const smartAccountIndex = 0;
      const { deployer, smartAccountOwner, bob } = await getSigners();
      const { klasterModule, klasterPaymaster } = await setupTests();
      const chainId = await getChainId();

      // create user account
      const smartAccount = await getKlasterAccount(
        smartAccountOwner.address,
        smartAccountIndex,
      );

      // fund user account with 1 ETH
      await deployer.sendTransaction({
        to: smartAccount.target,
        value: ONE_ETH,
      });
      expect(
        await deployer.provider.getBalance(smartAccount.target),
      ).to.be.equal(ONE_ETH);

      // generate userOp that moves 1 ETH from user account to bob
      const userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        bob.address,
        ONE_ETH,
        EMPTY_CALLDATA,
        false,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
      );

      // validate user op
      const validateUserOpResult = await klasterModule.validateUserOp(
        userOp,
        HashZero,
      );
      const validationData = parseValidationData(validateUserOpResult);
      expect(validationData.status).to.be.equal(SIG_VALIDATION_SUCCESS);
      expect(validationData.validAfter.toString()).to.be.equal(NOW);
      expect(validationData.validUntil.toString()).to.be.equal(FAR_FUTURE);

      // execute userOp
      const tx = await klasterPaymaster.handleOps([userOp], {
        value: ONE_ETH,
      });

      // check the balance changes
      await expect(tx).to.changeEtherBalance(smartAccount.target, -ONE_ETH);
      await expect(tx).to.changeEtherBalance(bob.address, ONE_ETH);
    });

    // Pass in valid userOp with invalid userOpHash
    it("Returns SIG_VALIDATION_FAILED when invalid itxHash is passed in userOp signature", async () => {
      const smartAccountIndex = 0;
      const chainId = await getChainId();
      const { smartAccountOwner } = await getSigners();
      const { klasterModule } = await setupTests();

      // create user account
      await getKlasterAccount(smartAccountOwner.address, smartAccountIndex);

      // generate userOp
      let userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        AddressZero,
        ZERO_VALUE,
        EMPTY_CALLDATA,
        false,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
      );

      userOp = await updateSignature(userOp, {
        itxHash: HashZero, // set invalid itx hash
      });

      // validate user op
      const validateUserOpResult = await klasterModule.validateUserOp(
        userOp,
        HashZero,
      );
      const validationData = parseValidationData(validateUserOpResult);
      expect(validationData.status).to.be.equal(SIG_VALIDATION_FAILED);
    });

    // Pass in valid userOp with invalid chain Id
    it("Returns SIG_VALIDATION_FAILED when invalid chainId is passed in userOpHash", async () => {
      const smartAccountIndex = 0;
      const { smartAccountOwner } = await getSigners();
      const { klasterModule } = await setupTests();

      // create user account
      await getKlasterAccount(smartAccountOwner.address, smartAccountIndex);

      // generate userOp with wrong chainId
      const userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        AddressZero,
        ZERO_VALUE,
        EMPTY_CALLDATA,
        false,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        "666", // pass the wrong chain id!
      );

      // validate user op
      const validateUserOpResult = await klasterModule.validateUserOp(
        userOp,
        HashZero,
      );
      const validationData = parseValidationData(validateUserOpResult);
      expect(validationData.status).to.be.equal(SIG_VALIDATION_FAILED);
    });

    it("Returns SIG_VALIDATION_FAILED when userOp is signed by an invalid owner", async () => {
      const smartAccountIndex = 0;
      const chainId = await getChainId();
      const { smartAccountOwner, bob } = await getSigners();
      const { klasterModule } = await setupTests();

      // create user account
      await getKlasterAccount(smartAccountOwner.address, smartAccountIndex);

      // generate userOp
      let userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        AddressZero,
        ZERO_VALUE,
        EMPTY_CALLDATA,
        false,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
      );

      const decodedSig = await decodeSig(userOp);
      userOp = await updateSignature(userOp, {
        signature: await bob.signMessage(ethers.getBytes(decodedSig.itxHash)), // sign with bob wallet (bob NOT an account owner)
      });

      // validate user op
      const validateUserOpResult = await klasterModule.validateUserOp(
        userOp,
        HashZero,
      );
      const validationData = parseValidationData(validateUserOpResult);
      expect(validationData.status).to.be.equal(SIG_VALIDATION_FAILED);
    });

    it("Returns SIG_VALIDATION_FAILED when invalid merkle proof is submitted in the userOp signature", async () => {
      const smartAccountIndex = 0;
      const chainId = await getChainId();
      const { smartAccountOwner } = await getSigners();
      const { klasterModule } = await setupTests();

      // create user account
      await getKlasterAccount(smartAccountOwner.address, smartAccountIndex);

      // generate userOp
      let userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        AddressZero,
        ZERO_VALUE,
        EMPTY_CALLDATA,
        false,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
      );

      userOp = await updateSignature(userOp, {
        proof: [HashZero], // set invalid proof
      });

      // validate user op
      const validateUserOpResult = await klasterModule.validateUserOp(
        userOp,
        HashZero,
      );
      const validationData = parseValidationData(validateUserOpResult);
      expect(validationData.status).to.be.equal(SIG_VALIDATION_FAILED);
    });

    it("Returns SIG_VALIDATION_FAILED when invalid lower bound timestamp is submitted in the userOp signature", async () => {
      const smartAccountIndex = 0;
      const chainId = await getChainId();
      const { smartAccountOwner } = await getSigners();
      const { klasterModule } = await setupTests();

      // create user account
      await getKlasterAccount(smartAccountOwner.address, smartAccountIndex);

      // generate userOp
      let userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        AddressZero,
        ZERO_VALUE,
        EMPTY_CALLDATA,
        false,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
      );

      userOp = await updateSignature(userOp, {
        lowerBoundTimestamp: "0", // set invalid lowebound timestamp (different from the one signed)
      });

      // validate user op
      const validateUserOpResult = await klasterModule.validateUserOp(
        userOp,
        HashZero,
      );
      const validationData = parseValidationData(validateUserOpResult);
      expect(validationData.status).to.be.equal(SIG_VALIDATION_FAILED);
    });

    it("Returns SIG_VALIDATION_FAILED when invalid upper bound timestamp is submitted in the userOp signature", async () => {
      const smartAccountIndex = 0;
      const chainId = await getChainId();
      const { smartAccountOwner } = await getSigners();
      const { klasterModule } = await setupTests();

      // create user account
      await getKlasterAccount(smartAccountOwner.address, smartAccountIndex);

      // generate userOp
      let userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        AddressZero,
        ZERO_VALUE,
        EMPTY_CALLDATA,
        false,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
      );

      userOp = await updateSignature(userOp, {
        upperBoundTimestamp: "0", // set invalid upperbound timestamp (different from the one signed)
      });

      // validate user op
      const validateUserOpResult = await klasterModule.validateUserOp(
        userOp,
        HashZero,
      );
      const validationData = parseValidationData(validateUserOpResult);
      expect(validationData.status).to.be.equal(SIG_VALIDATION_FAILED);
    });

    it("Returns SIG_VALIDATION_FAILED when invalid paymaster maxGasLimit is submitted in the userOp signature", async () => {
      const smartAccountIndex = 0;
      const chainId = await getChainId();
      const { smartAccountOwner } = await getSigners();
      const { klasterModule } = await setupTests();

      // create user account
      await getKlasterAccount(smartAccountOwner.address, smartAccountIndex);

      // generate userOp
      let userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        AddressZero,
        ZERO_VALUE,
        EMPTY_CALLDATA,
        false,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
      );

      const paymasterData = await decodePaymasterData(userOp);
      userOp = await updatePaymasterData(userOp, {
        maxGasLimit: (Number(paymasterData.maxGasLimit) + 1).toString(), // set invalid max gas limit (different from the one signed)
      });

      // validate user op
      const validateUserOpResult = await klasterModule.validateUserOp(
        userOp,
        HashZero,
      );
      const validationData = parseValidationData(validateUserOpResult);
      expect(validationData.status).to.be.equal(SIG_VALIDATION_FAILED);
    });

    it("Returns SIG_VALIDATION_FAILED when invalid paymaster nodePremium is submitted in the userOp signature", async () => {
      const smartAccountIndex = 0;
      const chainId = await getChainId();
      const { smartAccountOwner } = await getSigners();
      const { klasterModule } = await setupTests();

      // create user account
      await getKlasterAccount(smartAccountOwner.address, smartAccountIndex);

      // generate userOp
      let userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        AddressZero,
        ZERO_VALUE,
        EMPTY_CALLDATA,
        false,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
      );

      const paymasterData = await decodePaymasterData(userOp);
      userOp = await updatePaymasterData(userOp, {
        nodePremium: (Number(paymasterData.nodePremium) + 1).toString(), // set invalid max gas limit (different from the one signed)
      });

      // validate user op
      const validateUserOpResult = await klasterModule.validateUserOp(
        userOp,
        HashZero,
      );
      const validationData = parseValidationData(validateUserOpResult);
      expect(validationData.status).to.be.equal(SIG_VALIDATION_FAILED);
    });

    it("reverts when userOp.sender is an Unregistered Smart Account", async () => {
      const smartAccountIndex = 0;
      const chainId = await getChainId();
      const { smartAccountOwner } = await getSigners();
      const { klasterModule, klasterPaymaster, entryPoint } =
        await setupTests();

      // create user account
      const smartAccount = await getKlasterAccount(
        smartAccountOwner.address,
        smartAccountIndex,
      );
      expect(await klasterModule.getOwner(smartAccount.target)).to.be.equal(
        smartAccountOwner.address,
      );

      // renounce ownership
      const renounceUserOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        await klasterModule.getAddress(),
        ZERO_VALUE,
        klasterModule.interface.encodeFunctionData("renounceOwnership"),
        false,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
      );
      await klasterPaymaster.handleOps([renounceUserOp], {
        value: ONE_ETH,
      });
      await expect(
        klasterModule.getOwner(smartAccount.target),
      ).to.be.revertedWithCustomError(
        klasterModule,
        "NoOwnerRegisteredForSmartAccount",
      );

      // create empty operation to be executed from a smart account without an owner
      const emptyOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        AddressZero,
        ZERO_VALUE,
        EMPTY_CALLDATA,
        false,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
      );

      // validate the emptyOp will be rejected becuase the smart account is now ownerless
      await expect(
        klasterModule.validateUserOp(emptyOp, HashZero),
      ).to.be.revertedWithCustomError(
        klasterModule,
        "NoOwnerRegisteredForSmartAccount",
      );
      await expect(
        klasterPaymaster.handleOps([emptyOp], {
          value: ONE_ETH,
        }),
      ).to.be.revertedWithCustomError(entryPoint, "FailedOp");
    });

    it("Reverts when length of user.signature is less than 65 ", async () => {
      const smartAccountIndex = 0;
      const chainId = await getChainId();
      const { smartAccountOwner } = await getSigners();
      const { klasterModule, klasterPaymaster, entryPoint } =
        await setupTests();

      await getKlasterAccount(smartAccountOwner.address, smartAccountIndex);

      let userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        AddressZero,
        ZERO_VALUE,
        EMPTY_CALLDATA,
        true,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
      );

      let shortSig = "0xffffffff"; // < 65 bytes
      userOp = await updateSignature(userOp, {
        signature: shortSig,
      });

      await expect(
        klasterModule.validateUserOp(userOp, HashZero),
      ).to.be.revertedWithCustomError(klasterModule, "WrongSignatureLength");

      await expect(
        klasterPaymaster.handleOps([userOp], {
          value: ONE_ETH,
        }),
      ).to.be.revertedWithCustomError(entryPoint, "FailedOp");
    });
  });

  describe("isValidSignatureForAddress() & isValidSignature(): ", async () => {
    it("Returns EIP1271_MAGIC_VALUE for valid signature signed by Smart Account Owner", async () => {
      const smartAccountIndex = 0;
      const { smartAccountOwner } = await getSigners();
      const { klasterModule } = await setupTests();

      const smartAccount = await getKlasterAccount(
        smartAccountOwner.address,
        smartAccountIndex,
      );

      const messageToSign = "SCW signed this message";
      const dataHash = hashMessage(messageToSign);
      const signature = await smartAccountOwner.signMessage(messageToSign);

      /**
       * check valid signatures
       */
      expect(
        await smartAccount
          .connect(smartAccountOwner)
          .isValidSignature(
            dataHash,
            ethers.AbiCoder.defaultAbiCoder().encode(
              ["bytes", "address"],
              [signature, klasterModule.target],
            ),
          ),
      ).to.equal(EIP1271_MAGIC_VALUE);

      expect(
        await klasterModule.isValidSignatureForAddress(
          dataHash,
          signature,
          await smartAccount.getAddress(),
        ),
      ).to.equal(EIP1271_MAGIC_VALUE);
    });

    it("Reverts when Unregistered Smart Account calls isValidSignature()", async () => {
      const { smartAccountOwner } = await getSigners();
      const { klasterModule, randomContract } = await setupTests();

      const messageToSign = "SCW signed this message";
      const dataHash = hashMessage(messageToSign);
      const signature = await smartAccountOwner.signMessage(messageToSign);

      const unregisteredSmartAccount = await randomContract.getAddress();

      // set msg.sender to be unregisteredSmartAccount
      await expect(
        klasterModule.isValidSignatureForAddress(
          dataHash,
          signature,
          unregisteredSmartAccount,
        ),
      ).to.be.revertedWithCustomError(
        klasterModule,
        "NoOwnerRegisteredForSmartAccount",
      );

      await expect(
        klasterModule
          .connect(smartAccountOwner)
          .isValidSignature(
            dataHash,
            ethers.AbiCoder.defaultAbiCoder().encode(
              ["bytes", "address"],
              [signature, klasterModule.target],
            ),
          ),
      ).to.be.revertedWithCustomError(
        klasterModule,
        "NoOwnerRegisteredForSmartAccount",
      );
    });

    it("Reverts when signature length is less than 65", async () => {
      const smartAccountIndex = 0;
      const { smartAccountOwner } = await getSigners();
      const { klasterModule } = await setupTests();

      const smartAccount = await getKlasterAccount(
        smartAccountOwner.address,
        smartAccountIndex,
      );

      const messageToSign = "SCW signed this message";
      const dataHash = hashMessage(messageToSign);
      const invalidSignature = "0xffffffff"; // < 65 bytes

      await expect(
        klasterModule.isValidSignatureForAddress(
          dataHash,
          invalidSignature,
          await smartAccount.getAddress(),
        ),
      ).to.be.revertedWithCustomError(klasterModule, "WrongSignatureLength");

      await expect(
        smartAccount
          .connect(smartAccountOwner)
          .isValidSignature(
            dataHash,
            ethers.AbiCoder.defaultAbiCoder().encode(
              ["bytes", "address"],
              [invalidSignature, klasterModule.target],
            ),
          ),
      ).to.be.revertedWithCustomError(klasterModule, "WrongSignatureLength");
    });

    it("Returns 0xffffffff for signatures not signed by Smart Account Owners ", async () => {
      const smartAccountIndex = 0;
      const { smartAccountOwner } = await getSigners();
      const { klasterModule } = await setupTests();

      const smartAccount = await getKlasterAccount(
        smartAccountOwner.address,
        smartAccountIndex,
      );

      const messageToSign = "SCW signed this message";
      const signature = await smartAccountOwner.signMessage(messageToSign);

      /**
       * check invalid signatures
       */
      const unsignedDataHash = hashMessage("unsigned data");
      expect(
        await smartAccount
          .connect(smartAccountOwner)
          .isValidSignature(
            unsignedDataHash,
            ethers.AbiCoder.defaultAbiCoder().encode(
              ["bytes", "address"],
              [signature, klasterModule.target],
            ),
          ),
      ).to.equal(EIP1271_INVALID_SIGNATURE);

      expect(
        await klasterModule.isValidSignatureForAddress(
          unsignedDataHash,
          signature,
          await smartAccount.getAddress(),
        ),
      ).to.equal(EIP1271_INVALID_SIGNATURE);
    });
  });

  describe("complex userOp tree", async () => {
    it(`will successfully execute an iTx bundle of three userOps:
          - userOp1: transfer 1 ETH to alice (+ lazy init smart account wallet)
          - userOp2: transfer 1 ETH to charlie
          - userOp3: transfer 1 ETH to bob
    `, async () => {
      const smartAccountIndex = 0;
      const chainId = await getChainId();
      const { deployer, smartAccountOwner, alice, bob, charlie } =
        await getSigners();
      const { klasterPaymaster } = await setupTests();

      // precompute user account address
      const smartAccount = await computeWalletAddress(
        smartAccountOwner.address,
        smartAccountIndex,
      );

      // fund user account with 3 ETH
      await deployer.sendTransaction({
        to: smartAccount,
        value: 3n * ONE_ETH,
      });
      expect(await deployer.provider.getBalance(smartAccount)).to.be.equal(
        3n * ONE_ETH,
      );

      // generate three user ops, 1 eth -> alice , 1 eth -> charlie, 1 eth -> bob
      const userOps = await fillAndSignMany(
        smartAccountOwner.address,
        smartAccountIndex,
        [alice.address, charlie.address, bob.address],
        [ONE_ETH, ONE_ETH, ONE_ETH],
        [EMPTY_CALLDATA, EMPTY_CALLDATA, EMPTY_CALLDATA],
        [true, false, false], // lazy create smart contract account as a part of first userOp
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
        [0, 1, 2], // different nonce keys to make userOps independent (can be executed in parallel) (see 2D nonces)
      );

      // batch execute userOps
      const tx = await klasterPaymaster.handleOps(userOps, {
        value: ONE_ETH,
      });

      // check the balance changes
      await expect(tx).to.changeEtherBalance(smartAccount, -3n * ONE_ETH);
      await expect(tx).to.changeEtherBalance(alice.address, ONE_ETH);
      await expect(tx).to.changeEtherBalance(bob.address, ONE_ETH);
      await expect(tx).to.changeEtherBalance(charlie.address, ONE_ETH);
    });
  });
});
