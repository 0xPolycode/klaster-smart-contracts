import { expect } from "chai";
import { getChainId } from "hardhat";
import {
  ONE_ETH,
  EMPTY_CALLDATA,
  FAR_FUTURE,
  NOW,
  AddressZero,
  ZERO_VALUE,
} from "./utils/constants";
import { computeWalletAddress } from "./utils/setupHelper";
import { getSigners, setupTests } from "./utils/testUtils";
import { decodePaymasterData, fillAndSign } from "./utils/userOp";
import { ExecutionResult, SimulateValidationResult } from "./types";

/**
 * 1. Klaster node (backend) will charge the user upfront for the max_cost of userOp execution by charging:
 *    max_cost = userOp.maxFeePerGas * userOp.paymasterAndData.maxGasLimit
 *
 * 2. Klaster Node will execute userOp at some point between userOp.signature.lowerBoundTimestamp & upperBoundTimestamp
 *    Klaster node has to execute the given userOp through the KlasterPaymaster (this contract) as is defined by the userOp.paymasterAndData
 *
 * 3. At the moment of execution, KlasterPaymaster will receive callback from an EntryPoint, with the userOp execution details (total gas cost of userOp execution).
 *    KlasterPaymaster contract will use the received data to calculate the refund sent back to the userOp.sender wallet.
 *
 *    refund = max_cost - (userOp_actual_cost)*(1 + node_premium_percentage)
 *
 *    Refund can't be negative. In the case of max_cost not being enough to cover for tx execution,
 *    refund is 0 and the node has taken the damage of not estimating userOp cost correctly.
 *
 * NOTES:
 *    Node acts as a Paymaster to be able to use ERC4337 EntryPoint and execute UserOps.
 *    It stakes some msg.value in the KlasterPaymaster handleOps() call, and then immediately unstakes whatever is left
 *    after the handleOps() call was processed. As this is part of one tx, there's never staked balance left in the
 *    EntryPoint, which is important because the KlasterPaymaster will accept to process any tx by default (see _validatePaymasterUserOp() functiom),
 *    so the remaining staked balance could be drained to execute userOps for free.
 *
 *    Temporary staked balance is used to refund distribute refunds for userOps and the rest is returned back to the node
 *    within the same transaction.
 *
 *    Node has to send enough msg.value in handleOps call to cover for all refunds or the handleOps call will fail.
 */
describe("KlasterPaymaster: ", async () => {
  describe("handleOps(): ", async () => {
    it("will refund the userOp.sender correctly after executing given userOp", async () => {
      const smartAccountIndex = 0;
      const { deployer, klasterNode, smartAccountOwner, bob } =
        await getSigners();
      const { klasterPaymaster, entryPoint, scaFactory } = await setupTests();
      const chainId = await getChainId();

      // precompute smart account address (will be lazy deployed)
      const smartAccount = await computeWalletAddress(
        smartAccountOwner.address,
        smartAccountIndex,
      );

      // fund user account with 1 ETH
      await deployer.sendTransaction({
        to: smartAccount,
        value: ONE_ETH,
      });
      expect(await deployer.provider.getBalance(smartAccount)).to.be.equal(
        ONE_ETH,
      );

      // generate userOp that moves 1 ETH from user account to bob
      const userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        bob.address,
        ONE_ETH,
        EMPTY_CALLDATA,
        true,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
      );
      const userOpHash4337 = await entryPoint.getUserOpHash(userOp);

      // node executes userOp with 1 ETH msg.value (used for refunds)
      const nodeDeposit = ONE_ETH;
      const tx = await klasterPaymaster
        .connect(klasterNode)
        .handleOps([userOp], {
          value: nodeDeposit,
        });
      const receipt = await tx.wait();

      // verify the event was emitted for depositing 1 ETH to klaster paymaster
      await expect(tx)
        .to.emit(entryPoint, "Deposited")
        .withArgs(klasterPaymaster.target, nodeDeposit);

      // verify the user account was lazy deployed
      await expect(tx).to.emit(entryPoint, "AccountDeployed").withArgs(
        userOpHash4337, // erc4337 userOp hash
        smartAccount, // userOp.sender
        scaFactory.target, // factory address
        klasterPaymaster.target, // paymaster address
      );

      // verify the userOp was executed successfully
      await expect(tx).to.emit(entryPoint, "UserOperationEvent");
      await expect(tx).to.changeEtherBalance(bob, ONE_ETH); // bob balance increased

      // verify the userOp.sender received a refund from paymaster
      const paymasterAndData = await decodePaymasterData(userOp);
      const userOpCost = receipt!.gasPrice! * receipt!.gasUsed;
      const userPaid =
        BigInt(userOp.maxFeePerGas) * BigInt(paymasterAndData.maxGasLimit);
      expect(userPaid > userOpCost); // expect the user has overpaid for tx
      expect(
        await deployer.provider.getBalance(smartAccount),
      ).to.be.greaterThan(0); // and in that case expect some refund received after wallet was emptied (1 ETH sent to bob)

      // verify the node withdrew everything that was left from the 1 ETH msg.value deposit
      expect((await entryPoint.getDepositInfo(klasterPaymaster)).deposit).equal(
        0,
      );
    });

    it("will refund 0 to the userOp.sender if the user has underpaid for the tx", async () => {
      const smartAccountIndex = 0;
      const { deployer, klasterNode, smartAccountOwner, bob } =
        await getSigners();
      const { klasterPaymaster, entryPoint, scaFactory } = await setupTests();
      const chainId = await getChainId();

      // precompute smart account address (will be lazy deployed)
      const smartAccount = await computeWalletAddress(
        smartAccountOwner.address,
        smartAccountIndex,
      );

      // fund user account with 1 ETH
      await deployer.sendTransaction({
        to: smartAccount,
        value: ONE_ETH,
      });
      expect(await deployer.provider.getBalance(smartAccount)).to.be.equal(
        ONE_ETH,
      );

      // generate userOp that moves 1 ETH from user account to bob
      const lowMaxGasLimit = 10_000; // user will be undercharged for the userOp cost
      const userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        bob.address,
        ONE_ETH,
        EMPTY_CALLDATA,
        true,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
        lowMaxGasLimit,
      );
      const userOpHash4337 = await entryPoint.getUserOpHash(userOp);

      // node executes userOp with 1 ETH msg.value (used for refunds)
      const nodeDeposit = ONE_ETH;
      const tx = await klasterPaymaster
        .connect(klasterNode)
        .handleOps([userOp], {
          value: nodeDeposit,
        });
      const receipt = await tx.wait();

      // verify the event was emitted for depositing 1 ETH to klaster paymaster
      await expect(tx)
        .to.emit(entryPoint, "Deposited")
        .withArgs(klasterPaymaster.target, nodeDeposit);

      // verify the user account was lazy deployed
      await expect(tx).to.emit(entryPoint, "AccountDeployed").withArgs(
        userOpHash4337, // erc4337 userOp hash
        smartAccount, // userOp.sender
        scaFactory.target, // factory address
        klasterPaymaster.target, // paymaster address
      );

      // verify the userOp was executed successfully
      await expect(tx).to.emit(entryPoint, "UserOperationEvent");
      await expect(tx).to.changeEtherBalance(bob, ONE_ETH); // bob balance increased

      // verify the userOp.sender has received 0 refund from paymaster
      const paymasterAndData = await decodePaymasterData(userOp);
      const userOpCost = receipt!.gasPrice! * receipt!.gasUsed;
      const userPaid =
        BigInt(userOp.maxFeePerGas) * BigInt(paymasterAndData.maxGasLimit);
      expect(userPaid < userOpCost); // expect the user has underpaid for tx
      expect(await deployer.provider.getBalance(smartAccount)).to.be.equal(0); // and in that case expect 0 refund received from paymaster

      // verify the node withdrew everything that was left from the 1 ETH msg.value deposit
      expect((await entryPoint.getDepositInfo(klasterPaymaster)).deposit).equal(
        0,
      );
    });

    it("will fail if msg.value was not big enough to cover for userOp excecution & refunds", async () => {
      const smartAccountIndex = 0;
      const { deployer, klasterNode, smartAccountOwner, bob } =
        await getSigners();
      const { klasterPaymaster, entryPoint, scaFactory } = await setupTests();
      const chainId = await getChainId();

      // precompute smart account address (will be lazy deployed)
      const smartAccount = await computeWalletAddress(
        smartAccountOwner.address,
        smartAccountIndex,
      );

      // fund user account with 1 ETH
      await deployer.sendTransaction({
        to: smartAccount,
        value: ONE_ETH,
      });
      expect(await deployer.provider.getBalance(smartAccount)).to.be.equal(
        ONE_ETH,
      );

      // generate userOp that moves 1 ETH from user account to bob
      const lowMaxGasLimit = 10_000; // user will be undercharged for the userOp cost
      const userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        bob.address,
        ONE_ETH,
        EMPTY_CALLDATA,
        true,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
        lowMaxGasLimit,
      );

      const tx = klasterPaymaster.connect(klasterNode).handleOps([userOp], {
        value: 0, // eth sent is 0 -> can't process userOp
      });
      await expect(tx).to.be.revertedWithCustomError(
        klasterPaymaster,
        "EmptyMessageValue",
      );
    });

    it("will fail if malicious node is trying to execute userOp via different paymaster then the one defined in userOp", async () => {
      const smartAccountIndex = 0;
      const { deployer, klasterNode, smartAccountOwner, bob } =
        await getSigners();
      const { maliciousPaymaster, entryPoint } = await setupTests();
      const chainId = await getChainId();

      // precompute smart account address (will be lazy deployed)
      const smartAccount = await computeWalletAddress(
        smartAccountOwner.address,
        smartAccountIndex,
      );

      // fund user account with 1 ETH
      await deployer.sendTransaction({
        to: smartAccount,
        value: ONE_ETH,
      });
      expect(await deployer.provider.getBalance(smartAccount)).to.be.equal(
        ONE_ETH,
      );

      // generate userOp that moves 1 ETH from user account to bob
      const userOp = await fillAndSign(
        smartAccountOwner.address,
        smartAccountIndex,
        bob.address,
        ONE_ETH,
        EMPTY_CALLDATA,
        true,
        NOW,
        FAR_FUTURE,
        smartAccountOwner,
        chainId,
      );
      const tx = maliciousPaymaster
        .connect(klasterNode)
        .getFunction("handleOps")([userOp], {
        value: ONE_ETH,
      });
      await expect(tx).to.be.revertedWithCustomError(entryPoint, "FailedOp");
    });
  });
  describe("simulateHandleOp(): ", async () => {
    it("will revert if 0 msg.value sent", async () => {
      const smartAccountIndex = 0;
      const { smartAccountOwner } = await getSigners();
      const { klasterPaymaster } = await setupTests();
      const chainId = await getChainId();

      // generate userOp that runs empty op
      const userOp = await fillAndSign(
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
      const faultyTx = klasterPaymaster.simulateHandleOp.staticCall(
        userOp,
        AddressZero,
        EMPTY_CALLDATA,
      );
      await expect(faultyTx).to.be.revertedWithCustomError(
        klasterPaymaster,
        "EmptyMessageValue",
      );
    });
    it("can call simulateHandleOp()", async () => {
      const smartAccountIndex = 0;
      const { smartAccountOwner } = await getSigners();
      const { klasterPaymaster, entryPoint } = await setupTests();
      const chainId = await getChainId();

      // generate userOp that runs empty op
      const userOp = await fillAndSign(
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

      let simulationResult: ExecutionResult | null = null;
      try {
        await klasterPaymaster.simulateHandleOp(
          userOp,
          AddressZero,
          EMPTY_CALLDATA,
          { value: ONE_ETH },
        );
      } catch (err: any) {
        const parsed = entryPoint.interface.parseError(err.data);
        simulationResult = {
          preOpGas: parsed!.args[0],
          paid: parsed!.args[1],
          validAfter: parsed!.args[2],
          validUntil: parsed!.args[3],
          targetSuccess: parsed!.args[4],
          targetResult: parsed!.args[5],
        };
      }
      expect(simulationResult).to.exist;
      expect(simulationResult!.validAfter.toString()).to.be.equal(NOW);
      expect(simulationResult!.validUntil.toString()).to.be.equal(FAR_FUTURE);
      expect(simulationResult!.paid).to.be.greaterThan(0);
      expect(simulationResult!.preOpGas).to.be.greaterThan(0);
      expect(simulationResult!.targetResult).to.be.equal("0x");
      expect(simulationResult!.targetSuccess).to.be.false;
    });
  });

  describe("simulateValidation(): ", async () => {
    it("wil revert if 0 msg.value sent", async () => {
      const smartAccountIndex = 0;
      const { smartAccountOwner } = await getSigners();
      const { klasterPaymaster, entryPoint } = await setupTests();
      const chainId = await getChainId();

      // generate userOp that runs empty op
      const userOp = await fillAndSign(
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
      const faultyTx = klasterPaymaster.simulateValidation.staticCall(userOp);
      await expect(faultyTx).to.be.revertedWithCustomError(
        klasterPaymaster,
        "EmptyMessageValue",
      );
    });
    it("can call simulateValidation()", async () => {
      const smartAccountIndex = 0;
      const { smartAccountOwner } = await getSigners();
      const { klasterPaymaster, entryPoint } = await setupTests();
      const chainId = await getChainId();

      // generate userOp that runs empty op
      const userOp = await fillAndSign(
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

      let simulateValidationResult: SimulateValidationResult | null = null;
      try {
        await klasterPaymaster.simulateValidation(userOp, {
          value: ONE_ETH,
        });
      } catch (err: any) {
        const parsed = entryPoint.interface.parseError(err.data);
        simulateValidationResult = {
          returnInfo: {
            preOpGas: parsed!.args[0][0],
            prefund: parsed!.args[0][1],
            sigFailed: parsed!.args[0][2],
            validAfter: parsed!.args[0][3],
            validUntil: parsed!.args[0][4],
            paymasterContext: parsed!.args[0][5],
          },
          senderInfo: {
            stake: parsed!.args[1][0],
            unstakeDelaySec: parsed!.args[1][1],
          },
          factoryInfo: {
            stake: parsed!.args[2][0],
            unstakeDelaySec: parsed!.args[2][1],
          },
          paymasterInfo: {
            stake: parsed!.args[3][0],
            unstakeDelaySec: parsed!.args[3][1],
          },
        };
      }
      expect(simulateValidationResult).to.exist;
      expect(simulateValidationResult!.returnInfo.sigFailed).to.be.false;
      expect(
        simulateValidationResult!.returnInfo.validAfter.toString(),
      ).to.be.equal(NOW);
      expect(
        simulateValidationResult!.returnInfo.validUntil.toString(),
      ).to.be.equal(FAR_FUTURE);
    });
  });

  describe("calculateRefund(): ", async () => {
    it("should calculate userOp refund correctly if user overpaid (refund > 0)", async () => {
      const { klasterPaymaster } = await setupTests();

      const maxGasLimit = 1000n;
      const maxFeePerGas = 1000n;
      const actualGasCost = 1000n;
      const nodeOperatorPremium = 10n;

      const userPaid = maxGasLimit * maxFeePerGas;
      const actualGasCostWithPremium =
        (actualGasCost * (100n + nodeOperatorPremium)) / 100n;

      expect(userPaid > actualGasCostWithPremium).to.be.true;

      const expectedRefund = userPaid - actualGasCostWithPremium;
      const fetchedRefund = await klasterPaymaster.calculateRefund(
        maxGasLimit,
        maxFeePerGas,
        actualGasCost,
        nodeOperatorPremium,
      );
      expect(fetchedRefund).to.be.equal(expectedRefund);
    });

    it("should calculate userOp refund correctly if user underpaid (refund = 0)", async () => {
      const { klasterPaymaster } = await setupTests();

      const maxGasLimit = 1000n;
      const maxFeePerGas = 1000n;
      const actualGasCost = maxGasLimit * maxFeePerGas + 1n; // spend more than user paid
      const nodeOperatorPremium = 10n;

      const userPaid = maxGasLimit * maxFeePerGas;
      const actualGasCostWithPremium =
        (actualGasCost * (100n + nodeOperatorPremium)) / 100n;

      expect(userPaid < actualGasCostWithPremium).to.be.true;

      const expectedRefund = 0n;
      const fetchedRefund = await klasterPaymaster.calculateRefund(
        maxGasLimit,
        maxFeePerGas,
        actualGasCost,
        nodeOperatorPremium,
      );
      expect(fetchedRefund).to.be.equal(expectedRefund);
    });
  });
});
