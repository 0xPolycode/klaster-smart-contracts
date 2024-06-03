# Klaster Protocol Contracts

[Klaster.io](https://klaster.io) is a chain-abstraction protocol. 
This smart contracts repo serves as the back-bone of the Klaster protocol, which is two smart contracts:

1. [KlasterPaymaster](./contracts/KlasterPaymaster.sol)
2. [KlasterEcdsaOwnershipModule](./contracts/KlasterEcdsaOwnershipModule.sol)

## Technical Introduction

Klaster protocol is a commitment & execution layer above all other blockchain networks.

Klaster protocol works with **iTx's** (inter chain transactions). This is a bundle of transactions targeting different blockchain networks, that may or may not be dependent on one another.

Klaster nodes as a part of Klaster network. They receive user's iTx bundles, they generate merkle root iTx hash for the given bundle and commit to the user to execute their full iTx bundle for a given percentage premium taken on top of every userOp.

Every transaction in the iTx bundle is actually a *UserOp* transaction as defined in the [4337 stack](https://www.erc4337.io/), with an additional new fields appended on top of *UserOp* data model:

- lowerBoundTimestamp

    *Earliest the tx can get executed on chain.*

- upperBoundTimestamp

    *Latest the tx can get executed on chain.*

- maxGasLimit
    
    *Max gas limit charged to the user for executing the UserOp.*

- chainId

    *Chain where the UserOp is allowed to get executed on.*

- klasterEntrypoint

    *Klaster entrypoint address.*

- iTxHash

    *Merkle root hash of all the UserOp from particular iTx bundle.*

- merkleProof

    *The proof that this particular UserOp is a part of a given merkle tree with root iTxHash.*

- klasterNodeFee

    *The percentage on top of the actual UserOp tx cost, that the Klaster node charges for executing the UserOp.*
    
In the core of the protocol, [Biconomy smart accounts V2](https://docs.biconomy.io/contracts) are being used as the wallets that the UserOps are being executed on top.

## Example use case

For example a user may define iTx bundle containg two transactions:

1. Bridge funds from their smart account wallet from Polygon to Base.

2. Swap funds to some other asset on Base.

This iTx bundle will have it's root iTx hash which user has to sign and provide the signature to the Klaster network in order for Klaster network to be allowed to process the txs one by one.

## Core contracts

There's two core contracts to be scheduled for audit as stated above: **KlasterEcdsaOwnershipModule** & **KlasterPaymaster**.

> They are dependent on some other contracts either included directly from an installed npm package (*@account-abstraction/contracts*, *@openzeppelin/contracts*) or cloned to this repository in the lack of the npm package, but have been marked to be taken from the given github repo at the beginning of the Solidity code (files in *./interfaces* & *./modules* subfolders).
All the dependencies, be it cloned & used from this repo, or included via an npm package, have been audited.

### KlasterEcdsaOwnershipModule

**KlasterEcdsaOwnershipModule.sol** is an authorization module built on top of Biconomy smart accounts architecture. It validates the user's signature against the given UserOp and a merkle root hash of the full iTx bundle containing multiple UserOp's.

This contract is modeled on top of the audited Biconomy's [EcdsaOwnershipRegistryModule](https://github.com/bcnmy/scw-contracts/blob/main/contracts/smart-account/modules/EcdsaOwnershipRegistryModule.sol) which validates the signature against one single UserOp and can be used with existing (already deployed) Bicnomy infrastructure to initialize smart accounts with his module enabled.

### KlasterPaymaster

**KlasterPaymaster.sol** is a wrapper around the [4337 EntryPoint V6 contract](https://www.erc4337.io/docs/understanding-ERC-4337/entry-point-contract) which is already deployed on different chains at the address: 

```0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789```

KlasterPaymaster allows Klaster nodes to execute userOps by using the KlasterPaymaster as a proxy and is responsible for:

1. executing UserOps as a part of iTx bundles
2. calculating total gas spent on the UserOp execution and then giving back the refund to the user

For every UserOp, the user was charged upfront the for the amount equal to:

`upfrontPayment = userOp.maxGasPrice * userOp.maxGasLimit` 

Klaster node takes a fee percentage on top of the given tx cost.

As the KlasterPaymaster works in a way as a 4337 Paymaster, it's got the callback exposed (*postOp() function*) to check what was the actual gas price & gas spent by the UserOp at the moment of execution. KlasterPaymaster takes it's fee into account, and then calculates the potential refund to be given back to the user if the gas price terms were a little bit favorable, or the user overestimated their UserOp maxGasLimit. 

On the other hand, if the gas price spiked and the Klaster node was commited to execute the tx, the cost for the user was capped to the `userOp.maxGasPrice * userOp.maxGasLimit` but the node must execute the UserOp with a loss - that's the risk that Klaster nodes take when commiting to the tx execution.