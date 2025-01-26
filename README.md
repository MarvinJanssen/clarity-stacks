# clarity-stacks

A Clarity library to check if a specific transaction ID was mined in a Stacks block.

Inspired by the excellent [clarity-bitcoin](https://github.com/friedger/clarity-bitcoin) library.

With thanks to @Friedger.

## Why?

Why not? In all seriousness, this library allows you to check if a specific transaction has been mined in a Stacks block in Clarity. It is particularly useful to prove if a given contract has a specific code body. Since there is no Clarity function to fetch a transaction nor to read a contract code body, this is the next best thing.

The inability to deploy a contract from an existing contract is sometimes a limiting factor for protocols. Whilst this library does not provide such a feature, it does allow a protocol to accept a contract deployed by a third-party by verifying if the code body is as it expects.

## Clarity functions

### clarity-stacks

Stateless contract that verifies if a specific transaction ID was mined in a block.

Use `was-tx-mined-compact`, it returns `(ok true)` if the transaction was mined. It takes the following parameters:

- `txid`: 32-byte txid buffer
- `proof`: tuple with a merkle proof (see below)
- `tx-block-height`: block height of the transaction to verify
- `block-header-without-signer-signatures`: as described (see below)

### code-body-prover

Stateless contract that verifies if a contract with a specific code body was mined in a block.

Use `is-contract-deployed`, it returns `(ok true)` if the transaction was mined. It takes the following parameters:

- `nonce`: tx nonce as an 8-byte buffer
- `fee`: tx fee as an 8-byte buffer
- `signature`: 65-byte signature
- `contract`: contract principal to check
- `code-body`: code body to prove
- `proof`: tuple with a merkle proof (see below)
- `tx-block-height`: block height of the transaction to verify
- `block-header-without-signer-signatures`: as described (see below)

### clarity-stacks-helper

Contains helper functions to calculate block hashes that check the length of the inputs:

- `block-header-hash`: calculates the block header hash.
- `block-id-header-hash`: calculates the block ID.

## Merkle proof

The merkle proof is a tuple in the form of:

```clarity
{ tx-index: uint, hashes: (list 14 (buff 32)), tree-depth: uint}
```

There is a helper function in `clarity-stacks.ts` to generate it for you. (See below.)

## Block header without signer signatures

Required to be able to calculate the block header hash. It should be a buffer containing the entire block header of a Nakamoto block with the signer signatures stripped out. It should look like this:

- version: 1 byte
- chain_length: 8 bytes
- burn_spent: 8 bytes
- consensus_hash: 20 bytes
- parent_block_id: 32 bytes
- tx_merkle_root: 32 bytes
- state_index_root: 32 bytes
- timestamp: 8 bytes
- miner_signature: 65 bytes
- signer_bitvec: 2 bytes bitvec bit count + 4 bytes buffer length + bitvec buffer

Luckily for you, there is a helper function in `clarity-stacks.ts` to generate it for you. (See below.)

## clarity-stacks.ts

A minimal TypeScript library to make using the clarity-stacks library a bit easier.

### Class MerkleTree

Feed it a list of transaction IDs and it will construct a Stacks-compatible merkle tree for you.

```ts
const tree = MerkleTree.new([txid1, txid2, txid3, txid4]);
const root = tree.root(); // get the merkle root
const proof = tree.proof(0); // generate a proof for txid1
```

### Creating proof tuples

Construct a merkle tree as above, then use the helper function:

```ts
const proof = tree.proof(0);
const proofCV = proof_path_to_cv(0, proof, 2); // tx_index, proof, tree depth
```

### Fetching and preparing block headers

There are helper functions to fetch, parse, and prepare blocks. Uses the new v3 API that returns raw blocks. 

```ts
const block = await fetch_nakamoto_block_struct(block_height);
const block_header_without_signer_signatures = raw_block_header(block);
```

### Example script

A small example file at `src/example.ts` that uses some of the TypeScript library functions. It can be executed directly with `npx ts-node src/example.ts`.

## Unit tests

There are some, mainly to illustrate how to use the Clarity and TypeScript library. Run `npm test` after installing dependencies.

## Future developments

The library requires information that the Stacks chain already knows to be submitted, like the block header, transaction IDs, and so on. It makes the library wasteful in that sense. A Clarity function that fetches a code body or returns a hash of a code body would make the library redundant. If you like this library, then consider voicing your support for such a feature.

```clarity
(get-code-body 'SP123....my-contract)
(get-code-body-sha256 'SP123....my-contract)
```

