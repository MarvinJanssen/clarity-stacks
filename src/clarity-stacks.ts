import { sha512_256 } from '@noble/hashes/sha512';
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { bufferCV, BytesReader, deserializeTransaction, listCV, tupleCV, uintCV } from '@stacks/transactions';
import type { StacksTransaction, TupleCV } from '@stacks/transactions';

export const NAKAMOTO_SIGNER_SIGNATURE_LENGTH = 65;

export function tagged_sha512_256(tag: Uint8Array, data: Uint8Array): Uint8Array {
    return sha512_256(new Uint8Array([...tag, ...data]));
}

export type NakamotoBlockStruct = {
    version: Uint8Array, // 1 byte
    chain_length: Uint8Array, // 8 bytes
    burn_spent: Uint8Array, // 8 bytes
    consensus_hash: Uint8Array, // 20 bytes
    parent_block_id: Uint8Array, // 32 bytes
    tx_merkle_root: Uint8Array, // 32 bytes
    state_index_root: Uint8Array, // 32 bytes
    timestamp: Uint8Array, // 8 bytes
    miner_signature: Uint8Array, // 65 bytes
    signer_signatures: Uint8Array[], // 65 bytes per signature
    signer_bitvec: Uint8Array, // 2 bytes bitvec bit count + 4 bytes buffer length + bitvec buffer
    transactions: StacksTransaction[]
}

// Adopted from https://github.com/stacks-network/stacks-core/blob/eb865279406d0700474748dc77df100cba6fa98e/stacks-common/src/util/hash.rs
export class MerkleTree {
    static MERKLE_PATH_LEAF_TAG = new Uint8Array([0x00]);
    static MERKLE_PATH_NODE_TAG = new Uint8Array([0x01]);

    nodes: Uint8Array[][];

    constructor(nodes: Uint8Array[][] = []) {
        this.nodes = nodes;
    }

    static empty(): MerkleTree {
        return new MerkleTree();
    }

    static new(data: Uint8Array[]): MerkleTree {
        if (data.length === 0) {
            return new MerkleTree();
        }

        let leaf_hashes: Uint8Array[] = data.map(buf => MerkleTree.get_leaf_hash(buf));

        // force even number
        if (leaf_hashes.length % 2 !== 0) {
            const dup = leaf_hashes[leaf_hashes.length - 1];
            leaf_hashes.push(dup);
        }

        let nodes: Uint8Array[][] = [leaf_hashes];

        while (true) {
            const current_level = nodes[nodes.length - 1];
            const next_level: Uint8Array[] = [];

            for (let i = 0; i < current_level.length; i += 2) {
                if (i + 1 < current_level.length) {
                    next_level.push(MerkleTree.get_node_hash(current_level[i], current_level[i + 1]));
                } else {
                    next_level.push(current_level[i]);
                }
            }

            // at root
            if (next_level.length === 1) {
                nodes.push(next_level);
                break;
            }

            // force even number
            if (next_level.length % 2 !== 0) {
                const dup = next_level[next_level.length - 1];
                next_level.push(dup);
            }

            nodes.push(next_level);
        }

        return new MerkleTree(nodes);
    }

    static get_leaf_hash(leaf_data: Uint8Array): Uint8Array {
        return tagged_sha512_256(MerkleTree.MERKLE_PATH_LEAF_TAG, leaf_data);
    }

    static get_node_hash(left: Uint8Array, right: Uint8Array): Uint8Array {
        return tagged_sha512_256(MerkleTree.MERKLE_PATH_NODE_TAG, new Uint8Array([...left, ...right]));
    }

    proof(index: number): Uint8Array[] {
        if (this.nodes.length === 0) {
            return [];
        }
        if (index > this.nodes[0].length-1) {
            throw new Error("Index out of bounds");
        }
        const depth = this.nodes.length - 1;
        const path = Math.pow(2, depth) + index;

        let proof: Uint8Array[] = [];
        let position = index;
        for (let level = 0 ; level < depth ; ++level) {
            const left = ((1 << level) & path) > 0;
            proof.push(this.nodes[level][position + (left ? -1 : 1)]);
            position = ~~(position / 2);
        }

        return proof;
    }

    root(): Uint8Array {
        if (this.nodes.length === 0) {
            return new Uint8Array(32);
        }
        return this.nodes[this.nodes.length - 1][0];
    }

    depth(): number {
        if (this.nodes.length === 0) {
            return 0;
        }
        return this.nodes.length - 1;
    }

    pretty_print(): string {
        let str = '';
        for (let level = this.nodes.length-1 ; level >= 0 ; --level) {
            const whitespace = " ".repeat((this.nodes.length-level-1)*2);
            str += this.nodes[level].map(node => whitespace+bytesToHex(node)+"\n").join('');
        }
        return str;
    }
}

export function merkle_tree_from_txs(txs: StacksTransaction[]): MerkleTree {
    return MerkleTree.new(txs.map(tx => hexToBytes(tx.txid())));
}

export function block_header_hash(block: NakamotoBlockStruct): Uint8Array {
    return sha512_256(raw_block_header(block));
}

export function block_index_header_hash(block_sighash: Uint8Array, consensus_hash: Uint8Array): Uint8Array {
    return sha512_256(new Uint8Array([...block_sighash, ...consensus_hash]));
}

export function raw_block_header(block: NakamotoBlockStruct): Uint8Array {
    return new Uint8Array([
        ...block.version,
        ...block.chain_length,
        ...block.burn_spent,
        ...block.consensus_hash,
        ...block.parent_block_id,
        ...block.tx_merkle_root,
        ...block.state_index_root,
        ...block.timestamp,
        ...block.miner_signature,
        ...block.signer_bitvec
    ]);
}

export function proof_path_to_cv(tx_index: number, hashes: Uint8Array[], tree_depth: number): TupleCV {
    return tupleCV({
        "tx-index": uintCV(tx_index),
        "hashes": listCV(hashes.map(bufferCV)),
        "tree-depth": uintCV(tree_depth)
    });
}

export function proof_cv(tx_index: number, merkle_tree: MerkleTree) {
    return proof_path_to_cv(tx_index, merkle_tree.proof(tx_index), merkle_tree.depth());
}

export async function fetch_raw_nakamoto_block(height: number, block_api?: string): Promise<Uint8Array> {
    block_api = block_api || 'https://api.hiro.so/v3/blocks/height/';
    const response = await fetch(`${block_api}${height}`);
    return await (response as any).bytes();
}

export function parse_raw_nakamoto_block(raw_block: Uint8Array): NakamotoBlockStruct {
    const reader = new BytesReader(raw_block);
    let block: NakamotoBlockStruct = {
        version: reader.readBytes(1),
        chain_length: reader.readBytes(8),
        burn_spent: reader.readBytes(8),
        consensus_hash: reader.readBytes(20),
        parent_block_id: reader.readBytes(32),
        tx_merkle_root: reader.readBytes(32),
        state_index_root: reader.readBytes(32),
        timestamp: reader.readBytes(8),
        miner_signature: reader.readBytes(65),
        signer_signatures: [],
        signer_bitvec: new Uint8Array(),
        transactions: []
    };
    const signature_count = reader.readUInt32BE();
    for (let i = 0; i < signature_count; i++) {
        block.signer_signatures.push(reader.readBytes(NAKAMOTO_SIGNER_SIGNATURE_LENGTH));
    }
    reader.consumed += 2; // skip signer bitvec bit count
    const bitvec_byte_length = reader.readUInt32BE();
    reader.consumed -= 6; // go back to the start of the bitvec
    block.signer_bitvec = reader.readBytes(2 + 4 + bitvec_byte_length);
    const tx_count = reader.readUInt32BE();
    for (let i = 0 ; i < tx_count ; ++i) {
        block.transactions.push(deserializeTransaction(reader));
    }
    if (reader.consumed !== raw_block.length) {
        throw new Error("Left-over bytes in raw block");
    }
    return block;
}

export async function fetch_nakamoto_block_struct(height: number, block_api?: string): Promise<NakamotoBlockStruct> {
    const raw_block = await fetch_raw_nakamoto_block(height, block_api);
    return parse_raw_nakamoto_block(raw_block);
}
