import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
  AddressVersion,
  boolCV,
  bufferCV,
  bufferCVFromString,
  contractPrincipalCV,
  createAssetInfo,
  createStacksPublicKey,
  cvToString,
  FungibleConditionCode,
  makeContractDeploy,
  makeStandardFungiblePostCondition,
  makeSTXTokenTransfer,
  makeUnsignedContractDeploy,
  PostConditionMode,
  pubKeyfromPrivKey,
  publicKeyToAddress,
  serializeCV,
  SingleSigSpendingCondition,
  uintCV,
  UnsignedContractDeployOptions,
} from "@stacks/transactions";
import { describe, expect, it } from "vitest";
import {
  block_header_hash,
  fetch_nakamoto_block_struct,
  merkle_tree_from_txs,
  parse_raw_nakamoto_block,
  proof_cv,
  raw_block_header,
} from "../src/clarity-stacks.ts";
import { CODE_BODY, TX_HEX } from "./data-deploy-tx.ts";

const accounts = simnet.getAccounts();
const deployer_secret =
  "753b7cc01a1a2e86221266a154af739463fce51219d97e4f856cd7200c3bd2a601";
const deployer = accounts.get("deployer")!;
const address1 = accounts.get("wallet_1")!;
const address2 = accounts.get("wallet_2")!;

const code_body = '(print "Proving contract code on Stacks is cool!")';
const code_body_bytes = new TextEncoder().encode(code_body);

describe("code-body-prover.clar", () => {
	it("Generates the same txid for a contract deploy transaction", async () => {
		const contract_name = 'my-contract';
		const tx_nonce = 3;
		const tx_fee = 20;

		const deploy_tx = await makeContractDeploy({
			codeBody: code_body,
			senderKey: deployer_secret,
			clarityVersion: 3,
			contractName: contract_name,
			fee: tx_fee,
			nonce: tx_nonce,
			network: 'mocknet',
			anchorMode: 'any',
			postConditionMode: PostConditionMode.Allow,
			postConditions: [],
			sponsored: false
		});

		const tx_spending_condition = deploy_tx.auth.spendingCondition as SingleSigSpendingCondition;
		const signature = hexToBytes(tx_spending_condition.signature.data);

		const tx_nonce_bytes = new Uint8Array(8);
		tx_nonce_bytes[7] = tx_nonce;

		const tx_fee_bytes = new Uint8Array(8);
		tx_fee_bytes[7] = tx_fee;

		const deploy_expected_txid = hexToBytes(deploy_tx.txid());

		let response = simnet.callReadOnlyFn(
			'code-body-prover',
			'calculate-txid',
			[
				bufferCV(tx_nonce_bytes),
				bufferCV(tx_fee_bytes),
				bufferCV(signature),
				contractPrincipalCV(deployer, contract_name),
				bufferCV(code_body_bytes)
			],
			address1
		);

		expect(response.result).toBeOk(bufferCV(deploy_expected_txid));
	});

	it("Can verify that a contract deploy transaction with a specific code body was mined", async () => {
		const contract_name = 'my-contract';
		const tx_nonce = 3;
		const tx_fee = 20;

		const deploy_tx = await makeContractDeploy({
			codeBody: code_body,
			senderKey: deployer_secret,
			clarityVersion: 3,
			contractName: contract_name,
			fee: tx_fee,
			nonce: tx_nonce,
			network: 'mocknet',
			anchorMode: 'any',
			postConditionMode: PostConditionMode.Allow,
			postConditions: [],
			sponsored: false
		});

		const tx_spending_condition = deploy_tx.auth.spendingCondition as SingleSigSpendingCondition;
		const signature = hexToBytes(tx_spending_condition.signature.data);

		const tx_nonce_bytes = new Uint8Array(8);
		tx_nonce_bytes[7] = tx_nonce;

		const tx_fee_bytes = new Uint8Array(8);
		tx_fee_bytes[7] = tx_fee;

		const deploy_expected_txid = hexToBytes(deploy_tx.txid());

		let response = simnet.callReadOnlyFn(
			'code-body-prover',
			'calculate-txid',
			[
				bufferCV(tx_nonce_bytes),
				bufferCV(tx_fee_bytes),
				bufferCV(signature),
				contractPrincipalCV(deployer, contract_name),
				bufferCV(code_body_bytes)
			],
			address1
		);

		expect(response.result).toBeOk(bufferCV(deploy_expected_txid));

		const unrelated_tx = await makeSTXTokenTransfer({
			recipient: address2,
			fee: 100,
			nonce: tx_nonce + 1,
			amount: 1000,
			senderKey: deployer_secret,
			network: 'mocknet',
			anchorMode: 'any',
			sponsored: false
		});

		const merkle_tree = merkle_tree_from_txs([deploy_tx, unrelated_tx]);
		const merkle_root = merkle_tree.root();

		// let's rewrite a block for our test
		const raw_mock_block = hexToBytes('00000000000006b0640000005cc4e4fab48077a657f82aac6012166525de0c5b53a3008c03d7039979ef223a52b3112fede246066c1b3be96acc3f0e47c345b332c0aebf96e9414d181f9dc949115bc057b98a0d75348e54c05ff8287e3bb80c95872c04038d6299532a78ff61705d4e4867644b1aec6ec069376f387faaa464591b7eb20200000000677e87db00b57b3fde1c8bce6a9364f9e47fa6a65d3c3a5bc76d377ed8a74546a718ab475d2b20dd591a003501624e6a842484a162c7ffccb857f4a78d76caae6366a33cd700000014007e8cb07951f28c9b6b99ea5aa9237dc7b3cc27b6c3ca92296dde9e691bd557c12fa01f1c7679f62c3c321bb3d86f675c370cfd2b23da5a70ac9ef0e1adbb97d0007467b27153049fa8e41187de38530148b703d2752c34dcf627cafb8b47c9d55743c9b5fd22d1f594d8861807f4141f32891f6328618dcf383a130ce5d4b7906901b62dfb71f37f92cc6b3a5204626c3e2df8910e0a44a33aaf2575d91b6949cfc80eb718ef692b5c70ee710f5a58dc692de4980876c3c0bb0183c9f8c5d33256c301f0a1557b05dc9da978d24ac5a89f50d8821665a8ece7f5f60b0857176f020fc0099541c112527fb59c6e22f6f4c0fb998e6ea610508820a1f62d53dd1bed7a8300a965bd21a6848e2cfd4f22bfe355270569ca8d036a8a0e0956f699b8a6c313866ea247630fdb8791c9407e030d564a48da4c3d56129017eb65f0f24256cae0d300eda58c7664cc4270a94764b13c6180d4f5988870856463eef0fc63975dadc0882553fe1205653c3148cad926e9c3f321fa963ed8a80ccf2148004a2a4d4af9de00d9d775837649928b32a14840b31629f95ad4ab3585220bf3a844afcb507fef124978cd57c55f6350ad60ad2474457e55e277db6cf8377d5ff893016c60192398008ae1d24927af6b682fa2b199cabd094f911ade725360bbabf402cffcd925f17222d3148f250ee67b1bd367113c2c7a13dc381dbf667762588eb8cb48341ce7f101d7ab98aa0b4249a0f5a5fd9ff18622b36a7a10f8f411a5200f52e4c653079b860a357546c5dda85cfacf73ca67747a0ca5b26c9c4c5442c77b2418e2ecd8e01a000cc8b19de661474bc2d53da4d3d0cc0e431386b04290586c54d9d2caa0869a0d4522a18efe5c39a888ebaea55e0b5f07f11354cdb560309c16749c73be03b5790095c9bba8f5c9ab8c979a3f6293c939337fd7d1ce84e2452d1bf546100a09f7e018de2ee24218e1f3468cd967811873ee8f8b559f341f083bd34b0a91d1de546b003af83dba80a26260ab5e5fe774d92b944e1e133d94dd27ef8b443831ff406c115980a05cf71d4d11cee9705c9970cf011b02a0f9198c18e3c244618486f04fff010236c15f5fb370db4b6101c6f21f94bc166dd5f42267870c9aa3a01f4cfc8c0c065a7568e870a91c6ebe6280ad078992a83c7af7a2cbbe6b2fc5a94a69723e98017593f306eac4913ce4c689220ad9b4cfe87b77f60e50f0c50fdcd96177607e936ba3b84953ca9d0a649dc67dcb647f97ddf0536361105d61409588b5eec6ebb401b8798d9097742e7b78aae992744d714a646ef28f9207c695370bce0c8cdf1ae65a4aa25cd5d7c49a443d39c22f19ca6e191ac6a988870180964a0cb1dd424d4d014e9f6201f8f085a4b1cbbce4045bfdabdfac819b4f1542050c5787f9afcff8f9386bbc585546b609e6bc26fc5066e8bc3176811b1813681703b9bb319283781300d9f8586e933e3b0cdc7a784b2d6379e4dc62f1e6075770e885c7adcf1ed41a767c12b6761e2381caa7d90e193048989de7206e48b43126a89c6a80409fe336c700a695a65b6c83daf301b5ed1f90dc7842ed9ea57e774fe0e4638b5c5a6e3ff3724baf51901d9294a523ef108ea0b62486b6f80c49ca34e8d84f3401da7d111e0e0115c2a5e92204a27a66ecb1df66be399e43536fa4e2bf62ae482136c1b7a607677faceeb6ff8ef1cbf5a26e26bd0ba8b5a7e4e8b2b012e6f9413f8d0314d37dcd00d5b1106dcd197e3eaaa5e5969e7eb1350dc7c09e50da1adef7369ae45c52f3c213b8c59cce0bad14884f0e26f95eed666e9318569ddde5671084e8fb297de5f90ec9000001daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000000200000000010400c96dc19fafcf7bf1b42c59faa88e0ea5fcd8ef6c000000000000034b0000000000055c33000088e497445b9165f31e9ec591ae886d4cafd1ea365a0c772642e2e1a517626bde164eb86017967506b0f48d60c08114b6f0aa997510d03645bc7976ac53d802be0302000000000005162fbde0255efaa0354d12463d045c3291b3cc1a8b00000000000f638d0000000000000000000000000000000000000000000000000000000000000000000000000000010400a4e680bdfe8804b7fe69a4a64948c558558293a7000000000000000d00000000000027100001a039ec812f2b59f0967e6d71be072de17282e73fd661f8b01d587c0a4ea3f54d0d8bc1743d8f40a9990c304d523fb1561131dc34abdf523b478e79858559c30d030200000002010216a4e680bdfe8804b7fe69a4a64948c558558293a716eae2820eebe09cfe1ad1436203a264fd9f958c271477656c7368636f726769636f696e2d746f6b656e0e77656c7368636f726769636f696e01000000001dcd6500000316402da2c079e5d31d58b9cfc7286d1b1eb2f7834e0f616d6d2d7661756c742d76322d303103000000000005471002162ec1a2dc2904ebc8b408598116c75e42c51afa2612777261707065722d616c65782d762d322d310b737761702d68656c706572000000050616402da2c079e5d31d58b9cfc7286d1b1eb2f7834e0c746f6b656e2d77636f7267690616402da2c079e5d31d58b9cfc7286d1b1eb2f7834e0d746f6b656e2d777374782d76320100000000000000000000000005f5e1000100000000000000000000000ba43b74000a01000000000000000000000000020fc266');
		const mock_block = parse_raw_nakamoto_block(raw_mock_block);

		mock_block.transactions = [deploy_tx, unrelated_tx];
		mock_block.tx_merkle_root = merkle_root;

		const mock_block_header_hash = block_header_hash(mock_block);

		simnet.callPublicFn("clarity-stacks", "debug-set-block-header-hash", [uintCV(1), bufferCV(mock_block_header_hash)], address1);

		// deploy tx proof
		const proofCV = proof_cv(0, merkle_tree);

		response = simnet.callReadOnlyFn(
			"code-body-prover",
			"is-contract-deployed",
			[
				bufferCV(tx_nonce_bytes),
				bufferCV(tx_fee_bytes),
				bufferCV(signature),
				contractPrincipalCV(deployer, contract_name),
				bufferCV(code_body_bytes),
				proofCV,
				uintCV(1),
				bufferCV(raw_block_header(mock_block))
			],
			address1
		);

		expect(response.result).toBeOk(boolCV(true));
	});


	it("Can verify that age-of-empires contract was deployed at block 528,385", async () => {
		const contract_name = 'age-of-empires';
		const tx_nonce = 3272;
		const tx_fee = 146677;

		const deploy_tx = await makeUnsignedContractDeploy({
			codeBody: CODE_BODY,
			clarityVersion: 3,
			contractName: contract_name,
			fee: tx_fee,
			nonce: tx_nonce,
			network: 'mainnet',
			anchorMode: 'any',
			postConditionMode: PostConditionMode.Deny,
			postConditions: [],
			sponsored: false,
			publicKey: bytesToHex(pubKeyfromPrivKey(deployer_secret).data),
		} as UnsignedContractDeployOptions);

		const tx_spending_condition = deploy_tx.auth.spendingCondition as SingleSigSpendingCondition;
		const signature = hexToBytes(tx_spending_condition.signature.data);

		let hex: string ="";
		const tx_nonce_bytes = new Uint8Array(8);
		hex = tx_nonce.toString(16);
		hexToBytes(hex.padStart(16, "0")).forEach((v, i) => tx_nonce_bytes[i] = v);

		const tx_fee_bytes = new Uint8Array(8);
		hex = tx_fee.toString(16);
		hexToBytes(hex.padStart(16, "0")).forEach((v, i) => tx_fee_bytes[i] = v);

		const deploy_expected_txid = "1023fce43ffd00facea3e8e01a4afc7cb56b3e2d9c1358e27a8aafc9216d953a";
		const code_body_bytes = new TextEncoder().encode(CODE_BODY);

		let response = simnet.callReadOnlyFn(
			'code-body-prover',
			'calculate-txid',
			[
				bufferCV(tx_nonce_bytes),
				bufferCV(tx_fee_bytes),
				bufferCV(signature),
				contractPrincipalCV(deployer, contract_name),
				bufferCV(code_body_bytes)
			],
			address1
		);

		expect(response.result).toBeOk(bufferCV(hexToBytes(deploy_expected_txid)));

		const unrelated_tx = await makeSTXTokenTransfer({
			recipient: address2,
			fee: 100,
			nonce: tx_nonce + 1,
			amount: 1000,
			senderKey: deployer_secret,
			network: 'mocknet',
			anchorMode: 'any',
			sponsored: false
		});

		const merkle_tree = merkle_tree_from_txs([deploy_tx, unrelated_tx]);
		const merkle_root = merkle_tree.root();

		// let's rewrite a block for our test
		const raw_mock_block = hexToBytes('00000000000006b0640000005cc4e4fab48077a657f82aac6012166525de0c5b53a3008c03d7039979ef223a52b3112fede246066c1b3be96acc3f0e47c345b332c0aebf96e9414d181f9dc949115bc057b98a0d75348e54c05ff8287e3bb80c95872c04038d6299532a78ff61705d4e4867644b1aec6ec069376f387faaa464591b7eb20200000000677e87db00b57b3fde1c8bce6a9364f9e47fa6a65d3c3a5bc76d377ed8a74546a718ab475d2b20dd591a003501624e6a842484a162c7ffccb857f4a78d76caae6366a33cd700000014007e8cb07951f28c9b6b99ea5aa9237dc7b3cc27b6c3ca92296dde9e691bd557c12fa01f1c7679f62c3c321bb3d86f675c370cfd2b23da5a70ac9ef0e1adbb97d0007467b27153049fa8e41187de38530148b703d2752c34dcf627cafb8b47c9d55743c9b5fd22d1f594d8861807f4141f32891f6328618dcf383a130ce5d4b7906901b62dfb71f37f92cc6b3a5204626c3e2df8910e0a44a33aaf2575d91b6949cfc80eb718ef692b5c70ee710f5a58dc692de4980876c3c0bb0183c9f8c5d33256c301f0a1557b05dc9da978d24ac5a89f50d8821665a8ece7f5f60b0857176f020fc0099541c112527fb59c6e22f6f4c0fb998e6ea610508820a1f62d53dd1bed7a8300a965bd21a6848e2cfd4f22bfe355270569ca8d036a8a0e0956f699b8a6c313866ea247630fdb8791c9407e030d564a48da4c3d56129017eb65f0f24256cae0d300eda58c7664cc4270a94764b13c6180d4f5988870856463eef0fc63975dadc0882553fe1205653c3148cad926e9c3f321fa963ed8a80ccf2148004a2a4d4af9de00d9d775837649928b32a14840b31629f95ad4ab3585220bf3a844afcb507fef124978cd57c55f6350ad60ad2474457e55e277db6cf8377d5ff893016c60192398008ae1d24927af6b682fa2b199cabd094f911ade725360bbabf402cffcd925f17222d3148f250ee67b1bd367113c2c7a13dc381dbf667762588eb8cb48341ce7f101d7ab98aa0b4249a0f5a5fd9ff18622b36a7a10f8f411a5200f52e4c653079b860a357546c5dda85cfacf73ca67747a0ca5b26c9c4c5442c77b2418e2ecd8e01a000cc8b19de661474bc2d53da4d3d0cc0e431386b04290586c54d9d2caa0869a0d4522a18efe5c39a888ebaea55e0b5f07f11354cdb560309c16749c73be03b5790095c9bba8f5c9ab8c979a3f6293c939337fd7d1ce84e2452d1bf546100a09f7e018de2ee24218e1f3468cd967811873ee8f8b559f341f083bd34b0a91d1de546b003af83dba80a26260ab5e5fe774d92b944e1e133d94dd27ef8b443831ff406c115980a05cf71d4d11cee9705c9970cf011b02a0f9198c18e3c244618486f04fff010236c15f5fb370db4b6101c6f21f94bc166dd5f42267870c9aa3a01f4cfc8c0c065a7568e870a91c6ebe6280ad078992a83c7af7a2cbbe6b2fc5a94a69723e98017593f306eac4913ce4c689220ad9b4cfe87b77f60e50f0c50fdcd96177607e936ba3b84953ca9d0a649dc67dcb647f97ddf0536361105d61409588b5eec6ebb401b8798d9097742e7b78aae992744d714a646ef28f9207c695370bce0c8cdf1ae65a4aa25cd5d7c49a443d39c22f19ca6e191ac6a988870180964a0cb1dd424d4d014e9f6201f8f085a4b1cbbce4045bfdabdfac819b4f1542050c5787f9afcff8f9386bbc585546b609e6bc26fc5066e8bc3176811b1813681703b9bb319283781300d9f8586e933e3b0cdc7a784b2d6379e4dc62f1e6075770e885c7adcf1ed41a767c12b6761e2381caa7d90e193048989de7206e48b43126a89c6a80409fe336c700a695a65b6c83daf301b5ed1f90dc7842ed9ea57e774fe0e4638b5c5a6e3ff3724baf51901d9294a523ef108ea0b62486b6f80c49ca34e8d84f3401da7d111e0e0115c2a5e92204a27a66ecb1df66be399e43536fa4e2bf62ae482136c1b7a607677faceeb6ff8ef1cbf5a26e26bd0ba8b5a7e4e8b2b012e6f9413f8d0314d37dcd00d5b1106dcd197e3eaaa5e5969e7eb1350dc7c09e50da1adef7369ae45c52f3c213b8c59cce0bad14884f0e26f95eed666e9318569ddde5671084e8fb297de5f90ec9000001daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000000200000000010400c96dc19fafcf7bf1b42c59faa88e0ea5fcd8ef6c000000000000034b0000000000055c33000088e497445b9165f31e9ec591ae886d4cafd1ea365a0c772642e2e1a517626bde164eb86017967506b0f48d60c08114b6f0aa997510d03645bc7976ac53d802be0302000000000005162fbde0255efaa0354d12463d045c3291b3cc1a8b00000000000f638d0000000000000000000000000000000000000000000000000000000000000000000000000000010400a4e680bdfe8804b7fe69a4a64948c558558293a7000000000000000d00000000000027100001a039ec812f2b59f0967e6d71be072de17282e73fd661f8b01d587c0a4ea3f54d0d8bc1743d8f40a9990c304d523fb1561131dc34abdf523b478e79858559c30d030200000002010216a4e680bdfe8804b7fe69a4a64948c558558293a716eae2820eebe09cfe1ad1436203a264fd9f958c271477656c7368636f726769636f696e2d746f6b656e0e77656c7368636f726769636f696e01000000001dcd6500000316402da2c079e5d31d58b9cfc7286d1b1eb2f7834e0f616d6d2d7661756c742d76322d303103000000000005471002162ec1a2dc2904ebc8b408598116c75e42c51afa2612777261707065722d616c65782d762d322d310b737761702d68656c706572000000050616402da2c079e5d31d58b9cfc7286d1b1eb2f7834e0c746f6b656e2d77636f7267690616402da2c079e5d31d58b9cfc7286d1b1eb2f7834e0d746f6b656e2d777374782d76320100000000000000000000000005f5e1000100000000000000000000000ba43b74000a01000000000000000000000000020fc266');
		const mock_block = parse_raw_nakamoto_block(raw_mock_block);

		mock_block.transactions = [deploy_tx, unrelated_tx];
		mock_block.tx_merkle_root = merkle_root;

		const mock_block_header_hash = block_header_hash(mock_block);

		simnet.callPublicFn("clarity-stacks", "debug-set-block-header-hash", [uintCV(1), bufferCV(mock_block_header_hash)], address1);

		// deploy tx proof
		const proofCV = proof_cv(0, merkle_tree);

		response = simnet.callReadOnlyFn(
			"code-body-prover",
			"is-contract-deployed",
			[
				bufferCV(tx_nonce_bytes),
				bufferCV(tx_fee_bytes),
				bufferCV(signature),
				contractPrincipalCV(deployer, contract_name),
				bufferCV(code_body_bytes),
				proofCV,
				uintCV(1),
				bufferCV(raw_block_header(mock_block))
			],
			address1
		);

		expect(response.result).toBeOk(boolCV(true));
	});
  it("Can verify that agp441 contract was deployed at block 516,259", async () => {
    const contract = "SP1E0XBN9T4B10E9QMR7XMFJPMA19D77WY3KP2QKC.agp441";
    const tx_id =
      "d04091fae9b483e9dd787340e9a56eede3bd4e5e3790109da30dbffa2c4c1620";
    const tx_nonce = 190;
    const tx_fee = 500002;
    const block_height = 516259;
    const tx_index = 1;

    const [contract_address, contract_name] = contract.split(".");

    const signature = hexToBytes(TX_HEX.slice(90, 90 + 130));

    let hex: string = "";
    const tx_nonce_bytes = new Uint8Array(8);
    hex = tx_nonce.toString(16);
    hexToBytes(hex.padStart(16, "0")).forEach(
      (v, i) => (tx_nonce_bytes[i] = v)
    );
    //console.log(bytesToHex(tx_nonce_bytes));

    const tx_fee_bytes = new Uint8Array(8);
    hex = tx_fee.toString(16);
    hexToBytes(hex.padStart(16, "0")).forEach((v, i) => (tx_fee_bytes[i] = v));
    //console.log(bytesToHex(tx_fee_bytes));

    const code_body_bytes = new TextEncoder().encode(CODE_BODY);

    const responseTxId = simnet.callReadOnlyFn(
      "code-body-prover",
      "calculate-txid",
      [
        bufferCV(tx_nonce_bytes),
        bufferCV(tx_fee_bytes),
        bufferCV(signature),
        contractPrincipalCV(contract_address, contract_name),
        bufferCV(code_body_bytes),
      ],
      address1
    );

    expect(responseTxId.result).toBeOk(bufferCV(hexToBytes(tx_id)));

    const block = await fetch_nakamoto_block_struct(block_height);
    console.log(
      cvToString(
        simnet.callReadOnlyFn(
          "clarity-stacks",
          "get-block-info-header-hash?",
          [uintCV(block_height)],
          deployer
        ).result
      )
    );
    const merkle_tree = merkle_tree_from_txs([
      hexToBytes(
        "6d5299ef7c9251ee09ed34ebfafb3aac03c7c4209134eb055169fa1c55cdd0a2"
      ),
      hexToBytes(tx_id),
      hexToBytes(
        "d4a8cc0f8f471795cd2bb170d8843d41ba121baf032080bd2fb5e5e5c08d5e1d"
      ),
    ]);

    // deploy tx proof
    const proofCV = proof_cv(tx_index, merkle_tree);

    const response = simnet.callReadOnlyFn(
      "code-body-prover",
      "is-contract-deployed",
      [
        bufferCV(tx_nonce_bytes),
        bufferCV(tx_fee_bytes),
        bufferCV(signature),
        contractPrincipalCV(contract_address, contract_name),
        bufferCV(code_body_bytes),
        proofCV,
        uintCV(block_height),
        bufferCV(raw_block_header(block)),
      ],
      address1
    );

    expect(response.result).toBeOk(boolCV(true));
  });
});
