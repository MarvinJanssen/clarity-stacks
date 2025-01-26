import { stringAsciiCV } from "@stacks/transactions";
import { describe, expect, it } from "vitest";

const accounts = simnet.getAccounts();
const address1 = accounts.get("wallet_1")!;

const code_body = '(print "Proving contract code on Stacks is cool!")';
const code_body_bytes = new TextEncoder().encode(code_body);

describe("clarity-stacks-helper.clar", () => {
	it("Can turn a string-ascii into a buffer", () => {
		const response = simnet.callReadOnlyFn('clarity-stacks-helper', 'string-ascii-to-buffer', [stringAsciiCV(code_body)], address1);
		expect(response.result).toBeBuff(code_body_bytes);
	});
});
