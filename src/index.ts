import { ASTStaticSandboxGuard } from './ast_guard.js';

const guard = new ASTStaticSandboxGuard();

console.log("🛡️ Starting AST Static Sandbox Guard Telemetry Sandbox Verification...\n");

// Test A: Obfuscated attack payload trying to evade regex using bracket manipulation
const maliciousObfuscatedPayload = `
const decoderToken = "pro" + "cess";
const executionRef = global[decoderToken];
executionRef.exit(1);
`;

const resultA = guard.inspectCodePayload(maliciousObfuscatedPayload);
console.log("📋 Analysis Results [Test A]:", JSON.stringify(resultA, null, 2));

// Test B: Compliant Mathematical Standard Operations Array
const safePayload = `
export function computeCompoundInterest(principal, rate, time) {
    return principal * Math.pow((1 + rate), time);
}
`;

const resultB = guard.inspectCodePayload(safePayload);
console.log("\n📋 Analysis Results [Test B]:", JSON.stringify(resultB, null, 2));
