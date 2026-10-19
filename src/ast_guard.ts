import * as acorn from 'acorn';
import * as walk from 'acorn-walk';

export interface GuardAnalysisResult {
  isSafe: boolean;
  violations: string[];
  riskScore: number; // Scale from 0 to 100
}

export class ASTStaticSandboxGuard {
  // Explicit signatures known for sandbox escape Vectors and reverse shell allocations
  private restrictedProperties = new Set(['process', 'child_process', 'fs', 'cluster', 'worker_threads', 'global', 'require', 'import']);
  private restrictedFunctions = new Set(['eval', 'Function', 'setTimeout', 'setInterval']);

  /**
   * Statically audits untrusted JavaScript execution strings using abstract syntax tree verification paths
   */
  public inspectCodePayload(untrustedJavaScriptCode: string): GuardAnalysisResult {
    const violations: string[] = [];
    let riskScore = 0;

    try {
      // Compile code string down into an abstract cryptographic syntax tree node structure
      const ast = acorn.parse(untrustedJavaScriptCode, { ecmaVersion: 'latest', sourceType: 'module' });

      // Walk the tree nodes recursively to intercept dynamic or obfuscated execution calls
      walk.ancestor(ast, {
        CallExpression(node: any) {
          const calleeName = node.callee.name;
          
          // 1. Intercept Direct Execution Vulnerabilities (eval, Function constructors)
          if (calleeName && ['eval', 'Function'].includes(calleeName)) {
            violations.push(`🚨 CRITICAL: Direct dynamic execution trigger detected via function invocation: \`\${calleeName}()\`.`);
            riskScore += 50;
          }
        },
        MemberExpression(node: any) {
          // 2. Intercept Obfuscated Property Lookups (e.g. process["platform"] or global["exec"])
          if (node.property && node.property.type === 'Literal') {
            const propertyValue = String(node.property.value);
            if (['process', 'child_process', 'fs', 'require'].includes(propertyValue)) {
              violations.push(`⚠️ WARNING: Obfuscated string literal dictionary bracket access pattern caught mapping restricted token: \`\${propertyValue}\`.`);
              riskScore += 30;
            }
          }
        },
        Identifier(node: any, state: any, ancestors: any[]) {
          // 3. Intercept Raw Environment Reference Access Attempts
          const identifierName = node.name;
          if (['process', 'global', 'module', 'require'].includes(identifierName)) {
            // Confirm the node isn't just an internal variable declaration signature locally scoped
            const parent = ancestors[ancestors.length - 2];
            if (parent && parent.type !== 'VariableDeclarator' && parent.type !== 'Property') {
              violations.push(`🚨 CRITICAL: Attempted hardware runtime context exposure via global identifier reference: \`\${identifierName}\`.`);
              riskScore += 40;
            }
          }
        }
      });

    } catch (parseError: any) {
      violations.push(`❌ PARSE_FAILURE: Input payload syntax structure is malformed or intentionally corrupted: ${parseError.message}`);
      riskScore = 100; // Refuse execution on compilation anomalies
    }

    return {
      isSafe: violations.length === 0,
      violations,
      riskScore: Math.min(riskScore, 100)
    };
  }
}
