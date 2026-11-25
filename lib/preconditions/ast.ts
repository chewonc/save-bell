// Deterministic call-site analysis for JavaScript / TypeScript with the TypeScript compiler's parser (no type checker,
// no AI). It finds calls to a module's functions through the module's import or require bindings, and classifies each
// argument only from what the syntax tree shows. Anything decided at run time (environment values, values passed in
// from elsewhere, computed objects) is reported as such, never guessed. A reference the analysis cannot follow (the
// module passed around, a method read without being called, a dynamic require) is reported as "untracked", so callers
// can refuse to conclude "absent" from an incomplete picture.
import ts from "typescript";

export type ArgKind =
  | { kind: "string"; value: string }
  | { kind: "env"; name: string; fallback: "none" | "or_literal" | "nullish_literal" | "other" }
  | { kind: "function" }
  | { kind: "read_file"; path: string }
  | { kind: "missing" }
  | { kind: "unknown"; text: string };

export type OptionsKind =
  | { kind: "none" }
  | { kind: "object"; props: string[]; algorithms: string[] | null; algorithmsKnown: boolean }
  | { kind: "unknown"; text: string };

export type CallSite = { file: string; line: number; quote: string; method: string; test: boolean; key: ArgKind; options: OptionsKind };
export type Untracked = { file: string; line: number; quote: string; why: string };
export type ModuleUsage = { calls: CallSite[]; untracked: Untracked[]; files_scanned: number; parse_errors: string[] };

export const SCANNABLE = /\.(c|m)?[jt]sx?$/;
const SKIP_DIR = /(^|\/)(node_modules|dist|build|out|coverage|\.next|vendor)\//;
export const TEST_PATH = /(^|\/)(test|tests|__tests__|spec|e2e)\/|\.(test|spec)\.[cm]?[jt]sx?$/;

/** Source files worth scanning, smallest-first so a capped scan covers as many files as possible. */
export function scannableFiles(entries: { path: string; size?: number }[], cap = 150): { paths: string[]; truncated: boolean } {
  const all = entries.filter((e) => SCANNABLE.test(e.path) && !SKIP_DIR.test(e.path) && !e.path.endsWith(".d.ts") && !/\.min\.[cm]?js$/.test(e.path) && (e.size ?? 0) < 300_000);
  all.sort((a, b) => (a.size ?? 0) - (b.size ?? 0) || a.path.localeCompare(b.path));
  return { paths: all.slice(0, cap).map((e) => e.path), truncated: all.length > cap };
}

const lineOf = (sf: ts.SourceFile, n: ts.Node) => sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;
const lineText = (sf: ts.SourceFile, line: number) => sf.text.split("\n")[line - 1]?.trim().slice(0, 300) ?? "";
const strOf = (n: ts.Node): string | null => (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n) ? n.text : null);

function envName(n: ts.Expression): string | null {
  // process.env.NAME or process.env["NAME"]
  if (ts.isPropertyAccessExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === "env" && ts.isIdentifier(n.expression.expression) && n.expression.expression.text === "process") return n.name.text;
  if (ts.isElementAccessExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === "env" && ts.isIdentifier(n.expression.expression) && n.expression.expression.text === "process") return strOf(n.argumentExpression) ?? "?";
  return null;
}

/** The initializer of a `const` declared once in this file, if `id` names one. */
function constInit(sf: ts.SourceFile, name: string): ts.Expression | null {
  const found: ts.VariableDeclaration[] = [];
  const visit = (n: ts.Node) => { if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === name) found.push(n); ts.forEachChild(n, visit); };
  visit(sf);
  if (found.length !== 1) return null;
  const d = found[0];
  const list = d.parent;
  if (!ts.isVariableDeclarationList(list) || !(list.flags & ts.NodeFlags.Const) || !d.initializer) return null;
  return d.initializer;
}
function isFunctionDecl(sf: ts.SourceFile, name: string): boolean {
  let hit = false;
  const visit = (n: ts.Node) => { if (ts.isFunctionDeclaration(n) && n.name?.text === name) hit = true; if (!hit) ts.forEachChild(n, visit); };
  visit(sf);
  return hit;
}
const unwrap = (n: ts.Expression): ts.Expression => (ts.isParenthesizedExpression(n) || ts.isAsExpression(n) || ts.isNonNullExpression(n) || ts.isTypeAssertionExpression(n) || ts.isSatisfiesExpression(n) ? unwrap(n.expression) : n);

export function classifyArg(sf: ts.SourceFile, raw: ts.Expression | undefined, depth = 0): ArgKind {
  if (!raw) return { kind: "missing" };
  const n = unwrap(raw);
  const s = strOf(n);
  if (s != null) return { kind: "string", value: s };
  const env = envName(n);
  if (env) return { kind: "env", name: env, fallback: "none" };
  if (ts.isBinaryExpression(n) && (n.operatorToken.kind === ts.SyntaxKind.BarBarToken || n.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)) {
    const left = envName(unwrap(n.left));
    if (left) {
      const right = strOf(unwrap(n.right));
      const fallback = right != null && right.length > 0 ? (n.operatorToken.kind === ts.SyntaxKind.BarBarToken ? "or_literal" : "nullish_literal") : "other";
      return { kind: "env", name: left, fallback };
    }
  }
  if (ts.isArrowFunction(n) || ts.isFunctionExpression(n)) return { kind: "function" };
  if (ts.isCallExpression(n)) {
    const callee = n.expression;
    const name = ts.isPropertyAccessExpression(callee) ? callee.name.text : ts.isIdentifier(callee) ? callee.text : "";
    const p = n.arguments[0] ? strOf(unwrap(n.arguments[0])) : null;
    if ((name === "readFileSync") && p != null) return { kind: "read_file", path: p };
  }
  if (ts.isIdentifier(n) && depth < 3) {
    if (isFunctionDecl(sf, n.text)) return { kind: "function" };
    const init = constInit(sf, n.text);
    if (init) return classifyArg(sf, init, depth + 1);
  }
  return { kind: "unknown", text: n.getText(sf).slice(0, 120) };
}

function classifyOptions(sf: ts.SourceFile, raw: ts.Expression | undefined): OptionsKind {
  if (!raw) return { kind: "none" };
  let n = unwrap(raw);
  if (ts.isArrowFunction(n) || ts.isFunctionExpression(n)) return { kind: "none" }; // verify(token, key, callback)
  if (ts.isIdentifier(n)) { if (isFunctionDecl(sf, n.text)) return { kind: "none" }; const init = constInit(sf, n.text); if (init) n = unwrap(init); }
  if (!ts.isObjectLiteralExpression(n)) return { kind: "unknown", text: n.getText(sf).slice(0, 120) };
  const props: string[] = []; let algorithms: string[] | null = null; let algorithmsKnown = true;
  for (const p of n.properties) {
    if (ts.isSpreadAssignment(p)) { props.push("..."); algorithmsKnown = false; continue; }
    const name = p.name && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)) ? p.name.text : "?";
    props.push(name);
    if (name === "algorithms") {
      const v = ts.isPropertyAssignment(p) ? unwrap(p.initializer) : null;
      if (v && ts.isArrayLiteralExpression(v) && v.elements.every((e) => strOf(e) != null)) algorithms = v.elements.map((e) => strOf(e)!);
      else algorithmsKnown = false;
    }
  }
  return { kind: "object", props, algorithms, algorithmsKnown };
}

/** Calls to `methods` of `moduleName` in the given files, through import / require bindings. */
export function findModuleCalls(files: { path: string; text: string }[], moduleName: string, methods: string[]): ModuleUsage {
  const out: ModuleUsage = { calls: [], untracked: [], files_scanned: 0, parse_errors: [] };
  for (const f of files) {
    if (!f.text.includes(moduleName)) { out.files_scanned++; continue; } // a file that never names the module cannot bind it
    let sf: ts.SourceFile;
    try { sf = ts.createSourceFile(f.path, f.text, ts.ScriptTarget.Latest, true, /x$/.test(f.path) ? ts.ScriptKind.TSX : undefined); }
    catch (e) { out.parse_errors.push(`${f.path}: ${String(e).slice(0, 80)}`); continue; }
    out.files_scanned++;
    const test = TEST_PATH.test(f.path);
    const namespaces = new Set<string>(); const named = new Map<string, string>();
    const isModule = (n: ts.Node | undefined) => !!n && strOf(n) === moduleName;
    const isRequireOfModule = (n: ts.Expression | undefined): boolean => !!n && ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === "require" && isModule(n.arguments[0]);
    const bindings = (n: ts.Node) => {
      if (ts.isImportDeclaration(n) && isModule(n.moduleSpecifier) && n.importClause) {
        const c = n.importClause;
        if (c.name) namespaces.add(c.name.text);
        if (c.namedBindings && ts.isNamespaceImport(c.namedBindings)) namespaces.add(c.namedBindings.name.text);
        if (c.namedBindings && ts.isNamedImports(c.namedBindings)) for (const el of c.namedBindings.elements) named.set(el.name.text, (el.propertyName ?? el.name).text);
      }
      if (ts.isVariableDeclaration(n) && n.initializer && isRequireOfModule(unwrap(n.initializer))) {
        if (ts.isIdentifier(n.name)) namespaces.add(n.name.text);
        else if (ts.isObjectBindingPattern(n.name)) for (const el of n.name.elements) if (ts.isIdentifier(el.name)) named.set(el.name.text, (el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName : el.name).text);
      }
      // require() / import() whose result is not bound to a simple name, or of a computed module name
      if (ts.isCallExpression(n) && ((ts.isIdentifier(n.expression) && n.expression.text === "require") || n.expression.kind === ts.SyntaxKind.ImportKeyword) && n.arguments[0]) {
        const arg = n.arguments[0];
        const bound = ts.isVariableDeclaration(n.parent) || (ts.isParenthesizedExpression(n.parent) && ts.isVariableDeclaration(n.parent.parent));
        if ((isModule(arg) && !bound) || (strOf(arg) == null && !ts.isStringLiteral(arg))) {
          if (isModule(arg) || strOf(arg) == null) out.untracked.push({ file: f.path, line: lineOf(sf, n), quote: lineText(sf, lineOf(sf, n)), why: isModule(arg) ? "module loaded without a simple binding" : "dynamic require/import with a computed module name" });
        }
      }
      ts.forEachChild(n, bindings);
    };
    bindings(sf);
    if (!namespaces.size && !named.size) continue;
    const visit = (n: ts.Node) => {
      if (ts.isCallExpression(n)) {
        const callee = n.expression;
        let method: string | null = null;
        if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) && namespaces.has(callee.expression.text) && methods.includes(callee.name.text)) method = callee.name.text;
        else if (ts.isIdentifier(callee) && named.has(callee.text) && methods.includes(named.get(callee.text)!)) method = named.get(callee.text)!;
        if (method) {
          const line = lineOf(sf, n);
          out.calls.push({ file: f.path, line, quote: lineText(sf, line), method, test, key: classifyArg(sf, n.arguments[1]), options: classifyOptions(sf, n.arguments[2]) });
        }
      }
      // A namespace or named binding used other than as `ns.method(...)` / `fn(...)`: the analysis cannot follow it.
      if (ts.isIdentifier(n) && (namespaces.has(n.text) || named.has(n.text))) {
        const p = n.parent;
        const declaring = ts.isImportClause(p) || ts.isNamespaceImport(p) || ts.isImportSpecifier(p) || ((ts.isVariableDeclaration(p) || ts.isBindingElement(p)) && p.name === n);
        const asCallee = ts.isCallExpression(p) && p.expression === n;
        const asMember = ts.isPropertyAccessExpression(p) && p.expression === n;
        const calledMember = asMember && ts.isCallExpression(p.parent) && p.parent.expression === p;
        const tracked = declaring || (named.has(n.text) && asCallee) || (namespaces.has(n.text) && (calledMember || (asMember && !methods.includes((p as ts.PropertyAccessExpression).name.text))));
        if (!tracked) { const line = lineOf(sf, n); out.untracked.push({ file: f.path, line, quote: lineText(sf, line), why: `${n.text} is used in a way the analysis does not follow` }); }
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }
  return out;
}

/** PEM header type ("RSA PRIVATE KEY", "PUBLIC KEY", "DSA PRIVATE KEY", ...) of a key text, or null if it is not PEM. */
export function pemType(text: string): string | null {
  const m = /-----BEGIN ([A-Z0-9 ]+)-----/.exec(text);
  return m ? m[1] : null;
}
