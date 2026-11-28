// What SaveBell shows for each rule in rules/savebell.yml. The text comes from here, never from the runner, and a result
// for a rule id not listed here is dropped. Every result is a "Possible issue": the pattern can be unsafe, but input may
// be validated elsewhere (middleware, an allowlist, a gateway), so SaveBell never calls it confirmed.
export type ScanRule = { id: string; title: string; cwe: string; why: string; fix: string };

export const SCAN_RULES: ScanRule[] = [
  { id: "savebell.js-eval", title: "Code built at runtime is executed", cwe: "CWE-95", why: "If any part of the text comes from a user, they could run their own code on your server.", fix: "Avoid eval and new Function; parse data with JSON.parse or use a lookup table." },
  { id: "savebell.js-shell-exec", title: "Shell command built from a variable", cwe: "CWE-78", why: "If the variable can contain user input, it could run other commands on your server.", fix: "Use execFile or spawn with an argument list instead of one command string." },
  { id: "savebell.js-sql-concat", title: "SQL query built by joining strings", cwe: "CWE-89", why: "If the variable can contain user input, it could read or change your database (SQL injection).", fix: "Pass values as query parameters (placeholders) instead of joining them into the SQL text." },
  { id: "savebell.js-cors-any-origin-credentials", title: "Any website may call this API with the user's cookies", cwe: "CWE-942", why: "Another site could make requests as a signed-in user and read the answers.", fix: "List the exact origins that may call the API instead of allowing all of them." },
  { id: "savebell.py-eval", title: "Code built at runtime is executed", cwe: "CWE-95", why: "If any part of the text comes from a user, they could run their own code on your server.", fix: "Avoid eval and exec; parse data with json.loads or ast.literal_eval." },
  { id: "savebell.py-shell-true", title: "Command run through the shell with a variable", cwe: "CWE-78", why: "If the value can contain user input, it could run other commands on your server.", fix: "Pass an argument list without shell=True." },
  { id: "savebell.py-sql-format", title: "SQL query built with string formatting", cwe: "CWE-89", why: "If the value can contain user input, it could read or change your database (SQL injection).", fix: "Use query parameters, e.g. cursor.execute(\"... WHERE id = %s\", (value,))." },
];

export const ruleById = (id: string) => SCAN_RULES.find((r) => r.id === id) ?? null;
