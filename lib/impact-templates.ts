// Plain-language impact templates, chosen by keywords in an advisory's own text. No model is involved: the same
// advisory always gets the same wording. Used for alert titles (lib/claim-rules.ts) and for the template impact
// walkthrough (lib/simulate.ts). Every sentence describes what COULD happen; none claims that it did.
export type ImpactKind = "code_execution" | "injection" | "script_injection" | "auth_bypass" | "token_forgery" | "file_access" | "server_side_request" | "denial_of_service" | "data_exposure" | "object_tampering" | "generic";

export type ImpactTemplate = {
  kind: ImpactKind;
  /** At most 8 everyday words, for a non-expert. */
  title: string;
  /** What an attacker would do, in plain words. Never a technique or payload. */
  attacker: string;
  /** What the application would then do. */
  app: string;
  /** What that could mean for the people using the application. */
  consequence: string;
};

const T: { test: RegExp; t: ImpactTemplate }[] = [
  { test: /remote code execution|\brce\b|arbitrary code|code execution|command injection|execute (arbitrary )?commands?|deserializ/i, t: { kind: "code_execution", title: "Attackers could run code on your server", attacker: "Someone sends your app a specially prepared request.", app: "The affected package treats part of that request as instructions and runs them on your server.", consequence: "Data on the server could be read or changed, and the server could be used to reach other systems." } },
  { test: /sql injection|\bsqli\b|nosql injection|query injection/i, t: { kind: "injection", title: "Attackers could read or change your database", attacker: "Someone types specially prepared text into a field your app sends to its database.", app: "The affected package passes that text to the database as part of a query.", consequence: "Stored records, including other users' data, could be read, changed or deleted." } },
  { test: /cross[- ]site scripting|\bxss\b|html injection|script injection/i, t: { kind: "script_injection", title: "Attackers could run scripts in users' browsers", attacker: "Someone plants specially prepared content where your app will display it.", app: "The affected package shows that content to other visitors without making it harmless.", consequence: "A visitor's session could be used without their knowledge, or the page they see could be altered." } },
  { test: /signature|\bjwt\b|json web token|forg(e|ed|ery)|token (validation|verification)/i, t: { kind: "token_forgery", title: "Your login tokens could be forged", attacker: "Someone presents a login token they made themselves.", app: "The affected package accepts the token as genuine.", consequence: "That person could act as another user, including one with more permissions." } },
  { test: /authenticat|authoriz|authoris|access control|privilege escalation|bypass|permission check|middleware/i, t: { kind: "auth_bypass", title: "Attackers could bypass login or permission checks", attacker: "Someone sends a request shaped to skip a check.", app: "The affected package lets the request through without the usual login or permission check.", consequence: "Pages or data meant for signed-in or authorised users could be reached by others." } },
  { test: /path traversal|directory traversal|arbitrary file (read|write)|file (disclosure|inclusion)|zip slip/i, t: { kind: "file_access", title: "Attackers could read files they should not", attacker: "Someone asks your app for a file using a specially prepared name.", app: "The affected package looks outside the folder it was meant to stay in.", consequence: "Configuration, source code or stored secrets on the server could be exposed." } },
  { test: /server[- ]side request forgery|\bssrf\b/i, t: { kind: "server_side_request", title: "Your server could be tricked into calling internal systems", attacker: "Someone gives your app an address to fetch.", app: "The affected package fetches it from inside your network.", consequence: "Internal services that are not meant to be public could be reached or probed." } },
  { test: /denial[- ]of[- ]service|\bdos\b|\bredos\b|resource exhaustion|infinite loop|out[- ]of[- ]memory|crash|uncontrolled (resource|recursion)/i, t: { kind: "denial_of_service", title: "Attackers could crash or slow your service", attacker: "Someone sends input that is very expensive to process.", app: "The affected package spends its time or memory on that input.", consequence: "Your app could become slow or unavailable for everyone until it recovers." } },
  { test: /prototype pollution|mass assignment|object injection/i, t: { kind: "object_tampering", title: "Attackers could change how your app behaves", attacker: "Someone sends data with unexpected fields.", app: "The affected package copies those fields into settings the rest of the app relies on.", consequence: "Checks elsewhere in the app could stop working as intended." } },
  { test: /information (disclosure|exposure|leak)|sensitive (data|information)|leak|expos(e|ed|ure)|disclos/i, t: { kind: "data_exposure", title: "Private data could leak", attacker: "Someone makes an ordinary-looking request.", app: "The affected package includes information in its answer that should have stayed private.", consequence: "Details about users or about the system could be seen by people who should not see them." } },
];

const GENERIC: ImpactTemplate = { kind: "generic", title: "A package you use has a security flaw", attacker: "Someone uses the flaw described in the advisory.", app: "The affected package behaves in a way its authors did not intend.", consequence: "The effect depends on how your app uses the package; the advisory describes what is possible." };

/** The first template whose keywords appear in the advisory text; a neutral one otherwise. */
export function impactFor(text: string | null | undefined): ImpactTemplate {
  const s = text ?? "";
  return T.find((x) => x.test.test(s))?.t ?? GENERIC;
}
