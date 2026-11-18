// Read-only: print the source audit for the store this process is configured with (local .data/store.json when no
// Upstash variables are set). Usage: node --import tsx scripts/checks/source-audit.mts
process.env.AW_NO_PERSIST = "1"; // never write the local store file from this script
const { sourceAudit } = await import("../../lib/sources/audit");
console.log(JSON.stringify(await sourceAudit(), null, 2));
