// account-kernel K1 probe (throwaway spike). Runs inside the kernel iframe.
// Exposes a postMessage API against BOTH IndexedDB and OPFS so K1 can see whether
// a same-site subdomain embed shares storage (unpartitioned) or not (partitioned).
//
// NOTE ON TRUST: a real kernel would verify e.origin against an allowlist before
// acting. This probe accepts any parent and simply reports its own origin, because
// the whole point of K1 is to observe the storage-partition behaviour, not to model
// the access-control boundary (that is K2 / H6).

const logEl = document.getElementById("log");
function log(...a) {
  const line = a.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join(" ");
  logEl.textContent += line + "\n";
  // eslint-disable-next-line no-console
  console.log("[kernel]", ...a);
}

// --- IndexedDB store ---
const DB_NAME = "account-kernel-k1";
const STORE = "kv";
function idbOpen() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function idbPut(key, val) {
  const db = await idbOpen();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(val, key);
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
  db.close();
}
async function idbGet(key) {
  const db = await idbOpen();
  const val = await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const r = tx.objectStore(STORE).get(key);
    r.onsuccess = () => resolve(r.result ?? null);
    r.onerror = () => reject(r.error);
  });
  db.close();
  return val;
}

// --- OPFS store (async main-thread API; no worker/sync handle needed for K1) ---
async function opfsWrite(key, val) {
  const root = await navigator.storage.getDirectory();
  const fh = await root.getFileHandle(`k1-${key}.txt`, { create: true });
  const w = await fh.createWritable();
  await w.write(String(val));
  await w.close();
}
async function opfsRead(key) {
  try {
    const root = await navigator.storage.getDirectory();
    const fh = await root.getFileHandle(`k1-${key}.txt`, { create: false });
    const f = await fh.getFile();
    return await f.text();
  } catch (e) {
    if (e && e.name === "NotFoundError") return null;
    throw e;
  }
}

async function handle(op, key, val) {
  if (op === "whoami") {
    let estimate = null;
    try { estimate = await navigator.storage?.estimate?.(); } catch { /* ignore */ }
    return { origin: location.origin, secureContext: isSecureContext, estimate };
  }
  if (op === "write") {
    const out = {};
    try { await idbPut(key, val); out.idb = "written"; } catch (e) { out.idb = "ERR " + e; }
    try { await opfsWrite(key, val); out.opfs = "written"; } catch (e) { out.opfs = "ERR " + e; }
    out.wrote = val;
    return out;
  }
  if (op === "read") {
    const out = {};
    try { out.idb = await idbGet(key); } catch (e) { out.idb = "ERR " + e; }
    try { out.opfs = await opfsRead(key); } catch (e) { out.opfs = "ERR " + e; }
    return out;
  }
  return { error: "unknown op " + op };
}

window.addEventListener("message", async (e) => {
  const msg = e.data || {};
  if (!msg || typeof msg.op !== "string") return;
  const result = await handle(msg.op, msg.key, msg.val).catch((err) => ({ error: String(err) }));
  log(msg.op, msg.key ?? "", "->", result);
  e.source.postMessage(
    { id: msg.id, op: msg.op, result, kernelOrigin: location.origin },
    e.origin === "null" ? "*" : e.origin,
  );
});

log("kernel ready", location.origin, "secureContext=" + isSecureContext);
try { parent.postMessage({ ready: true, kernelOrigin: location.origin }, "*"); } catch { /* top-level */ }
