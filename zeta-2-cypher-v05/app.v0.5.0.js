const ZETA_DIGITS = "16449340668482264364724151666460251892189499012067984377355582293700074704032008738336289006197587053040043189623371906796287246870050077879351029463308662768317333093677626050952510068721400547968115587948903608232777619198407564558769632356367097100969489020859320080516364788783388460444451840598251452506833876314227658793929588063204472197908477340910590208378289549278263890379763583343942045159120818099593454448774587965008808894087011116347106931614618428879815486244835909183448757387428394082760287563214346010013576620982048720690400073826635603024022844629630324566097171951427721315951255679986190871931543953524106380440721421339654750580158723165839947624349142243348362904887009665059862263034109596736552811371670326911498784034357161605776676333067252736894238416640889536227595400772794748127102520498378433230017165744810302860434966884794216728433597281997793810008466560780537782885947278625931618664588292160658193859232415325806461781201884649777625984977560609384606051467685834725623197101836301479837488962159297027632358745738223006797795679319515651996612383618366168655665797003758579395038193467059393114859491596635058620858526381064548879582000789743717215693657490825080352045741139287635530947709860823922939866707500525803645340315412739072742722890227479742157521265272866790504356086447019522174348296308095407209404388845394174205278719269341962282024749751511874134727875179936647336874820752335660885793907659619607908126511591050729219558844613572641252614751578071609175156885327683293665654765588128436115113494859670092266296975220677781810295008702914015225183747431377217755317906719967001114954768292364207502705341165049051072861188854707754573575854747032957919907087156125812402558853000196898875722439717953811180793070896494335953356183275794651103546695668292833094507406208425346300827605686180238175238239659462458207920249063737872085300479379967603565543851521312093605893490413075491311959041935877531888380567912171377264570722995635142812810658216832092872867483537830128254732917028021436897618019637363184980566899586355341068647425930801883367749469866838428949777402705311753583758607474169405737637153525165870187112803861643246178480126671392369158545043444646648471950875283006191625838679257789892298444165212547711817391890576286084578861368469335293800824741929432439323626468769086749231576094206150249840056930228249239061832435185795019030056175145835716574335223282351666140476391283940576264724881002052041812033788626252366555788937763981538291415976032314805706590691944583703140205153805821921917295905553978794000789946";
const ZETA_DECIMAL_DIGITS = ZETA_DIGITS.slice(1);
const MASK64 = (1n << 64n) - 1n;
const MAGIC = [0x5a, 0x32, 0x43, 0x32]; // Z2C2
const DEFAULT_ITERATIONS = 250000;
const MAX_MESSAGE_BYTES = 2000;

const $ = (id) => document.getElementById(id);
const refs = {
  messageInput: $('messageInput'),
  encodePassword: $('encodePassword'),
  decodePassword: $('decodePassword'),
  cipherOutput: $('cipherOutput'),
  cipherInput: $('cipherInput'),
  plainOutput: $('plainOutput'),
  statusText: $('statusText'),
};

function setStatus(message, type = '') {
  refs.statusText.textContent = message;
  refs.statusText.className = type;
}

function utf8Bytes(text) {
  return new TextEncoder().encode(text);
}

function rotl(x, k) {
  return ((x << BigInt(k)) | (x >> BigInt(64 - k))) & MASK64;
}

function read64(bytes, offset) {
  let v = 0n;
  for (let i = 0; i < 8; i++) v |= BigInt(bytes[offset + i] || 0) << BigInt(i * 8);
  return v & MASK64;
}

class Xoshiro256StarStar {
  constructor(seedBytes) {
    this.s = [read64(seedBytes, 0), read64(seedBytes, 8), read64(seedBytes, 16), read64(seedBytes, 24)];
    if (this.s.every(v => v === 0n)) this.s[0] = 0x9e3779b97f4a7c15n;
  }
  next() {
    const result = (rotl((this.s[1] * 5n) & MASK64, 7) * 9n) & MASK64;
    const t = (this.s[1] << 17n) & MASK64;
    this.s[2] ^= this.s[0];
    this.s[3] ^= this.s[1];
    this.s[1] ^= this.s[2];
    this.s[0] ^= this.s[3];
    this.s[2] ^= t;
    this.s[3] = rotl(this.s[3], 45);
    return result;
  }
}

function bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToBytes(str) {
  const clean = String(str || '').replace(/\s+/g, '');
  const binary = atob(clean);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function concatBytes(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let p = 0;
  for (const a of arrays) { out.set(a, p); p += a.length; }
  return out;
}

function uint32Bytes(n) {
  return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
}

function readUint32(bytes, pos) {
  return ((bytes[pos] << 24) | (bytes[pos + 1] << 16) | (bytes[pos + 2] << 8) | bytes[pos + 3]) >>> 0;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

async function deriveSeed(password, salt, iterations) {
  const material = await crypto.subtle.importKey('raw', utf8Bytes(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, material, 256);
  return new Uint8Array(bits);
}

function zetaDigit(line, digit, mix) {
  const m = BigInt(ZETA_DECIMAL_DIGITS.length);
  const idx = Number((BigInt(line) * 1315423911n + BigInt(digit) * 2654435761n + (mix & 0xffffffffn)) % m);
  return ZETA_DECIMAL_DIGITS.charCodeAt(idx) - 48;
}

function makeKeystream(length, seedBytes) {
  const rng = new Xoshiro256StarStar(seedBytes);
  const stream = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    let b = 0;
    for (let bit = 0; bit < 8; bit++) {
      const a = rng.next();
      const c = rng.next();
      const line = 1000000 + Number(a % 900000000n);
      const digit = 1 + Number(c % BigInt(Math.min(1800, ZETA_DECIMAL_DIGITS.length - 1)));
      const invert = Number((c >> 23n) & 1n);
      const zd = zetaDigit(line, digit, a ^ c);
      const bitVal = (zd & 1) ^ invert;
      b |= bitVal << bit;
    }
    stream[i] = b;
  }
  return stream;
}

function xorBytes(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function parsePackage(text) {
  let pkg;
  try { pkg = JSON.parse(text); }
  catch { throw new Error('ZETA DATAが正しくありません。'); }

  const marker = pkg.z || pkg.type || pkg.magic;
  if (marker !== 'ZETA2' && marker !== 'ZETA2CYPHER') throw new Error('ZETA DATAが正しくありません。');

  const salt = pkg.salt || pkg.s || (pkg.kdf && pkg.kdf.salt);
  const iterations = pkg.n || (pkg.kdf && pkg.kdf.iterations) || DEFAULT_ITERATIONS;
  const data = pkg.data || pkg.d || pkg.cipher;

  if (!salt || !data) throw new Error('ZETA DATAが正しくありません。');
  return { salt, iterations: Number(iterations), data };
}


async function encode() {
  try {
    const password = refs.encodePassword.value;
    const message = refs.messageInput.value;
    if (!message) throw new Error('文章を入力してください。');
    if (!password) throw new Error('パスワードを入力してください。');

    const messageBytes = utf8Bytes(message);
    if (messageBytes.length > MAX_MESSAGE_BYTES) {
      throw new Error(`${MAX_MESSAGE_BYTES} bytes以内にしてください。`);
    }

    setStatus('生成中…');
    refs.cipherOutput.value = '';

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const seed = await deriveSeed(password, salt, DEFAULT_ITERATIONS);
    const digest = (await sha256(messageBytes)).slice(0, 8);
    const payload = concatBytes(new Uint8Array(MAGIC), uint32Bytes(messageBytes.length), digest, messageBytes);
    const stream = makeKeystream(payload.length, seed);
    const cipher = xorBytes(payload, stream);

    const pkg = {
      type: 'ZETA2',
      version: 5,
      salt: bytesToBase64(salt),
      length: messageBytes.length,
      data: bytesToBase64(cipher)
    };

    refs.cipherOutput.value = JSON.stringify(pkg, null, 2);
    setStatus('生成しました。', 'ok');
  } catch (err) {
    setStatus(err.message || String(err), 'error');
  }
}

async function decode() {
  try {
    const password = refs.decodePassword.value;
    const text = refs.cipherInput.value.trim();
    if (!text) throw new Error('ZETA DATAを入力してください。');
    if (!password) throw new Error('パスワードを入力してください。');

    setStatus('復号中…');
    refs.plainOutput.value = '';

    const pkg = parsePackage(text);
    const salt = base64ToBytes(pkg.salt);
    const iterations = pkg.iterations;
    const cipher = base64ToBytes(pkg.data);
    const seed = await deriveSeed(password, salt, iterations);
    const stream = makeKeystream(cipher.length, seed);
    const plain = xorBytes(cipher, stream);

    for (let i = 0; i < MAGIC.length; i++) {
      if (plain[i] !== MAGIC[i]) throw new Error('復号できません。');
    }

    const len = readUint32(plain, 4);
    if (len > plain.length - 16) throw new Error('復号できません。');

    const digest = plain.slice(8, 16);
    const msgBytes = plain.slice(16, 16 + len);
    const check = (await sha256(msgBytes)).slice(0, 8);
    for (let i = 0; i < 8; i++) {
      if (digest[i] !== check[i]) throw new Error('復号できません。');
    }

    refs.plainOutput.value = new TextDecoder('utf-8', { fatal: true }).decode(msgBytes);
    setStatus('復号しました。', 'ok');
  } catch (err) {
    // Decode failure must never change cipherInput. This allows retrying with the correct password.
    refs.plainOutput.value = '';
    setStatus(err.message || String(err), 'error');
  }
}

async function copyText(text, okMessage) {
  if (!text) { setStatus('コピーする内容がありません。', 'error'); return; }
  try {
    await navigator.clipboard.writeText(text);
    setStatus(okMessage, 'ok');
  } catch {
    setStatus('コピーできませんでした。', 'error');
  }
}

function downloadCipher() {
  const text = refs.cipherOutput.value.trim();
  if (!text) { setStatus('保存する内容がありません。', 'error'); return; }
  const blob = new Blob([text], { type: 'application/json;charset=utf-8' });
  const a = document.createElement('a');
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  a.href = URL.createObjectURL(blob);
  a.download = `zeta-${stamp}.zeta`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
  setStatus('保存しました。', 'ok');
}

async function loadCipherFile(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  refs.cipherInput.value = await file.text();
  refs.plainOutput.value = '';
  setStatus('読み込みました。', 'ok');
  event.target.value = '';
}

function togglePassword(input, button) {
  const showing = input.type === 'text';
  input.type = showing ? 'password' : 'text';
  button.textContent = showing ? '表示' : '隠す';
}

async function cleanupOldServiceWorkers() {
  if (!('serviceWorker' in navigator)) return;
  try {
    const regs = await navigator.serviceWorker.getRegistrations();
    for (const reg of regs) await reg.unregister();
    if ('caches' in window) {
      const keys = await caches.keys();
      await Promise.all(keys.map(key => caches.delete(key)));
    }
  } catch {}
}

$('encodeBtn').addEventListener('click', encode);
$('decodeBtn').addEventListener('click', decode);
$('copyCipherBtn').addEventListener('click', () => copyText(refs.cipherOutput.value, 'コピーしました。'));
$('copyPlainBtn').addEventListener('click', () => copyText(refs.plainOutput.value, 'コピーしました。'));
$('downloadCipherBtn').addEventListener('click', downloadCipher);
$('moveToDecodeBtn').addEventListener('click', () => {
  if (!refs.cipherOutput.value.trim()) { setStatus('ZETA DATAがありません。', 'error'); return; }
  refs.cipherInput.value = refs.cipherOutput.value;
  refs.plainOutput.value = '';
  setStatus('復号へ移しました。', 'ok');
});
$('loadCipherFile').addEventListener('change', loadCipherFile);
$('clearEncodeBtn').addEventListener('click', () => {
  refs.messageInput.value = '';
  refs.cipherOutput.value = '';
  setStatus('クリアしました。');
});
$('clearDecodeBtn').addEventListener('click', () => {
  refs.cipherInput.value = '';
  refs.plainOutput.value = '';
  setStatus('クリアしました。');
});
$('showEncodePassword').addEventListener('click', () => togglePassword(refs.encodePassword, $('showEncodePassword')));
$('showDecodePassword').addEventListener('click', () => togglePassword(refs.decodePassword, $('showDecodePassword')));

cleanupOldServiceWorkers();
