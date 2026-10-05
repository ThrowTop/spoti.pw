// Pinned upstream patcher snapshot (2026-10-05); local SHA-256 base check added.
// scripts/patcher-cli.ts
import { createWriteStream, createReadStream, openAsBlob } from "node:fs";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

// lib/patcher/macho.ts
var MH_MAGIC_64 = 4277009103;
var LC_SEGMENT_64 = 25;
var LC_LOAD_DYLIB = 12;
var LC_LOAD_WEAK_DYLIB = 2147483672;
var LC_REEXPORT_DYLIB = 2147483679;
var LC_LOAD_UPWARD_DYLIB = 2147483683;
var LC_RPATH = 2147483676;
var LC_ENCRYPTION_INFO_64 = 44;
var HEADER = 32;
var DYLIB_COMMANDS = /* @__PURE__ */ new Set([LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB]);
function view(bytes) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}
function cString(bytes, start, end) {
  let stop = start;
  while (stop < end && bytes[stop] !== 0) stop++;
  return new TextDecoder().decode(bytes.subarray(start, stop));
}
function checkMagic(bytes) {
  const magic = view(bytes).getUint32(0, true);
  if (magic === MH_MAGIC_64) return;
  if (magic === 3199925962 || magic === 3216703178) throw new Error("the app's binary holds several architectures");
  throw new Error("the app's binary is not a 64-bit Mach-O");
}
function headerSpan(first, extra = 0) {
  checkMagic(first);
  return HEADER + view(first).getUint32(20, true) + extra;
}
function readMachO(bytes) {
  checkMagic(bytes);
  const v = view(bytes);
  const ncmds = v.getUint32(16, true);
  const result = { encrypted: false, dylibs: [], rpaths: [], firstSection: Infinity };
  let off = HEADER;
  for (let i = 0; i < ncmds; i++) {
    const cmd = v.getUint32(off, true);
    const size = v.getUint32(off + 4, true);
    if (DYLIB_COMMANDS.has(cmd)) result.dylibs.push(cString(bytes, off + v.getUint32(off + 8, true), off + size));
    else if (cmd === LC_RPATH) result.rpaths.push(cString(bytes, off + v.getUint32(off + 8, true), off + size));
    else if (cmd === LC_ENCRYPTION_INFO_64) result.encrypted ||= v.getUint32(off + 16, true) !== 0;
    else if (cmd === LC_SEGMENT_64) {
      const sections = v.getUint32(off + 64, true);
      for (let s = 0; s < sections; s++) {
        const offset = v.getUint32(off + 72 + s * 80 + 48, true);
        if (offset) result.firstSection = Math.min(result.firstSection, offset);
      }
    }
    off += size;
  }
  return result;
}
function command(cmd, fixed, text2, fields) {
  const raw = new TextEncoder().encode(text2);
  const size = fixed + raw.length + 1 + 7 & ~7;
  const out = new Uint8Array(size);
  const v = view(out);
  v.setUint32(0, cmd, true);
  v.setUint32(4, size, true);
  v.setUint32(8, fixed, true);
  fields.forEach((field, i) => v.setUint32(12 + i * 4, field, true));
  out.set(raw, fixed);
  return out;
}
var weakDylib = (name2) => command(LC_LOAD_WEAK_DYLIB, 24, name2, [0, 0, 0]);
var rpath = (path2) => command(LC_RPATH, 12, path2, []);
function roomFor(dylibs, path2) {
  return dylibs.reduce((sum, d) => sum + weakDylib(d).length, 0) + (path2 ? rpath(path2).length : 0);
}
function addLoadCommands(bytes, dylibs, path2) {
  const info = readMachO(bytes);
  const commands = [];
  if (path2 && !info.rpaths.includes(path2)) commands.push([path2, rpath(path2)]);
  for (const dylib of dylibs) if (!info.dylibs.includes(dylib)) commands.push([dylib, weakDylib(dylib)]);
  if (!commands.length) return [];
  const v = view(bytes);
  let ncmds = v.getUint32(16, true);
  let sizeofcmds = v.getUint32(20, true);
  for (const [name2, cmd] of commands) {
    const end = HEADER + sizeofcmds;
    if (end + cmd.length > Math.min(info.firstSection, bytes.length) || bytes.subarray(end, end + cmd.length).some((b) => b)) {
      throw new Error(`no room in the binary for ${name2}`);
    }
    bytes.set(cmd, end);
    ncmds += 1;
    sizeofcmds += cmd.length;
  }
  v.setUint32(16, ncmds, true);
  v.setUint32(20, sizeofcmds, true);
  return commands.map(([name2]) => name2);
}

// lib/patcher/plist.ts
var APPLE_EPOCH = Date.UTC(2001, 0, 1);
function readBinary(bytes) {
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const trailer = bytes.length - 32;
  const offsetSize = bytes[trailer + 6];
  const refSize = bytes[trailer + 7];
  const count = Number(v.getBigUint64(trailer + 8));
  const top = Number(v.getBigUint64(trailer + 16));
  const table = Number(v.getBigUint64(trailer + 24));
  const uint = (at, size) => {
    let n = 0;
    for (let i = 0; i < size; i++) n = n * 256 + bytes[at + i];
    return n;
  };
  const offsetOf = (ref) => uint(table + ref * offsetSize, offsetSize);
  const object = (ref, depth) => {
    if (ref >= count || depth > 64) throw new Error("broken binary plist");
    let at = offsetOf(ref);
    const marker = bytes[at];
    const type = marker >> 4;
    const info = marker & 15;
    const length = () => {
      if (info !== 15) return info;
      const intMarker = bytes[at + 1];
      const size = 1 << (intMarker & 15);
      const n = uint(at + 2, size);
      at += 1 + size;
      return n;
    };
    switch (type) {
      case 0:
        if (info === 8) return false;
        if (info === 9) return true;
        throw new Error("unsupported binary plist value");
      case 1: {
        const size = 1 << info;
        if (size === 8) return v.getBigInt64(at + 1);
        if (size === 16) return v.getBigInt64(at + 9);
        return BigInt(uint(at + 1, size));
      }
      case 2:
        return info === 2 ? v.getFloat32(at + 1) : v.getFloat64(at + 1);
      case 3:
        return new Date(APPLE_EPOCH + v.getFloat64(at + 1) * 1e3);
      case 4: {
        const n = length();
        return bytes.slice(at + 1, at + 1 + n);
      }
      case 5: {
        const n = length();
        return new TextDecoder("latin1").decode(bytes.subarray(at + 1, at + 1 + n));
      }
      case 6: {
        const n = length();
        let s = "";
        for (let i = 0; i < n; i++) s += String.fromCharCode(v.getUint16(at + 1 + i * 2));
        return s;
      }
      case 8:
        return { CF$UID: BigInt(uint(at + 1, info + 1)) };
      case 10: {
        const n = length();
        const out = [];
        for (let i = 0; i < n; i++) out.push(object(uint(at + 1 + i * refSize, refSize), depth + 1));
        return out;
      }
      case 13: {
        const n = length();
        const out = {};
        for (let i = 0; i < n; i++) {
          const key = object(uint(at + 1 + i * refSize, refSize), depth + 1);
          if (typeof key !== "string") throw new Error("binary plist key is not a string");
          out[key] = object(uint(at + 1 + (n + i) * refSize, refSize), depth + 1);
        }
        return out;
      }
    }
    throw new Error(`unsupported binary plist type ${type}`);
  };
  return object(top, 0);
}
function unescapeXml(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (_, e) => {
    const lower = e.toLowerCase();
    if (lower === "amp") return "&";
    if (lower === "lt") return "<";
    if (lower === "gt") return ">";
    if (lower === "quot") return '"';
    if (lower === "apos") return "'";
    return String.fromCodePoint(lower.startsWith("#x") ? parseInt(lower.slice(2), 16) : parseInt(lower.slice(1), 10));
  });
}
function readXml(text2) {
  const tags = /<(\/?)([a-zA-Z]+)(?:\s+[^>]*?)?\s*(\/?)>|<!\[CDATA\[([\s\S]*?)\]\]>|<!--[\s\S]*?-->|<[?!][^>]*>|([^<]+)/g;
  const tokens = [];
  for (const m of text2.matchAll(tags)) {
    if (m[2]) tokens.push({ close: m[1] === "/", name: m[2], empty: m[3] === "/" });
    else if (m[4] !== void 0) tokens.push({ text: m[4] });
    else if (m[5] !== void 0) tokens.push({ text: unescapeXml(m[5]) });
  }
  let i = 0;
  const skipSpace = () => {
    while (i < tokens.length && "text" in tokens[i] && !tokens[i].text.trim()) i++;
  };
  const textUntil = (name2) => {
    let s = "";
    while (i < tokens.length) {
      const t = tokens[i++];
      if ("text" in t) s += t.text;
      else if (t.close && t.name === name2) return s;
      else throw new Error(`unexpected <${t.name}> in <${name2}>`);
    }
    throw new Error(`unclosed <${name2}>`);
  };
  const value = () => {
    skipSpace();
    const t = tokens[i++];
    if (!t || "text" in t || t.close) throw new Error("broken XML plist");
    switch (t.name) {
      case "dict": {
        const out = {};
        if (t.empty) return out;
        for (; ; ) {
          skipSpace();
          const k = tokens[i];
          if (k && !("text" in k) && k.close && k.name === "dict") return i++, out;
          if (!k || "text" in k || k.name !== "key") throw new Error("expected <key>");
          i++;
          const key = k.empty ? "" : textUntil("key");
          out[key] = value();
        }
      }
      case "array": {
        const out = [];
        if (t.empty) return out;
        for (; ; ) {
          skipSpace();
          const k = tokens[i];
          if (k && !("text" in k) && k.close && k.name === "array") return i++, out;
          out.push(value());
        }
      }
      case "string":
        return t.empty ? "" : textUntil("string");
      case "integer":
        return BigInt(textUntil("integer").trim());
      case "real":
        return Number(textUntil("real").trim());
      case "true":
        if (!t.empty) textUntil("true");
        return true;
      case "false":
        if (!t.empty) textUntil("false");
        return false;
      case "date":
        return new Date(textUntil("date").trim());
      case "data": {
        const b64 = t.empty ? "" : textUntil("data").replace(/\s+/g, "");
        return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
      }
      case "plist":
        return value();
    }
    throw new Error(`unsupported plist tag <${t.name}>`);
  };
  return value();
}
function parsePlist(bytes) {
  if (new TextDecoder("latin1").decode(bytes.subarray(0, 8)) === "bplist00") return readBinary(bytes);
  return readXml(new TextDecoder().decode(bytes));
}
function escapeXml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function base64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 32768) s += String.fromCharCode(...bytes.subarray(i, i + 32768));
  return btoa(s);
}
function writeValue(value, indent) {
  if (typeof value === "string") return `${indent}<string>${escapeXml(value)}</string>`;
  if (typeof value === "boolean") return `${indent}<${value}/>`;
  if (typeof value === "bigint") return `${indent}<integer>${value}</integer>`;
  if (typeof value === "number") return `${indent}<real>${value}</real>`;
  if (value instanceof Date) return `${indent}<date>${value.toISOString().replace(/\.\d{3}Z$/, "Z")}</date>`;
  if (value instanceof Uint8Array) return `${indent}<data>${base64(value)}</data>`;
  const inner = indent + "	";
  if (Array.isArray(value)) {
    if (!value.length) return `${indent}<array/>`;
    return `${indent}<array>
${value.map((v) => writeValue(v, inner)).join("\n")}
${indent}</array>`;
  }
  const keys = Object.keys(value);
  if (!keys.length) return `${indent}<dict/>`;
  const body = keys.map((k) => `${inner}<key>${escapeXml(k)}</key>
${writeValue(value[k], inner)}`).join("\n");
  return `${indent}<dict>
${body}
${indent}</dict>`;
}
function writePlist(value) {
  return new TextEncoder().encode(
    `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
${writeValue(value, "")}
</plist>
`
  );
}
function fromJson(value) {
  if (typeof value === "number") return Number.isInteger(value) ? BigInt(value) : value;
  if (Array.isArray(value)) return value.map(fromJson);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, fromJson(v)]));
  }
  return value;
}

// lib/patcher/zip.ts
var STORE = 0;
var DEFLATE = 8;
var UTF8 = 1 << 11;
var DESCRIPTOR = 1 << 3;
var MADE_BY_UNIX = 3 << 8 | 30;
var inflater = () => new DecompressionStream("deflate-raw");
var deflater = () => new CompressionStream("deflate-raw");
async function bytesOf(blob2) {
  return new Uint8Array(await blob2.arrayBuffer());
}
function view2(bytes) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}
async function readZip(blob2) {
  const tailStart = Math.max(0, blob2.size - 65557);
  const tail = await bytesOf(blob2.slice(tailStart));
  const t = view2(tail);
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (t.getUint32(i, true) === 101010256) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("not a ZIP archive");
  let count = t.getUint16(eocd + 10, true);
  let cdSize = t.getUint32(eocd + 12, true);
  let cdOffset = t.getUint32(eocd + 16, true);
  if (count === 65535 || cdSize === 4294967295 || cdOffset === 4294967295) {
    const locator = eocd - 20;
    if (locator < 0 || t.getUint32(locator, true) !== 117853008) throw new Error("broken ZIP64 archive");
    const record = view2(await bytesOf(blob2.slice(Number(t.getBigUint64(locator + 8, true)), blob2.size)));
    if (record.getUint32(0, true) !== 101075792) throw new Error("broken ZIP64 archive");
    count = Number(record.getBigUint64(32, true));
    cdSize = Number(record.getBigUint64(40, true));
    cdOffset = Number(record.getBigUint64(48, true));
  }
  const cd = await bytesOf(blob2.slice(cdOffset, cdOffset + cdSize));
  const c = view2(cd);
  const decoder = new TextDecoder();
  const entries = [];
  let p = 0;
  for (let i = 0; i < count; i++) {
    if (c.getUint32(p, true) !== 33639248) throw new Error("broken ZIP central directory");
    const nameLength = c.getUint16(p + 28, true);
    const extraLength = c.getUint16(p + 30, true);
    const commentLength = c.getUint16(p + 32, true);
    const nameBytes = cd.slice(p + 46, p + 46 + nameLength);
    const entry = {
      name: decoder.decode(nameBytes),
      nameBytes,
      madeBy: c.getUint16(p + 4, true),
      flags: c.getUint16(p + 8, true),
      method: c.getUint16(p + 10, true),
      time: c.getUint16(p + 12, true),
      date: c.getUint16(p + 14, true),
      crc: c.getUint32(p + 16, true),
      compressedSize: c.getUint32(p + 20, true),
      size: c.getUint32(p + 24, true),
      externalAttrs: c.getUint32(p + 38, true),
      localOffset: c.getUint32(p + 42, true)
    };
    let e = p + 46 + nameLength;
    const extraEnd = e + extraLength;
    while (e + 4 <= extraEnd) {
      const id = c.getUint16(e, true);
      const length = c.getUint16(e + 2, true);
      if (id === 1) {
        let q = e + 4;
        if (entry.size === 4294967295) entry.size = Number(c.getBigUint64(q, true)), q += 8;
        if (entry.compressedSize === 4294967295) entry.compressedSize = Number(c.getBigUint64(q, true)), q += 8;
        if (entry.localOffset === 4294967295) entry.localOffset = Number(c.getBigUint64(q, true));
      }
      e += 4 + length;
    }
    entries.push(entry);
    p = extraEnd + commentLength;
  }
  return entries;
}
async function dataOf(blob2, entry) {
  const header = view2(await bytesOf(blob2.slice(entry.localOffset, entry.localOffset + 30)));
  if (header.getUint32(0, true) !== 67324752) throw new Error(`broken ZIP entry ${entry.name}`);
  const start = entry.localOffset + 30 + header.getUint16(26, true) + header.getUint16(28, true);
  return blob2.slice(start, start + entry.compressedSize);
}
async function streamOf(blob2, entry) {
  const data = (await dataOf(blob2, entry)).stream();
  if (entry.method === STORE) return data;
  if (entry.method === DEFLATE) return data.pipeThrough(inflater());
  throw new Error(`${entry.name} uses compression method ${entry.method}`);
}
async function readEntry(blob2, entry) {
  return new Uint8Array(await new Response(await streamOf(blob2, entry)).arrayBuffer());
}
var CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 3988292384 ^ c >>> 1 : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();
function crc32(bytes, crc = 0) {
  let c = ~crc;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 255] ^ c >>> 8;
  return ~c >>> 0;
}
function dosTime(now) {
  return {
    time: now.getHours() << 11 | now.getMinutes() << 5 | now.getSeconds() >> 1,
    date: now.getFullYear() - 1980 << 9 | now.getMonth() + 1 << 5 | now.getDate()
  };
}
var ZipWriter = class {
  parts = [];
  central = [];
  offset = 0;
  stamp = dosTime(/* @__PURE__ */ new Date());
  get count() {
    return this.central.length;
  }
  push(meta, data) {
    const flags = meta.flags & ~DESCRIPTOR;
    const version = meta.method === DEFLATE ? 20 : 10;
    const n = meta.nameBytes.length;
    if (this.offset > 4294967295) throw new Error("the IPA would be over 4 GB");
    const local = new Uint8Array(30 + n);
    const l = view2(local);
    l.setUint32(0, 67324752, true);
    l.setUint16(4, version, true);
    l.setUint16(6, flags, true);
    l.setUint16(8, meta.method, true);
    l.setUint16(10, meta.time, true);
    l.setUint16(12, meta.date, true);
    l.setUint32(14, meta.crc, true);
    l.setUint32(18, meta.compressedSize, true);
    l.setUint32(22, meta.size, true);
    l.setUint16(26, n, true);
    local.set(meta.nameBytes, 30);
    const central = new Uint8Array(46 + n);
    const c = view2(central);
    c.setUint32(0, 33639248, true);
    c.setUint16(4, meta.madeBy, true);
    c.setUint16(6, version, true);
    c.setUint16(8, flags, true);
    c.setUint16(10, meta.method, true);
    c.setUint16(12, meta.time, true);
    c.setUint16(14, meta.date, true);
    c.setUint32(16, meta.crc, true);
    c.setUint32(20, meta.compressedSize, true);
    c.setUint32(24, meta.size, true);
    c.setUint16(28, n, true);
    c.setUint32(38, meta.externalAttrs, true);
    c.setUint32(42, this.offset, true);
    central.set(meta.nameBytes, 46);
    this.parts.push(local, ...data);
    this.central.push(central);
    this.offset += local.length + meta.compressedSize;
  }
  // An entry of another archive, its compressed bytes copied as they are.
  async copy(from, entry, name2) {
    const data = await dataOf(from, entry);
    const nameBytes = name2 === void 0 ? entry.nameBytes : new TextEncoder().encode(name2);
    this.push({ ...entry, nameBytes, flags: name2 === void 0 ? entry.flags : entry.flags | UTF8 }, [data]);
  }
  meta(entry) {
    return {
      nameBytes: new TextEncoder().encode(entry.name),
      flags: UTF8,
      madeBy: MADE_BY_UNIX,
      externalAttrs: (32768 | (entry.mode ?? 420)) << 16 >>> 0,
      ...this.stamp
    };
  }
  // Deflated as it streams in; only the compressed bytes are held until the entry is written.
  async addStream(entry, source) {
    let crc = 0;
    let size = 0;
    const counted = source.pipeThrough(
      new TransformStream({
        transform(chunk, controller) {
          crc = crc32(chunk, crc);
          size += chunk.length;
          controller.enqueue(chunk);
        }
      })
    );
    const chunks = [];
    let compressedSize = 0;
    const reader = counted.pipeThrough(deflater()).getReader();
    for (; ; ) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      compressedSize += value.length;
    }
    this.push({ ...this.meta(entry), method: DEFLATE, crc, size, compressedSize }, [new Blob(chunks)]);
  }
  async addBytes(entry, bytes) {
    const deflated = new Uint8Array(
      await new Response(new Blob([bytes]).stream().pipeThrough(deflater())).arrayBuffer()
    );
    const stored = deflated.length >= bytes.length;
    this.push(
      {
        ...this.meta(entry),
        method: stored ? STORE : DEFLATE,
        crc: crc32(bytes),
        size: bytes.length,
        compressedSize: stored ? bytes.length : deflated.length
      },
      [stored ? bytes : deflated]
    );
  }
  finish() {
    if (this.central.length > 65535) throw new Error("too many files for a ZIP without ZIP64");
    const size = this.central.reduce((sum, c) => sum + c.length, 0);
    const end = new Uint8Array(22);
    const e = view2(end);
    e.setUint32(0, 101010256, true);
    e.setUint16(8, this.central.length, true);
    e.setUint16(10, this.central.length, true);
    e.setUint32(12, size, true);
    e.setUint32(16, this.offset, true);
    return new Blob([...this.parts, ...this.central, end], { type: "application/octet-stream" });
  }
};

// lib/patcher/patch.ts
var KIT_FORMAT = 1;
var MAIN = "@main";
async function openKit(blob2) {
  const entries = await readZip(blob2);
  const manifest = entries.find((e) => e.name === "kit.json");
  if (!manifest) throw new Error("the mod's download has no kit.json");
  const json = JSON.parse(new TextDecoder().decode(await readEntry(blob2, manifest)));
  if (json.format > KIT_FORMAT) throw new Error("this version needs a newer patcher: reload the page");
  if (new Set(entries.map((entry) => entry.name)).size !== entries.length) throw new Error("the mod's download has duplicate files");
  if (json.protection && !json.integrity) throw new Error("the protected mod's download is missing its checksums");
  if (json.integrity) {
    const payload = entries.filter((entry) => !entry.name.endsWith("/") && /^(files|appintents)\//.test(entry.name));
    if (payload.length !== Object.keys(json.integrity).length) throw new Error("the mod's download has an incomplete file list");
    for (const entry of payload) {
      const expected = json.integrity[entry.name];
      if (!expected || !/^[0-9a-f]{64}$/.test(expected)) throw new Error("the mod's download has an invalid checksum");
      const bytes = await readEntry(blob2, entry);
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
      const actual = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
      if (actual !== expected) throw new Error("the mod's download is damaged; download it again");
    }
  }
  return { json, blob: blob2, entries };
}
function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}
function patchHead(source, spanOf, patch2, onBytes) {
  const reader = source.getReader();
  let head = new Uint8Array(0);
  return new ReadableStream({
    async pull(controller) {
      for (; ; ) {
        const { done, value } = await reader.read();
        if (done) {
          if (head) throw new Error("the app's binary is cut short");
          controller.close();
          return;
        }
        onBytes(value.length);
        if (!head) {
          controller.enqueue(value);
          return;
        }
        head = concat(head, value);
        if (head.length < 32 || head.length < spanOf(head)) continue;
        patch2(head);
        controller.enqueue(head);
        head = void 0;
        return;
      }
    },
    cancel(reason) {
      return reader.cancel(reason);
    }
  });
}
async function readHead(ipa2, entry) {
  const reader = (await streamOf(ipa2, entry)).getReader();
  let head = new Uint8Array(0);
  try {
    while (head.length < 32 || head.length < headerSpan(head)) {
      const { done, value } = await reader.read();
      if (done) throw new Error("the app's binary is cut short");
      head = concat(head, value);
    }
  } finally {
    reader.cancel().catch(() => {
    });
  }
  return head;
}
var text = (value) => typeof value === "string" ? value : "";
async function inspect(ipa2) {
  const entries = await readZip(ipa2).catch(() => {
    throw new Error("this file is not an IPA");
  });
  const plist = entries.find((e) => /^Payload\/[^/]+\.app\/Info\.plist$/.test(e.name));
  if (!plist) throw new Error("there is no app inside this file: is it an .ipa?");
  const dir = plist.name.slice(0, -"Info.plist".length);
  const info = parsePlist(await readEntry(ipa2, plist));
  if (!info || typeof info !== "object" || Array.isArray(info) || info instanceof Uint8Array || info instanceof Date) {
    throw new Error("the app's Info.plist is not a dictionary");
  }
  const dict = info;
  const executable = text(dict.CFBundleExecutable);
  const main = entries.find((e) => e.name === dir + executable);
  if (!main) throw new Error("the app's binary is missing from the IPA");
  return {
    entries,
    dir,
    info: dict,
    name: text(dict.CFBundleDisplayName) || text(dict.CFBundleName) || executable,
    bundleId: text(dict.CFBundleIdentifier),
    version: text(dict.CFBundleShortVersionString),
    build: text(dict.CFBundleVersion),
    executable,
    encrypted: readMachO(await readHead(ipa2, main)).encrypted,
    modded: entries.some((e) => e.name === `${dir}Frameworks/spotifyglass.dylib`)
  };
}
function mergeInfo(info, overlay) {
  const merged = { ...info };
  for (const [key, value] of Object.entries(overlay.set)) merged[key] = fromJson(value);
  for (const [key, values] of Object.entries(overlay.union)) {
    const current = Array.isArray(merged[key]) ? merged[key] : [];
    merged[key] = [...current, ...fromJson(values).filter((v) => !current.includes(v))];
  }
  for (const [key, value] of Object.entries(overlay.default)) if (!merged[key]) merged[key] = fromJson(value);
  return merged;
}
function modeOf(entry, fallback) {
  return entry.madeBy >> 8 === 3 && entry.externalAttrs >>> 16 ? entry.externalAttrs >>> 16 & 4095 : fallback;
}
async function patch(ipa2, app2, kit2, onProgress) {
  const { json } = kit2;
  const kitFile = (path2) => kit2.entries.find((e) => e.name === path2);
  const files = kit2.entries.filter((e) => e.name.startsWith("files/") && !e.name.endsWith("/"));
  const provided = new Set(files.map((e) => app2.dir + e.name.slice("files/".length)));
  const removed = json.remove.map((r) => app2.dir + r);
  const loads = new Map(json.load.map((l) => [app2.dir + (l.binary === MAIN ? app2.executable : l.binary), l]));
  const mainName = app2.dir + app2.executable;
  const intentsName = `${app2.dir}Metadata.appintents/extract.actionsdata`;
  const ours = json.appIntents ? kitFile(`${json.appIntents}/extract.actionsdata`) : void 0;
  const oursActions = ours ? JSON.parse(new TextDecoder().decode(await readEntry(kit2.blob, ours))) : void 0;
  let hadIntents = false;
  const main = app2.entries.find((e) => e.name === mainName);
  let mainDone = 0;
  const report = (stage) => onProgress({ stage, fraction: Math.min(1, mainDone / Math.max(1, main.size)) });
  const out = new ZipWriter();
  report("Copying the app");
  for (const entry of app2.entries) {
    const { name: name2 } = entry;
    if (!name2.startsWith("Payload/") || name2.split("/").some((part) => part.startsWith("."))) continue;
    if (removed.some((r) => name2 === r || name2.startsWith(r + "/")) || provided.has(name2)) continue;
    if (name2 === `${app2.dir}Info.plist`) {
      await out.addBytes({ name: name2, mode: modeOf(entry, 420) }, writePlist(mergeInfo(app2.info, json.infoPlist)));
      continue;
    }
    const load = loads.get(name2);
    if (load && name2 === mainName) {
      report("Adding the mod to the app");
      const room = roomFor(load.dylibs, json.rpath);
      const stream = patchHead(
        await streamOf(ipa2, entry),
        (first) => headerSpan(first, room),
        (head) => void addLoadCommands(head, load.dylibs, json.rpath),
        (n) => {
          mainDone += n;
          report("Adding the mod to the app");
        }
      );
      await out.addStream({ name: name2, mode: modeOf(entry, 493) }, stream);
      report("Copying the app");
      continue;
    }
    if (load) {
      const bytes = await readEntry(ipa2, entry);
      addLoadCommands(bytes, load.dylibs);
      await out.addBytes({ name: name2, mode: modeOf(entry, 493) }, bytes);
      continue;
    }
    if (name2 === intentsName && oursActions) {
      hadIntents = true;
      const theirs = JSON.parse(new TextDecoder().decode(await readEntry(ipa2, entry)));
      const merged = { ...theirs, actions: { ...theirs.actions, ...oursActions.actions } };
      await out.addBytes({ name: name2, mode: modeOf(entry, 420) }, new TextEncoder().encode(JSON.stringify(merged)));
      continue;
    }
    await out.copy(ipa2, entry);
  }
  for (const [name2, load] of loads) {
    if (!load.optional && !app2.entries.some((e) => e.name === name2)) throw new Error(`${name2} is missing from the IPA`);
  }
  report("Adding the mod's files");
  const host = {
    HOST_BUNDLE_ID: app2.bundleId,
    HOST_SHORT_VERSION: app2.version,
    HOST_VERSION: app2.build
  };
  for (const entry of files) {
    const path2 = entry.name.slice("files/".length);
    const name2 = app2.dir + path2;
    if (json.templates.includes(path2)) {
      const filled = new TextDecoder().decode(await readEntry(kit2.blob, entry)).replace(/HOST_BUNDLE_ID|HOST_SHORT_VERSION|HOST_VERSION/g, (key) => escapeXml(host[key]));
      await out.addBytes({ name: name2, mode: modeOf(entry, 420) }, new TextEncoder().encode(filled));
    } else {
      await out.copy(kit2.blob, entry, name2);
    }
  }
  if (ours && !hadIntents) {
    await out.copy(kit2.blob, ours, intentsName);
    const version = kitFile(`${json.appIntents}/version.json`);
    if (version) await out.copy(kit2.blob, version, `${app2.dir}Metadata.appintents/version.json`);
  }
  report("Writing the IPA");
  return { blob: out.finish(), name: `spoti.pw-${json.version}.ipa` };
}

// scripts/patcher-cli.ts
var annotate = (level, message) => process.env.GITHUB_ACTIONS === "true" ? `::${level}::${message}` : `${level}: ${message}`;
function fail(message) {
  console.error(annotate("error", message));
  process.exit(1);
}
var messageOf = (error) => error instanceof Error ? error.message : String(error);
var [ipaPath, kitPath, outDir = "."] = process.argv.slice(2);
if (!ipaPath || !kitPath) fail("usage: node patcher.mjs <decrypted.ipa> <kit.zip> [output folder]");
var started = performance.now();
var kit = await openKit(await openAsBlob(kitPath)).catch((error) => fail(`The mod's download: ${messageOf(error)}`));
if (kit.json.baseSHA256) {
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(ipaPath)) digest.update(chunk);
  if (digest.digest("hex") !== kit.json.baseSHA256)
    fail("This kit was compiled for a different base IPA. Use the original base, or bootstrap a new kit.");
}
var tested = kit.json.spotify ?? "the version its release names";
console.log(`Custom spoti.pw ${kit.json.version}, made for Spotify ${tested}`);
var ipa = await openAsBlob(ipaPath);
var app = await inspect(ipa).catch((error) => {
  const message = messageOf(error);
  if (/not an IPA|no app inside/.test(message)) fail("This isn't an IPA. The link has to download the .ipa file itself, not a page about it.");
  fail(`This IPA is damaged, download it again or try another copy: ${message}`);
});
if (app.encrypted) fail(`This IPA is encrypted: it's the copy the App Store installs. Use a decrypted IPA of Spotify ${tested}.`);
if (app.executable !== "Spotify") fail(`This is ${app.name}, not Spotify. The mod needs a decrypted IPA of Spotify ${tested}.`);
console.log(`Spotify ${app.version}, decrypted${app.modded ? ", already has the mod: it will be replaced" : ""}`);
if (kit.json.spotify && app.version !== kit.json.spotify) {
  console.log(annotate("warning", `Chroma ${kit.json.version} is made for Spotify ${kit.json.spotify}, this is ${app.version}. The app may crash on launch or miss features.`));
}
var stages = /* @__PURE__ */ new Set();
var { blob, name } = await patch(ipa, app, kit, ({ stage }) => {
  if (stages.has(stage)) return;
  stages.add(stage);
  console.log(stage);
});
await mkdir(outDir, { recursive: true });
var file = path.join(outDir, name);
await pipeline(Readable.fromWeb(blob.stream()), createWriteStream(file));
console.log(`${file}, ${(blob.size / 1e6).toFixed(1)} MB in ${((performance.now() - started) / 1e3).toFixed(1)} s`);
