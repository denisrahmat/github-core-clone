// A standalone GitHub-compatible git forge: one process, stdlib only, in-memory store.
// Serves git smart HTTP (v2 + v0), REST v3, GraphQL v4 and MCP from the same store.
// main.ts owns the lifecycle; this file is the server. Keep timestamps fixed so replays
// are byte-identical: REST-created commits use FIXED_TS, REST objects use FIXED_ISO.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

export const ZERO_OID = '0'.repeat(40);
const FIXED_TS = 1_700_000_000;
const FIXED_ISO = '2023-11-14T22:13:20Z';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const JSON_TYPE = 'application/json; charset=utf-8';

// ---------------------------------------------------------------- helpers

function sha1(data: Buffer | string): string {
  return createHash('sha1').update(data).digest('hex');
}

function hashObject(type: string, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1(Buffer.concat([head, data]));
}

function b64encode(buf: Buffer): string {
  return buf.toString('base64');
}
function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/\s+/g, ''), 'base64');
}
function b64urlEncode(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64url');
}
function b64urlDecode(text: string): string {
  try {
    return Buffer.from(text, 'base64url').toString('utf8');
  } catch {
    return '';
  }
}

function isOid(v: unknown): v is string {
  return typeof v === 'string' && /^[0-9a-f]{40}$/.test(v);
}

function escHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;');
}

// ---------------------------------------------------------------- pkt-line

function pkt(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  const head = Buffer.from(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');
function pktLines(parts: Array<string | Buffer | 'flush' | 'delim'>): Buffer {
  const bufs: Buffer[] = [];
  for (const p of parts) {
    if (p === 'flush') bufs.push(PKT_FLUSH);
    else if (p === 'delim') bufs.push(PKT_DELIM);
    else bufs.push(pkt(p));
  }
  return Buffer.concat(bufs);
}

/** Decode a pkt-line stream. Returns data payloads and control markers in order. */
function decodePktLines(buf: Buffer): Array<{ kind: 'data' | 'flush' | 'delim'; payload: Buffer }> {
  const out: Array<{ kind: 'data' | 'flush' | 'delim'; payload: Buffer }> = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const lenHex = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(lenHex)) break;
    const len = parseInt(lenHex, 16);
    if (len === 0) {
      out.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 1) {
      out.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) break;
    out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}

// ---------------------------------------------------------------- git objects

export interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    if (sp < 0) break;
    const mode = data.subarray(off, sp).toString('ascii');
    const nul = data.indexOf(0, sp + 1);
    if (nul < 0 || nul + 21 > data.length) break;
    const name = data.subarray(sp + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    off = nul + 21;
  }
  return entries;
}

function compareTreeName(a: TreeEntry, b: TreeEntry): number {
  const an = a.mode === '40000' ? `${a.name}/` : a.name;
  const bn = b.mode === '40000' ? `${b.name}/` : b.name;
  return an < bn ? -1 : an > bn ? 1 : 0;
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeName);
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const head = blank < 0 ? text : text.slice(0, blank);
  const message = blank < 0 ? '' : text.slice(blank + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

function parseTag(data: Buffer): { object: string; type: string; tag: string; tagger: string; message: string } {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const head = blank < 0 ? text : text.slice(0, blank);
  const message = blank < 0 ? '' : text.slice(blank + 2);
  let object = '';
  let type = '';
  let tag = '';
  let tagger = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
    else if (line.startsWith('tagger ')) tagger = line.slice(7);
  }
  return { object, type, tag, tagger, message };
}

function buildCommit(tree: string, parents: readonly string[], message: string, author: string, ts: number): Buffer {
  let s = `tree ${tree}\n`;
  for (const p of parents) s += `parent ${p}\n`;
  s += `author ${author} ${ts} +0000\n`;
  s += `committer ${author} ${ts} +0000\n`;
  s += `\n${message.endsWith('\n') ? message : `${message}\n`}`;
  return Buffer.from(s, 'utf8');
}

interface GitObj {
  type: 'commit' | 'tree' | 'blob' | 'tag';
  data: Buffer;
}

// ---------------------------------------------------------------- packfiles

const PACK_TYPE: Record<number, GitObj['type']> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
const PACK_TYPE_NUM: Record<GitObj['type'], number> = { commit: 1, tree: 2, blob: 3, tag: 4 };

function writePackObjectHeader(type: GitObj['type'], size: number): Buffer {
  const typeNum = PACK_TYPE_NUM[type];
  let n = size;
  const first = (typeNum << 4) | (n & 0x0f);
  n >>= 4;
  const bytes: number[] = [n === 0 ? first : first | 0x80];
  while (n !== 0) {
    bytes.push(n & 0x7f);
    n >>= 7;
    if (n !== 0) bytes[bytes.length - 1] |= 0x80;
  }
  return Buffer.from(bytes);
}

function writePack(objects: Iterable<{ type: GitObj['type']; data: Buffer }>): Buffer {
  const list = [...objects];
  const parts: Buffer[] = [];
  const head = Buffer.alloc(12);
  head.write('PACK', 0, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(list.length, 8);
  parts.push(head);
  for (const obj of list) {
    parts.push(writePackObjectHeader(obj.type, obj.data.length));
    parts.push(deflateSync(obj.data, { level: 6 }));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readVarint = (): number => {
    let v = 0;
    let shift = 0;
    for (;;) {
      const b = delta[off++];
      v |= (b & 0x7f) << shift;
      shift += 7;
      if ((b & 0x80) === 0) break;
    }
    return v;
  };
  readVarint(); // base size
  const resultSize = readVarint();
  const out: Buffer[] = [];
  let total = 0;
  while (off < delta.length) {
    const op = delta[off++];
    if (op & 0x80) {
      let cpOff = 0;
      let cpSize = 0;
      for (let i = 0; i < 4; i += 1) if (op & (1 << i)) cpOff |= delta[off++] << (8 * i);
      for (let i = 0; i < 3; i += 1) if (op & (0x10 << i)) cpSize |= delta[off++] << (8 * i);
      if (cpSize === 0) cpSize = 0x10000;
      out.push(base.subarray(cpOff, cpOff + cpSize));
      total += cpSize;
    } else if (op !== 0) {
      out.push(delta.subarray(off, off + op));
      total += op;
      off += op;
    } else {
      throw new Error('delta op 0');
    }
  }
  const res = Buffer.concat(out);
  if (res.length !== resultSize || total !== resultSize) throw new Error('delta size mismatch');
  return res;
}

/** Inflate one zlib stream starting at `off`; returns the data and the offset just past it. */
function inflateAt(pack: Buffer, off: number): { data: Buffer; next: number } {
  // inflateSync ignores trailing bytes and throws on a truncated stream, so the
  // predicate "inflateSync succeeds" is monotonic in the end offset: binary-search
  // the smallest end that inflates.
  let lo = off + 1;
  let hi = pack.length;
  let data: Buffer | null = null;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    try {
      data = inflateSync(pack.subarray(off, mid));
      hi = mid;
    } catch {
      lo = mid + 1;
    }
  }
  if (data === null) {
    try {
      data = inflateSync(pack.subarray(off, lo));
    } catch {
      throw new Error('corrupt zlib stream in pack');
    }
  }
  return { data, next: lo };
}

/** Parse a packfile. Resolves REF_DELTA/OFS_DELTA against the pack itself and `lookup`. */
function readPack(pack: Buffer, lookup?: (oid: string) => GitObj | undefined): Map<string, GitObj> {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('bad pack header');
  const count = pack.readUInt32BE(8);
  let off = 12;
  const byOffset = new Map<number, GitObj>();
  const byOid = new Map<string, GitObj>();
  const store = (entryOffset: number, type: GitObj['type'], data: Buffer): GitObj => {
    const obj: GitObj = { type, data };
    byOffset.set(entryOffset, obj);
    byOid.set(hashObject(type, data), obj);
    return obj;
  };
  for (let i = 0; i < count; i += 1) {
    const entryOffset = off;
    let b = pack[off++];
    const typeNum = (b >> 4) & 0x7;
    let size = b & 0x0f;
    let shift = 4;
    while (b & 0x80) {
      b = pack[off++];
      size |= (b & 0x7f) << shift;
      shift += 7;
    }
    let baseObj: GitObj | undefined;
    let type: GitObj['type'];
    if (typeNum === 6) {
      let ofsByte = pack[off++];
      let baseOff = ofsByte & 0x7f;
      while (ofsByte & 0x80) {
        ofsByte = pack[off++];
        baseOff = ((baseOff + 1) << 7) | (ofsByte & 0x7f);
      }
      baseObj = byOffset.get(entryOffset - baseOff);
      if (!baseObj) throw new Error('ofs-delta base missing');
      type = baseObj.type;
    } else if (typeNum === 7) {
      const baseOid = pack.subarray(off, off + 20).toString('hex');
      off += 20;
      baseObj = byOid.get(baseOid) ?? lookup?.(baseOid);
      if (!baseObj) throw new Error('ref-delta base missing');
      type = baseObj.type;
    } else {
      const t = PACK_TYPE[typeNum];
      if (!t) throw new Error(`unknown pack type ${typeNum}`);
      type = t;
    }
    const { data: raw, next } = inflateAt(pack, off);
    off = next;
    if (raw.length !== size) throw new Error('pack object size mismatch');
    if (baseObj) store(entryOffset, type, applyDelta(baseObj.data, raw));
    else store(entryOffset, type, raw);
  }
  return byOid;
}

// ---------------------------------------------------------------- store

interface Comment {
  id: number;
  nodeId: string;
  body: string;
  seq: number;
}

interface Issue {
  id: number;
  nodeId: string;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  seq: number;
  comments: Comment[];
}

interface FileChange {
  filename: string;
  status: 'added' | 'modified' | 'removed';
  additions: number;
  deletions: number;
  changes: number;
}

interface Pull {
  id: number;
  nodeId: string;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergeable: boolean;
  mergeSha: string | null;
  mergedAt: string | null;
  files: FileChange[];
  seq: number;
}

interface Label {
  id: number;
  name: string;
  color: string;
  description: string;
}

class Repo {
  id: number;
  name: string;
  owner: string | null = null;
  description: string;
  isPrivate: boolean;
  defaultBranch = 'main';
  seq: number;
  refs = new Map<string, string>(); // full refname -> oid
  objects = new Map<string, GitObj>();
  issues = new Map<number, Issue>();
  pulls = new Map<number, Pull>();
  labels = new Map<string, Label>();
  nextNumber = 1;
  packCache = new Map<string, Buffer>();
  packVersion = 0;

  constructor(id: number, name: string, description: string, isPrivate: boolean, seq: number) {
    this.id = id;
    this.name = name;
    this.description = description;
    this.isPrivate = isPrivate;
    this.seq = seq;
  }

  get defaultTip(): string | undefined {
    return this.refs.get(`refs/heads/${this.defaultBranch}`);
  }
}

let viewerLogin: string | null = null;
let nextRepoId = 5000;
let nextGlobalId = 100000;
let nextSeq = 1;
const reposByName = new Map<string, Repo>();
const reposById = new Map<number, Repo>();
const globalIdIndex = new Map<string, { kind: string; repoId: number; number: number }>();

function globalId(kind: string, repoId: number, number: number): string {
  const id = `${kind}_${b64urlEncode(`${kind}:${repoId}:${number}`)}`;
  globalIdIndex.set(id, { kind, repoId, number });
  return id;
}
function decodeGlobalId(id: string): { kind: string; repoId: number; number: number } | null {
  const hit = globalIdIndex.get(id);
  if (hit) return hit;
  const m = /^([A-Z])_([A-Za-z0-9_-]+)$/.exec(id);
  if (!m) return null;
  const parts = b64urlDecode(m[2]).split(':');
  if (parts.length !== 3) return null;
  const repoId = Number(parts[1]);
  const number = Number(parts[2]);
  if (!Number.isSafeInteger(repoId) || !Number.isSafeInteger(number)) return null;
  return { kind: parts[0], repoId, number };
}
function repoGlobalId(repo: Repo): string {
  return globalId('R', repo.id, 0);
}

function authorIdent(): string {
  const login = viewerLogin ?? 'forge';
  return `${login} <${login}@example.invalid>`;
}

/** Bind a repo to an owner on first owner-qualified access; returns null when owned by another. */
function findRepo(owner: string, name: string): Repo | null {
  const repo = reposByName.get(name);
  if (!repo) return null;
  if (repo.owner === null) {
    repo.owner = owner;
    if (viewerLogin === null) viewerLogin = owner;
  } else if (repo.owner !== owner) {
    return null;
  }
  return repo;
}

function createRepo(name: string, description: string, isPrivate: boolean): Repo {
  const repo = new Repo(nextRepoId++, name, description, isPrivate, nextSeq++);
  reposByName.set(name, repo);
  reposById.set(repo.id, repo);
  return repo;
}

function deleteRepo(repo: Repo): void {
  reposByName.delete(repo.name);
  reposById.delete(repo.id);
}

// ---- git graph helpers (per repo) ----

function getObject(repo: Repo, oid: string): GitObj | undefined {
  return repo.objects.get(oid);
}

function putObject(repo: Repo, type: GitObj['type'], data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) {
    repo.objects.set(oid, { type, data });
    repo.packVersion += 1;
  }
  return oid;
}

/** Flat path -> {oid, mode} map of a commit's tree, recursively. */
function treeFlat(repo: Repo, commitOid: string): Map<string, { oid: string; mode: string }> {
  const out = new Map<string, { oid: string; mode: string }>();
  const commit = repo.objects.get(commitOid);
  if (!commit || commit.type !== 'commit') return out;
  const rootTree = parseCommit(commit.data).tree;
  const walk = (treeOid: string, prefix: string): void => {
    const tree = repo.objects.get(treeOid);
    if (!tree || tree.type !== 'tree') return;
    for (const e of parseTree(tree.data)) {
      const path = prefix === '' ? e.name : `${prefix}/${e.name}`;
      if (e.mode === '40000') walk(e.oid, path);
      else out.set(path, { oid: e.oid, mode: e.mode });
    }
  };
  walk(rootTree, '');
  return out;
}

function buildTreeFromFlat(repo: Repo, flat: Map<string, { oid: string; mode: string }>): string {
  interface Node {
    files: Map<string, { oid: string; mode: string }>;
    dirs: Map<string, Node>;
  }
  const make = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = make();
  for (const [path, entry] of flat) {
    const segs = path.split('/');
    let node = root;
    for (let i = 0; i < segs.length - 1; i += 1) {
      const s = segs[i];
      let child = node.dirs.get(s);
      if (!child) {
        child = make();
        node.dirs.set(s, child);
      }
      node = child;
    }
    node.files.set(segs[segs.length - 1], entry);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, e] of node.files) entries.push({ mode: e.mode, name, oid: e.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    const data = buildTree(entries);
    return putObject(repo, 'tree', data);
  };
  return build(root);
}

function makeCommit(repo: Repo, treeOid: string, parents: readonly string[], message: string): string {
  const data = buildCommit(treeOid, parents, message, authorIdent(), FIXED_TS);
  return putObject(repo, 'commit', data);
}

function commitParents(repo: Repo, oid: string): string[] {
  const obj = repo.objects.get(oid);
  if (!obj || obj.type !== 'commit') return [];
  return parseCommit(obj.data).parents;
}

/** All commit ancestors of `oid` (including itself), BFS. */
function ancestorsOf(repo: Repo, oid: string, limit = 100000): Set<string> {
  const seen = new Set<string>();
  const queue = [oid];
  while (queue.length > 0) {
    const cur = queue.pop()!;
    if (seen.has(cur)) continue;
    seen.add(cur);
    if (seen.size > limit) break;
    for (const p of commitParents(repo, cur)) if (!seen.has(p)) queue.push(p);
  }
  return seen;
}

function isAncestor(repo: Repo, anc: string, desc: string): boolean {
  if (anc === desc) return true;
  return ancestorsOf(repo, desc).has(anc);
}

function mergeBase(repo: Repo, a: string, b: string): string | null {
  const aAnc = ancestorsOf(repo, a);
  // BFS from b by generation: nearest common ancestor first.
  const seen = new Set<string>([b]);
  const queue = [b];
  while (queue.length > 0) {
    const cur = queue.shift()!;
    if (aAnc.has(cur)) return cur;
    for (const p of commitParents(repo, cur)) if (!seen.has(p)) {
      seen.add(p);
      queue.push(p);
    }
  }
  return null;
}

/** Commits reachable from `tips` following parents, newest-first by BFS generation. */
function listCommits(repo: Repo, tip: string, limit = 10000): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length > 0 && out.length < limit) {
    const cur = queue.shift()!;
    if (seen.has(cur)) continue;
    seen.add(cur);
    const obj = repo.objects.get(cur);
    if (!obj || obj.type !== 'commit') continue;
    out.push(cur);
    for (const p of parseCommit(obj.data).parents) if (!seen.has(p)) queue.push(p);
  }
  return out;
}

/** Reachable objects from commit/tag tips, with optional commit-depth limit. */
function collectObjects(
  repo: Repo,
  tips: readonly string[],
  excludeCommits?: Set<string>,
  maxDepth?: number,
): { objects: Map<string, GitObj>; shallow: string[]; unshallow: string[] } {
  const objects = new Map<string, GitObj>();
  const shallow: string[] = [];
  const include = (oid: string): void => {
    const obj = repo.objects.get(oid);
    if (obj && !objects.has(oid)) objects.set(oid, obj);
  };
  const includeTree = (treeOid: string): void => {
    const tree = repo.objects.get(treeOid);
    if (!tree || tree.type !== 'tree') return;
    include(treeOid);
    for (const e of parseTree(tree.data)) {
      if (e.mode === '40000') includeTree(e.oid);
      else include(e.oid);
    }
  };
  const queue: Array<{ oid: string; depth: number }> = [];
  for (const tip of tips) {
    const obj = repo.objects.get(tip);
    if (!obj) continue;
    if (obj.type === 'tag') {
      include(tip);
      const target = parseTag(obj.data).object;
      queue.push({ oid: target, depth: 0 });
    } else {
      queue.push({ oid: tip, depth: 0 });
    }
  }
  const seenCommits = new Set<string>();
  while (queue.length > 0) {
    const { oid, depth } = queue.shift()!;
    if (seenCommits.has(oid)) continue;
    seenCommits.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    const excluded = excludeCommits?.has(oid) ?? false;
    if (!excluded) {
      include(oid);
      const commit = parseCommit(obj.data);
      includeTree(commit.tree);
    }
    const commit = parseCommit(obj.data);
    const atLimit = maxDepth !== undefined && depth + 1 >= maxDepth;
    if (atLimit) {
      // A sent commit whose parents fall outside the depth is a shallow boundary.
      // An excluded commit is not sent, so it is never a boundary.
      if (!excluded) shallow.push(oid);
      continue;
    }
    for (const p of commit.parents) queue.push({ oid: p, depth: depth + 1 });
  }
  const unshallow: string[] = [];
  return { objects, shallow, unshallow };
}

function diffFlat(
  a: Map<string, { oid: string; mode: string }>,
  b: Map<string, { oid: string; mode: string }>,
): Array<{ path: string; status: 'added' | 'modified' | 'removed'; oldOid: string | null; newOid: string | null }> {
  const out: Array<{ path: string; status: 'added' | 'modified' | 'removed'; oldOid: string | null; newOid: string | null }> = [];
  const paths = new Set([...a.keys(), ...b.keys()]);
  for (const path of [...paths].sort()) {
    const av = a.get(path);
    const bv = b.get(path);
    if (av && !bv) out.push({ path, status: 'removed', oldOid: av.oid, newOid: null });
    else if (!av && bv) out.push({ path, status: 'added', oldOid: null, newOid: bv.oid });
    else if (av && bv && av.oid !== bv.oid) out.push({ path, status: 'modified', oldOid: av.oid, newOid: bv.oid });
  }
  return out;
}

function countLines(buf: Buffer): number {
  if (buf.length === 0) return 0;
  let n = 0;
  for (let i = 0; i < buf.length; i += 1) if (buf[i] === 0x0a) n += 1;
  if (buf[buf.length - 1] !== 0x0a) n += 1;
  return n;
}

function peelToCommit(repo: Repo, oid: string): string | null {
  let cur = oid;
  for (let i = 0; i < 10; i += 1) {
    const obj = repo.objects.get(cur);
    if (!obj) return null;
    if (obj.type === 'commit') return cur;
    if (obj.type === 'tag') cur = parseTag(obj.data).object;
    else return null;
  }
  return null;
}

// ---------------------------------------------------------------- HTTP plumbing

let reqCounter = 0;

function reqId(): string {
  reqCounter += 1;
  return `req-${reqCounter.toString(16)}-${Date.now().toString(36)}`;
}

function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': reqId(),
    ...extra,
  });
  res.end(text);
}

function sendNoBody(res: ServerResponse, status: number, extra: Record<string, string> = {}): void {
  res.writeHead(status, { 'x-github-request-id': reqId(), ...extra });
  res.end();
}

function errJson(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function readBody(req: IncomingMessage, maxBytes = 64 * 1024 * 1024): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (c: Buffer) => {
      total += c.length;
      if (total > maxBytes) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseJsonBody(buf: Buffer): unknown {
  if (buf.length === 0) return {};
  return JSON.parse(buf.toString('utf8'));
}

function checkAuth(req: IncomingMessage): boolean {
  const auth = req.headers.authorization ?? '';
  if (TOKEN === '') return auth.startsWith('Bearer ') && auth.length > 7;
  return auth === `Bearer ${TOKEN}`;
}

// ---------------------------------------------------------------- REST object builders

function userObj(login: string): Record<string, unknown> {
  return { login, id: 1000, avatar_url: '', type: 'User', site_admin: false, html_url: '', url: '' };
}

function repoObj(repo: Repo): Record<string, unknown> {
  const owner = repo.owner ?? viewerLogin ?? '';
  const openIssues = [...repo.issues.values()].filter((i) => i.state === 'open').length
    + [...repo.pulls.values()].filter((p) => p.state === 'open').length;
  return {
    id: repo.id,
    node_id: repoGlobalId(repo),
    name: repo.name,
    full_name: owner === '' ? repo.name : `${owner}/${repo.name}`,
    owner: userObj(owner),
    private: repo.isPrivate,
    description: repo.description,
    fork: false,
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    pushed_at: FIXED_ISO,
    homepage: '',
    size: 0,
    stargazers_count: 0,
    watchers_count: 0,
    forks_count: 0,
    open_issues_count: openIssues,
    default_branch: repo.defaultBranch,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
    has_pages: false,
    has_downloads: true,
    archived: false,
    disabled: false,
    visibility: repo.isPrivate ? 'private' : 'public',
    license: null,
    topics: [],
    url: `/api/v3/repos/${owner}/${repo.name}`,
    html_url: `/${owner}/${repo.name}`,
    clone_url: `/${owner}/${repo.name}.git`,
    git_url: `git:///${owner}/${repo.name}.git`,
    ssh_url: `git@/${owner}/${repo.name}.git`,
  };
}

function labelObj(l: Label): Record<string, unknown> {
  return { id: l.id, name: l.name, color: l.color, description: l.description, url: '', default: false };
}

function issueObj(repo: Repo, issue: Issue): Record<string, unknown> {
  const owner = repo.owner ?? viewerLogin ?? '';
  return {
    id: issue.id,
    node_id: issue.nodeId,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    locked: false,
    user: userObj(owner),
    labels: issue.labels.map((name) => {
      const l = repo.labels.get(name);
      return l ? labelObj(l) : { id: 0, name, color: 'ededed', description: '', url: '', default: false };
    }),
    assignee: null,
    assignees: [],
    milestone: null,
    comments: issue.comments.length,
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    closed_at: issue.state === 'closed' ? FIXED_ISO : null,
    author_association: 'OWNER',
    url: `/api/v3/repos/${owner}/${repo.name}/issues/${issue.number}`,
    html_url: `/${owner}/${repo.name}/issues/${issue.number}`,
    repository_url: `/api/v3/repos/${owner}/${repo.name}`,
    labels_url: `/api/v3/repos/${owner}/${repo.name}/issues/${issue.number}/labels`,
    comments_url: `/api/v3/repos/${owner}/${repo.name}/issues/${issue.number}/comments`,
    events_url: `/api/v3/repos/${owner}/${repo.name}/issues/${issue.number}/events`,
  };
}

function prFileChanges(repo: Repo, pr: Pull): FileChange[] {
  return pr.files;
}

function pullObj(repo: Repo, pr: Pull): Record<string, unknown> {
  const owner = repo.owner ?? viewerLogin ?? '';
  const additions = pr.files.reduce((s, f) => s + f.additions, 0);
  const deletions = pr.files.reduce((s, f) => s + f.deletions, 0);
  return {
    id: pr.id,
    node_id: pr.nodeId,
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    locked: false,
    user: userObj(owner),
    labels: [],
    assignee: null,
    assignees: [],
    milestone: null,
    head: { ref: pr.headRef, sha: pr.headSha, label: `${owner}:${pr.headRef}`, user: userObj(owner) },
    base: { ref: pr.baseRef, sha: pr.baseSha, label: `${owner}:${pr.baseRef}`, user: userObj(owner) },
    merged: pr.merged,
    mergeable: pr.mergeable,
    merge_commit_sha: pr.mergeSha,
    merged_at: pr.mergedAt,
    closed_at: pr.state === 'closed' ? FIXED_ISO : null,
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    draft: false,
    additions,
    deletions,
    changed_files: pr.files.length,
    commits: 1,
    url: `/api/v3/repos/${owner}/${repo.name}/pulls/${pr.number}`,
    html_url: `/${owner}/${repo.name}/pull/${pr.number}`,
    diff_url: `/${owner}/${repo.name}/pull/${pr.number}.diff`,
    patch_url: `/${owner}/${repo.name}/pull/${pr.number}.patch`,
  };
}

function commitObj(repo: Repo, sha: string): Record<string, unknown> | null {
  const obj = repo.objects.get(sha);
  if (!obj || obj.type !== 'commit') return null;
  const c = parseCommit(obj.data);
  const owner = repo.owner ?? viewerLogin ?? '';
  return {
    sha,
    node_id: `C_${b64urlEncode(`C:${repo.id}:${sha.slice(0, 12)}`)}`,
    commit: {
      message: c.message.replace(/\n$/, ''),
      author: { name: authorIdent().split(' <')[0], email: `${owner}@example.invalid`, date: FIXED_ISO },
      committer: { name: authorIdent().split(' <')[0], email: `${owner}@example.invalid`, date: FIXED_ISO },
      tree: { sha: c.tree },
    },
    author: userObj(owner),
    committer: userObj(owner),
    parents: c.parents.map((p) => ({ sha: p })),
    url: `/api/v3/repos/${owner}/${repo.name}/commits/${sha}`,
    html_url: `/${owner}/${repo.name}/commit/${sha}`,
  };
}

// ---- contents commits ----

/** Commit a file change on a branch; creates the branch from the default tip when missing. */
function commitFileOnBranch(
  repo: Repo,
  branch: string,
  path: string,
  content: Buffer | null,
  message: string,
): { commitSha: string; blobSha: string | null } {
  let tip = repo.refs.get(`refs/heads/${branch}`);
  if (tip === undefined) {
    const base = repo.defaultTip;
    tip = base;
    if (base !== undefined) repo.refs.set(`refs/heads/${branch}`, base);
  }
  const flat = tip !== undefined ? treeFlat(repo, tip) : new Map<string, { oid: string; mode: string }>();
  let blobSha: string | null = null;
  if (content !== null) {
    blobSha = putObject(repo, 'blob', content);
    flat.set(path, { oid: blobSha, mode: '100644' });
  } else {
    flat.delete(path);
  }
  const treeOid = buildTreeFromFlat(repo, flat);
  const parents = tip !== undefined ? [tip] : [];
  const commitSha = makeCommit(repo, treeOid, parents, message);
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  return { commitSha, blobSha };
}

function resolveRef(repo: Repo, ref: string | undefined): string | undefined {
  if (!ref) return repo.defaultTip;
  const asBranch = repo.refs.get(`refs/heads/${ref}`);
  if (asBranch) return asBranch;
  const asTag = repo.refs.get(`refs/tags/${ref}`);
  if (asTag) return peelToCommit(repo, asTag) ?? asTag;
  if (repo.objects.has(ref)) return ref;
  return undefined;
}

// ---- pull requests ----

function computePrFiles(repo: Repo, pr: Pull): FileChange[] {
  const baseTip = pr.baseSha;
  const headTip = pr.headSha;
  const mb = mergeBase(repo, headTip, baseTip);
  const baseFlat = mb ? treeFlat(repo, mb) : new Map();
  const headFlat = treeFlat(repo, headTip);
  void baseTip;
  const changes: FileChange[] = [];
  for (const d of diffFlat(baseFlat, headFlat)) {
    let additions = 0;
    let deletions = 0;
    if (d.status === 'added' && d.newOid) {
      const blob = repo.objects.get(d.newOid);
      additions = blob ? countLines(blob.data) : 0;
    } else if (d.status === 'removed' && d.oldOid) {
      const blob = repo.objects.get(d.oldOid);
      deletions = blob ? countLines(blob.data) : 0;
    } else {
      if (d.newOid) {
        const blob = repo.objects.get(d.newOid);
        additions = blob ? countLines(blob.data) : 0;
      }
      if (d.oldOid) {
        const blob = repo.objects.get(d.oldOid);
        deletions = blob ? countLines(blob.data) : 0;
      }
    }
    changes.push({ filename: d.path, status: d.status, additions, deletions, changes: additions + deletions });
  }
  return changes;
}

function prIsConflicted(repo: Repo, pr: Pull): boolean {
  const mb = mergeBase(repo, pr.headSha, pr.baseSha);
  if (!mb) return false;
  const baseFlat = treeFlat(repo, mb);
  const headFlat = treeFlat(repo, pr.headSha);
  const curBaseFlat = treeFlat(repo, pr.baseSha);
  const baseChanges = new Map(diffFlat(baseFlat, curBaseFlat).map((d) => [d.path, d]));
  for (const d of diffFlat(baseFlat, headFlat)) {
    const b = baseChanges.get(d.path);
    if (!b) continue;
    // Both sides changed the same path since the merge base: conflict unless they agree.
    if (b.newOid !== d.newOid) return true;
  }
  return false;
}

function createPull(repo: Repo, title: string, body: string, headRef: string, baseRef: string): Pull | null {
  const headSha = repo.refs.get(`refs/heads/${headRef}`);
  const baseSha = repo.refs.get(`refs/heads/${baseRef}`);
  if (!headSha || !baseSha) return null;
  const number = repo.nextNumber++;
  const pr: Pull = {
    id: nextGlobalId++,
    nodeId: '',
    number,
    title,
    body: body ?? '',
    state: 'open',
    headRef,
    baseRef,
    headSha,
    baseSha,
    merged: false,
    mergeable: true,
    mergeSha: null,
    mergedAt: null,
    files: [],
    seq: nextSeq++,
  };
  pr.nodeId = globalId('P', repo.id, number);
  pr.files = computePrFiles(repo, pr);
  pr.mergeable = !prIsConflicted(repo, pr);
  repo.pulls.set(number, pr);
  return pr;
}

function squashMerge(repo: Repo, pr: Pull): { sha: string } | { conflict: true } {
  if (pr.merged) return { sha: pr.mergeSha! };
  // Re-read current tips: the base may have moved since creation.
  const headSha = repo.refs.get(`refs/heads/${pr.headRef}`) ?? pr.headSha;
  const baseSha = repo.refs.get(`refs/heads/${pr.baseRef}`) ?? pr.baseSha;
  pr.headSha = headSha;
  pr.baseSha = baseSha;
  if (prIsConflicted(repo, pr)) return { conflict: true };
  const mb = mergeBase(repo, headSha, baseSha);
  const baseFlat = treeFlat(repo, baseSha);
  const mbFlat = mb ? treeFlat(repo, mb) : new Map<string, { oid: string; mode: string }>();
  const headFlat = treeFlat(repo, headSha);
  const merged = new Map(baseFlat);
  for (const d of diffFlat(mbFlat, headFlat)) {
    if (d.status === 'removed') merged.delete(d.path);
    else if (d.newOid) merged.set(d.path, { oid: d.newOid, mode: '100644' });
  }
  const treeOid = buildTreeFromFlat(repo, merged);
  const message = `Merge pull request #${pr.number} from ${pr.headRef}\n\n${pr.title}`;
  const sha = makeCommit(repo, treeOid, [baseSha], message);
  repo.refs.set(`refs/heads/${pr.baseRef}`, sha);
  pr.merged = true;
  pr.state = 'closed';
  pr.mergeSha = sha;
  pr.mergedAt = FIXED_ISO;
  pr.baseSha = sha;
  return { sha };
}

function createIssue(repo: Repo, title: string, body: string, labels: string[]): Issue {
  const number = repo.nextNumber++;
  const issue: Issue = {
    id: nextGlobalId++,
    nodeId: '',
    number,
    title,
    body: body ?? '',
    state: 'open',
    labels: [...labels],
    seq: nextSeq++,
    comments: [],
  };
  issue.nodeId = globalId('I', repo.id, number);
  repo.issues.set(number, issue);
  return issue;
}

// ---------------------------------------------------------------- REST

function paginate<T>(req: IncomingMessage, res: ServerResponse, items: T[], query: URLSearchParams): T[] {
  const perPageRaw = query.get('per_page');
  if (perPageRaw === null) return items;
  const perPage = Math.max(1, Math.min(100, Number(perPageRaw) || 30));
  const page = Math.max(1, Number(query.get('page') ?? '1') || 1);
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  if (start + perPage < items.length) {
    const url = new URL(req.url ?? '/', 'http://entry');
    url.searchParams.set('per_page', String(perPage));
    url.searchParams.set('page', String(page + 1));
    const host = req.headers.host ?? '127.0.0.1';
    const next = `http://${host}${url.pathname}${url.search}`;
    res.setHeader('link', `<${next}>; rel="next"`);
  }
  return slice;
}

function treeOidAtPath(repo: Repo, tip: string, dirPath: string): string | null {
  const commit = repo.objects.get(tip);
  if (!commit || commit.type !== 'commit') return null;
  let treeOid = parseCommit(commit.data).tree;
  if (dirPath === '') return treeOid;
  for (const seg of dirPath.split('/')) {
    const tree = repo.objects.get(treeOid);
    if (!tree || tree.type !== 'tree') return null;
    const entry = parseTree(tree.data).find((e) => e.name === seg && e.mode === '40000');
    if (!entry) return null;
    treeOid = entry.oid;
  }
  return treeOid;
}

function contentsEntries(repo: Repo, tip: string, dirPath: string): Array<Record<string, unknown>> {
  const owner = repo.owner ?? viewerLogin ?? '';
  const flat = treeFlat(repo, tip);
  const prefix = dirPath === '' ? '' : `${dirPath}/`;
  const seen = new Map<string, { type: 'file' | 'dir'; sha: string; size: number }>();
  for (const [path, entry] of flat) {
    if (!path.startsWith(prefix)) continue;
    const rest = path.slice(prefix.length);
    const seg = rest.split('/')[0];
    if (rest.includes('/')) {
      if (!seen.has(seg)) {
        const treeOid = treeOidAtPath(repo, tip, prefix + seg);
        seen.set(seg, { type: 'dir', sha: treeOid ?? ZERO_OID, size: 0 });
      }
    } else {
      const blob = repo.objects.get(entry.oid);
      seen.set(seg, { type: 'file', sha: entry.oid, size: blob ? blob.data.length : 0 });
    }
  }
  const out: Array<Record<string, unknown>> = [];
  for (const [name, info] of [...seen.entries()].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const path = prefix + name;
    out.push({
      type: info.type,
      size: info.size,
      name,
      path,
      sha: info.sha,
      url: `/api/v3/repos/${owner}/${repo.name}/contents/${path}`,
      html_url: `/${owner}/${repo.name}/blob/${repo.defaultBranch}/${path}`,
      git_url: `/api/v3/repos/${owner}/${repo.name}/git/blobs/${info.sha}`,
      download_url: `/${owner}/${repo.name}/raw/${repo.defaultBranch}/${path}`,
      _links: { self: '', git: '', html: '' },
    });
  }
  return out;
}

function fileContentObj(repo: Repo, tip: string, path: string): Record<string, unknown> | null {
  const flat = treeFlat(repo, tip);
  const entry = flat.get(path);
  if (!entry) return null;
  const blob = repo.objects.get(entry.oid);
  if (!blob) return null;
  const owner = repo.owner ?? viewerLogin ?? '';
  const name = path.split('/').pop() ?? path;
  return {
    type: 'file',
    encoding: 'base64',
    size: blob.data.length,
    name,
    path,
    content: b64encode(blob.data),
    sha: entry.oid,
    url: `/api/v3/repos/${owner}/${repo.name}/contents/${path}`,
    html_url: `/${owner}/${repo.name}/blob/${repo.defaultBranch}/${path}`,
    git_url: `/api/v3/repos/${owner}/${repo.name}/git/blobs/${entry.oid}`,
    download_url: `/${owner}/${repo.name}/raw/${repo.defaultBranch}/${path}`,
    _links: { self: '', git: '', html: '' },
  };
}

async function handleRest(req: IncomingMessage, res: ServerResponse, path: string, query: URLSearchParams, body: unknown): Promise<boolean> {
  const method = req.method ?? 'GET';
  const seg = path.split('/').filter((s) => s !== '').map((s) => {
    try {
      return decodeURIComponent(s);
    } catch {
      return s;
    }
  });
  // seg[0] === 'api', seg[1] === 'v3'
  const rest = seg.slice(2);

  if (!checkAuth(req)) {
    errJson(res, 401, 'Bad credentials');
    return true;
  }

  const jsonBody = (body ?? {}) as Record<string, unknown>;
  const badJson = body === null; // marker set by dispatcher on parse failure

  if (badJson) {
    errJson(res, 400, 'Problems parsing JSON');
    return true;
  }

  // ---- API root / meta / rate limit / user ----
  if (rest.length === 0) {
    if (method === 'GET') {
      sendJson(res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    errJson(res, 404, 'Not Found');
    return true;
  }
  if (rest[0] === 'meta' && rest.length === 1) {
    if (method === 'GET') {
      sendJson(res, 200, { installed_version: '1.0.0', verifiable_password_authentication: true });
      return true;
    }
    errJson(res, 404, 'Not Found');
    return true;
  }
  if (rest[0] === 'rate_limit' && rest.length === 1) {
    sendJson(res, 200, { resources: { core: { limit: 5000, remaining: 4999, reset: FIXED_TS, used: 1 } }, rate: { limit: 5000, remaining: 4999, reset: FIXED_TS, used: 1 } });
    return true;
  }
  if (rest[0] === 'user' && rest.length === 1) {
    if (method === 'GET') {
      if (viewerLogin === null) {
        errJson(res, 404, 'Not Found');
        return true;
      }
      sendJson(res, 200, { ...userObj(viewerLogin), name: viewerLogin, email: `${viewerLogin}@example.invalid`, public_repos: reposByName.size });
      return true;
    }
    errJson(res, 404, 'Not Found');
    return true;
  }
  if (rest[0] === 'user' && rest[1] === 'repos') {
    if (method === 'GET') {
      const list = [...reposByName.values()]
        .filter((r) => r.owner === null || r.owner === viewerLogin)
        .sort((a, b) => a.seq - b.seq)
        .map((r) => repoObj(r));
      sendJson(res, 200, paginate(req, res, list, query));
      return true;
    }
    if (method === 'POST') {
      const name = typeof jsonBody.name === 'string' ? jsonBody.name.trim() : '';
      if (name === '' || name.includes('/')) {
        errJson(res, 422, 'Validation Failed: name is required');
        return true;
      }
      if (reposByName.has(name)) {
        errJson(res, 422, 'Repository already exists');
        return true;
      }
      const repo = createRepo(
        name,
        typeof jsonBody.description === 'string' ? jsonBody.description : '',
        jsonBody.private === true,
      );
      sendJson(res, 201, repoObj(repo));
      return true;
    }
    errJson(res, 404, 'Not Found');
    return true;
  }

  // ---- /repos/{owner}/{name}/... ----
  if (rest[0] !== 'repos' || rest.length < 3) {
    errJson(res, 404, 'Not Found');
    return true;
  }
  const owner = rest[1];
  const repoName = rest[2];
  const tail = rest.slice(3);

  const needRepo = (): Repo | null => findRepo(owner, repoName);

  // repo object itself
  if (tail.length === 0) {
    if (method === 'GET') {
      const repo = needRepo();
      if (!repo) {
        errJson(res, 404, 'Not Found');
        return true;
      }
      sendJson(res, 200, repoObj(repo));
      return true;
    }
    if (method === 'PATCH') {
      const repo = needRepo();
      if (!repo) {
        errJson(res, 404, 'Not Found');
        return true;
      }
      if (typeof jsonBody.description === 'string') repo.description = jsonBody.description;
      if (typeof jsonBody.private === 'boolean') repo.isPrivate = jsonBody.private;
      sendJson(res, 200, repoObj(repo));
      return true;
    }
    if (method === 'DELETE') {
      const repo = needRepo();
      if (!repo) {
        errJson(res, 404, 'Not Found');
        return true;
      }
      deleteRepo(repo);
      sendNoBody(res, 204);
      return true;
    }
    errJson(res, 404, 'Not Found');
    return true;
  }

  const repo = needRepo();
  if (!repo) {
    errJson(res, 404, 'Not Found');
    return true;
  }

  // ---- branches ----
  if (tail[0] === 'branches') {
    if (tail.length === 1 && method === 'GET') {
      const list: Array<Record<string, unknown>> = [];
      for (const [ref, sha] of [...repo.refs.entries()].sort()) {
        if (!ref.startsWith('refs/heads/')) continue;
        list.push({ name: ref.slice('refs/heads/'.length), commit: { sha, url: '' }, protected: false });
      }
      sendJson(res, 200, list);
      return true;
    }
    if (tail.length === 2 && method === 'GET') {
      const sha = repo.refs.get(`refs/heads/${tail[1]}`);
      if (!sha) {
        errJson(res, 404, 'Not Found');
        return true;
      }
      sendJson(res, 200, { name: tail[1], commit: { sha, url: '' }, protected: false });
      return true;
    }
    errJson(res, 404, 'Not Found');
    return true;
  }

  // ---- git refs ----
  if (tail[0] === 'git' && tail[1] === 'refs') {
    if (method === 'POST' && tail.length === 2) {
      const ref = typeof jsonBody.ref === 'string' ? jsonBody.ref : '';
      const sha = typeof jsonBody.sha === 'string' ? jsonBody.sha : '';
      if (!ref.startsWith('refs/') || !isOid(sha) || !repo.objects.has(sha)) {
        errJson(res, 422, 'Validation Failed');
        return true;
      }
      if (repo.refs.has(ref)) {
        errJson(res, 422, 'Reference already exists');
        return true;
      }
      repo.refs.set(ref, sha);
      const type = repo.objects.get(sha)?.type ?? 'commit';
      sendJson(res, 201, { ref, url: '', object: { sha, type, url: '' } });
      return true;
    }
    if (method === 'GET') {
      if (tail.length === 2) {
        const list: Array<Record<string, unknown>> = [];
        for (const [ref, sha] of [...repo.refs.entries()].sort()) {
          const type = repo.objects.get(sha)?.type ?? 'commit';
          list.push({ ref, url: '', object: { sha, type, url: '' } });
        }
        sendJson(res, 200, list);
        return true;
      }
      const ref = `refs/${tail.slice(2).join('/')}`;
      const sha = repo.refs.get(ref);
      if (!sha) {
        errJson(res, 404, 'Not Found');
        return true;
      }
      const type = repo.objects.get(sha)?.type ?? 'commit';
      sendJson(res, 200, { ref, url: '', object: { sha, type, url: '' } });
      return true;
    }
    errJson(res, 404, 'Not Found');
    return true;
  }

  // ---- commits ----
  if (tail[0] === 'commits') {
    if (tail.length === 1 && method === 'GET') {
      const tip = resolveRef(repo, query.get('sha') ?? undefined);
      if (!tip) {
        sendJson(res, 200, []);
        return true;
      }
      const list = listCommits(repo, tip).map((sha) => commitObj(repo, sha)).filter((c): c is Record<string, unknown> => c !== null);
      sendJson(res, 200, list);
      return true;
    }
    if (tail.length === 2 && method === 'GET') {
      const c = commitObj(repo, tail[1]);
      if (!c) {
        errJson(res, 404, 'Not Found');
        return true;
      }
      sendJson(res, 200, c);
      return true;
    }
    errJson(res, 404, 'Not Found');
    return true;
  }

  // ---- contents ----
  if (tail[0] === 'contents') {
    const contentPath = tail.slice(1).join('/');
    if (method === 'GET') {
      const tip = resolveRef(repo, query.get('ref') ?? undefined);
      if (!tip) {
        errJson(res, 404, 'Not Found');
        return true;
      }
      const flat = treeFlat(repo, tip);
      if (contentPath === '') {
        sendJson(res, 200, contentsEntries(repo, tip, ''));
        return true;
      }
      if (flat.has(contentPath)) {
        const obj = fileContentObj(repo, tip, contentPath);
        if (!obj) {
          errJson(res, 404, 'Not Found');
          return true;
        }
        sendJson(res, 200, obj);
        return true;
      }
      const isDir = [...flat.keys()].some((k) => k.startsWith(`${contentPath}/`));
      if (isDir) {
        sendJson(res, 200, contentsEntries(repo, tip, contentPath));
        return true;
      }
      errJson(res, 404, 'Not Found');
      return true;
    }
    if (method === 'PUT') {
      const message = typeof jsonBody.message === 'string' ? jsonBody.message : 'update';
      const branch = typeof jsonBody.branch === 'string' && jsonBody.branch !== '' ? jsonBody.branch : repo.defaultBranch;
      const contentB64 = typeof jsonBody.content === 'string' ? jsonBody.content : '';
      if (contentB64 === '') {
        errJson(res, 422, 'Validation Failed: content is required');
        return true;
      }
      const content = b64decode(contentB64);
      const tip = repo.refs.get(`refs/heads/${branch}`);
      const flat = tip !== undefined ? treeFlat(repo, tip) : new Map<string, { oid: string; mode: string }>();
      const existing = flat.get(contentPath);
      const isUpdate = existing !== undefined;
      if (isUpdate) {
        if (typeof jsonBody.sha !== 'string') {
          errJson(res, 422, 'Validation Failed: sha is required to update a file');
          return true;
        }
        if (jsonBody.sha !== existing.oid) {
          errJson(res, 409, 'Conflict: sha does not match the current file');
          return true;
        }
      } else if (typeof jsonBody.sha === 'string') {
        errJson(res, 422, 'Validation Failed: sha does not match');
        return true;
      }
      const { commitSha, blobSha } = commitFileOnBranch(repo, branch, contentPath, content, message);
      const ownerLogin = repo.owner ?? viewerLogin ?? '';
      sendJson(res, isUpdate ? 200 : 201, {
        content: {
          name: contentPath.split('/').pop() ?? contentPath,
          path: contentPath,
          sha: blobSha,
          size: content.length,
          url: `/api/v3/repos/${ownerLogin}/${repo.name}/contents/${contentPath}`,
          html_url: '',
          git_url: '',
          download_url: '',
          type: 'file',
          encoding: 'base64',
          content: contentB64,
          _links: { self: '', git: '', html: '' },
        },
        commit: { sha: commitSha, message, author: { name: authorIdent(), date: FIXED_ISO }, committer: { name: authorIdent(), date: FIXED_ISO } },
      });
      return true;
    }
    if (method === 'DELETE') {
      const message = typeof jsonBody.message === 'string' ? jsonBody.message : 'delete';
      const branch = typeof jsonBody.branch === 'string' && jsonBody.branch !== '' ? jsonBody.branch : repo.defaultBranch;
      const tip = repo.refs.get(`refs/heads/${branch}`);
      if (!tip) {
        errJson(res, 404, 'Not Found');
        return true;
      }
      const flat = treeFlat(repo, tip);
      const existing = flat.get(contentPath);
      if (!existing) {
        errJson(res, 404, 'Not Found');
        return true;
      }
      if (typeof jsonBody.sha === 'string' && jsonBody.sha !== existing.oid) {
        errJson(res, 409, 'Conflict: sha does not match the current file');
        return true;
      }
      const { commitSha } = commitFileOnBranch(repo, branch, contentPath, null, message);
      sendJson(res, 200, { content: null, commit: { sha: commitSha, message } });
      return true;
    }
    errJson(res, 404, 'Not Found');
    return true;
  }

  // ---- labels ----
  if (tail[0] === 'labels') {
    if (method === 'GET' && tail.length === 1) {
      sendJson(res, 200, [...repo.labels.values()].map((l) => labelObj(l)));
      return true;
    }
    if (method === 'POST' && tail.length === 1) {
      const name = typeof jsonBody.name === 'string' ? jsonBody.name : '';
      if (name === '') {
        errJson(res, 422, 'Validation Failed: name is required');
        return true;
      }
      let label = repo.labels.get(name);
      if (!label) {
        label = {
          id: nextGlobalId++,
          name,
          color: typeof jsonBody.color === 'string' ? jsonBody.color : 'ededed',
          description: typeof jsonBody.description === 'string' ? jsonBody.description : '',
        };
        repo.labels.set(name, label);
      }
      sendJson(res, 201, labelObj(label));
      return true;
    }
    errJson(res, 404, 'Not Found');
    return true;
  }

  // ---- issues ----
  if (tail[0] === 'issues') {
    if (tail.length === 1) {
      if (method === 'GET') {
        const state = query.get('state') ?? 'open';
        const sort = query.get('sort') ?? 'created';
        const direction = query.get('direction') ?? 'desc';
        let list = [...repo.issues.values()];
        if (state !== 'all') list = list.filter((i) => i.state === state);
        if (sort === 'created') {
          list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
        }
        sendJson(res, 200, paginate(req, res, list.map((i) => issueObj(repo, i)), query));
        return true;
      }
      if (method === 'POST') {
        const title = typeof jsonBody.title === 'string' ? jsonBody.title : '';
        const bodyText = typeof jsonBody.body === 'string' ? jsonBody.body : '';
        const labels = Array.isArray(jsonBody.labels) ? jsonBody.labels.filter((l): l is string => typeof l === 'string') : [];
        for (const l of labels) {
          if (!repo.labels.has(l)) {
            errJson(res, 422, `Validation Failed: label "${l}" does not exist`);
            return true;
          }
        }
        if (title === '') {
          errJson(res, 422, 'Validation Failed: title is required');
          return true;
        }
        const issue = createIssue(repo, title, bodyText, labels);
        sendJson(res, 201, issueObj(repo, issue));
        return true;
      }
      errJson(res, 404, 'Not Found');
      return true;
    }
    const num = Number(tail[1]);
    if (!Number.isSafeInteger(num) || num < 1) {
      errJson(res, 404, 'Not Found');
      return true;
    }
    // comments
    if (tail[2] === 'comments') {
      const issue = repo.issues.get(num);
      if (!issue) {
        errJson(res, 404, 'Not Found');
        return true;
      }
      if (method === 'GET') {
        sendJson(res, 200, issue.comments.map((c) => ({
          id: c.id,
          node_id: c.nodeId,
          body: c.body,
          user: userObj(repo.owner ?? viewerLogin ?? ''),
          created_at: FIXED_ISO,
          updated_at: FIXED_ISO,
          url: '',
          html_url: '',
          issue_url: '',
        })));
        return true;
      }
      if (method === 'POST') {
        const bodyText = typeof jsonBody.body === 'string' ? jsonBody.body : '';
        const comment: Comment = { id: nextGlobalId++, nodeId: '', body: bodyText, seq: nextSeq++ };
        comment.nodeId = globalId('C', repo.id, comment.id);
        issue.comments.push(comment);
        sendJson(res, 201, {
          id: comment.id,
          node_id: comment.nodeId,
          body: comment.body,
          user: userObj(repo.owner ?? viewerLogin ?? ''),
          created_at: FIXED_ISO,
          updated_at: FIXED_ISO,
          url: '',
          html_url: '',
          issue_url: '',
        });
        return true;
      }
      errJson(res, 404, 'Not Found');
      return true;
    }
    if (tail.length === 2) {
      const issue = repo.issues.get(num);
      const pr = issue === undefined ? repo.pulls.get(num) : undefined;
      if (method === 'GET') {
        if (issue) {
          sendJson(res, 200, issueObj(repo, issue));
          return true;
        }
        if (pr) {
          const asIssue = issueObj(repo, {
            id: pr.id,
            nodeId: pr.nodeId,
            number: pr.number,
            title: pr.title,
            body: pr.body,
            state: pr.state,
            labels: [],
            seq: pr.seq,
            comments: [],
          });
          (asIssue as Record<string, unknown>).pull_request = { url: '', html_url: '', diff_url: '', patch_url: '' };
          sendJson(res, 200, asIssue);
          return true;
        }
        errJson(res, 404, 'Not Found');
        return true;
      }
      if (method === 'PATCH') {
        if (!issue) {
          errJson(res, 404, 'Not Found');
          return true;
        }
        if (jsonBody.state === 'open' || jsonBody.state === 'closed') issue.state = jsonBody.state;
        if (typeof jsonBody.title === 'string') issue.title = jsonBody.title;
        if (typeof jsonBody.body === 'string') issue.body = jsonBody.body;
        if (Array.isArray(jsonBody.labels)) {
          issue.labels = jsonBody.labels.filter((l): l is string => typeof l === 'string');
        }
        sendJson(res, 200, issueObj(repo, issue));
        return true;
      }
      errJson(res, 404, 'Not Found');
      return true;
    }
    errJson(res, 404, 'Not Found');
    return true;
  }

  // ---- pulls ----
  if (tail[0] === 'pulls') {
    if (tail.length === 1) {
      if (method === 'GET') {
        const state = query.get('state') ?? 'open';
        let list = [...repo.pulls.values()];
        if (state !== 'all') list = list.filter((p) => p.state === state);
        list.sort((a, b) => b.seq - a.seq);
        sendJson(res, 200, paginate(req, res, list.map((p) => pullObj(repo, p)), query));
        return true;
      }
      if (method === 'POST') {
        const title = typeof jsonBody.title === 'string' ? jsonBody.title : '';
        const bodyText = typeof jsonBody.body === 'string' ? jsonBody.body : '';
        const headRaw = typeof jsonBody.head === 'string' ? jsonBody.head : '';
        const baseRaw = typeof jsonBody.base === 'string' ? jsonBody.base : repo.defaultBranch;
        const head = headRaw.includes(':') ? headRaw.split(':').pop()! : headRaw;
        const base = baseRaw.includes(':') ? baseRaw.split(':').pop()! : baseRaw;
        if (title === '' || head === '') {
          errJson(res, 422, 'Validation Failed');
          return true;
        }
        const pr = createPull(repo, title, bodyText, head, base);
        if (!pr) {
          errJson(res, 422, 'Validation Failed: head or base branch does not exist');
          return true;
        }
        sendJson(res, 201, pullObj(repo, pr));
        return true;
      }
      errJson(res, 404, 'Not Found');
      return true;
    }
    const num = Number(tail[1]);
    if (!Number.isSafeInteger(num) || num < 1) {
      errJson(res, 404, 'Not Found');
      return true;
    }
    if (tail[2] === 'files' && tail.length === 3 && method === 'GET') {
      const pr = repo.pulls.get(num);
      if (!pr) {
        errJson(res, 404, 'Not Found');
        return true;
      }
      sendJson(res, 200, prFileChanges(repo, pr).map((f) => ({
        filename: f.filename,
        status: f.status,
        additions: f.additions,
        deletions: f.deletions,
        changes: f.changes,
        blob_url: '',
        raw_url: '',
        contents_url: '',
        patch: '',
      })));
      return true;
    }
    if (tail[2] === 'commits' && tail.length === 3 && method === 'GET') {
      const pr = repo.pulls.get(num);
      if (!pr) {
        errJson(res, 404, 'Not Found');
        return true;
      }
      const mb = mergeBase(repo, pr.headSha, pr.baseSha);
      const mbAnc = mb ? ancestorsOf(repo, mb) : new Set<string>();
      const list = listCommits(repo, pr.headSha)
        .filter((sha) => !mbAnc.has(sha))
        .map((sha) => commitObj(repo, sha))
        .filter((c): c is Record<string, unknown> => c !== null);
      sendJson(res, 200, list);
      return true;
    }
    if (tail[2] === 'merge' && tail.length === 3 && method === 'PUT') {
      const pr = repo.pulls.get(num);
      if (!pr) {
        errJson(res, 404, 'Not Found');
        return true;
      }
      if (pr.merged) {
        sendJson(res, 200, { sha: pr.mergeSha, merged: true, message: 'Already merged' });
        return true;
      }
      const result = squashMerge(repo, pr);
      if ('conflict' in result) {
        errJson(res, 405, 'Merge conflict');
        return true;
      }
      sendJson(res, 200, { sha: result.sha, merged: true, message: `Merge pull request #${pr.number} from ${pr.headRef}` });
      return true;
    }
    if (tail.length === 2 && method === 'GET') {
      const pr = repo.pulls.get(num);
      if (!pr) {
        errJson(res, 404, 'Not Found');
        return true;
      }
      sendJson(res, 200, pullObj(repo, pr));
      return true;
    }
    errJson(res, 404, 'Not Found');
    return true;
  }

  errJson(res, 404, 'Not Found');
  return true;
}

// ---------------------------------------------------------------- git smart HTTP

function gitCapsV0Upload(repo: Repo): string {
  return 'multi_ack thin-pack side-band side-band-64k ofs-delta shallow no-progress include-tag multi_ack_detailed agent=forge/1.0 symref=HEAD:refs/heads/main object-format=sha1';
}
function gitCapsV0Receive(): string {
  return 'report-status side-band-64k delete-refs ofs-delta agent=forge/1.0 symref=HEAD:refs/heads/main object-format=sha1';
}

function sortedRefs(repo: Repo): Array<{ name: string; oid: string }> {
  return [...repo.refs.entries()].map(([name, oid]) => ({ name, oid })).sort((a, b) => (a.name < b.name ? -1 : 1));
}

function peeledOid(repo: Repo, refOid: string): string | null {
  const obj = repo.objects.get(refOid);
  if (!obj || obj.type !== 'tag') return null;
  return peelToCommit(repo, refOid);
}

function advertisementV0(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const caps = service === 'git-upload-pack' ? gitCapsV0Upload(repo) : gitCapsV0Receive();
  const parts: Buffer[] = [pkt(`# service=${service}\n`), PKT_FLUSH];
  const refs = sortedRefs(repo);
  const headTip = repo.defaultTip;
  if (refs.length === 0) {
    parts.push(pkt(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    const headLine = headTip !== undefined
      ? `${headTip} HEAD\0${caps}\n`
      : `${ZERO_OID} HEAD\0${caps}\n`;
    parts.push(pkt(headLine));
    for (const r of refs) parts.push(pkt(`${r.oid} ${r.name}\n`));
    for (const r of refs) {
      const peeled = peeledOid(repo, r.oid);
      if (peeled) parts.push(pkt(`${peeled} ${r.name}^{}\n`));
    }
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function advertisementV2(): Buffer {
  return pktLines([
    '# service=git-upload-pack\n',
    'flush',
    'version 2\n',
    'fetch=shallow filter\n',
    'ls-refs=unborn\n',
    'object-format=sha1\n',
    'flush',
  ]);
}

function lsRefsResponse(repo: Repo, args: { peel: boolean; symrefs: boolean; prefixes: string[] }): Buffer {
  const lines: string[] = [];
  const keep = (name: string): boolean => args.prefixes.length === 0 || args.prefixes.some((p) => name.startsWith(p));
  const headTip = repo.defaultTip;
  if (keep('HEAD')) {
    if (headTip !== undefined) lines.push(`${headTip} HEAD symref-target:refs/heads/main\n`);
    else lines.push('unborn HEAD symref-target:refs/heads/main\n');
  }
  for (const r of sortedRefs(repo)) {
    if (!keep(r.name)) continue;
    let line = `${r.oid} ${r.name}`;
    if (args.peel) {
      const peeled = peeledOid(repo, r.oid);
      if (peeled) line += ` peeled:${peeled}`;
    }
    lines.push(`${line}\n`);
  }
  const parts: Buffer[] = lines.map((l) => pkt(l));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

/** Objects reachable from `roots` (commits/tags), stopping parent-walk at `stopAt`. */
function closureObjects(
  repo: Repo,
  roots: readonly string[],
  stopAt?: Set<string>,
  maxDepth?: number,
): { commits: Set<string>; objects: Map<string, GitObj>; boundary: Set<string> } {
  const commits = new Set<string>();
  const objects = new Map<string, GitObj>();
  const boundary = new Set<string>();
  const include = (oid: string): void => {
    const o = repo.objects.get(oid);
    if (o && !objects.has(oid)) objects.set(oid, o);
  };
  const includeTree = (treeOid: string): void => {
    const t = repo.objects.get(treeOid);
    if (!t || t.type !== 'tree') return;
    include(treeOid);
    for (const e of parseTree(t.data)) {
      if (e.mode === '40000') includeTree(e.oid);
      else include(e.oid);
    }
  };
  const queue: Array<{ oid: string; depth: number }> = roots.map((oid) => ({ oid, depth: 0 }));
  const seen = new Set<string>();
  while (queue.length > 0) {
    const { oid, depth } = queue.shift()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    if (obj.type === 'tag') {
      include(oid);
      queue.push({ oid: parseTag(obj.data).object, depth });
      continue;
    }
    if (obj.type !== 'commit') continue;
    commits.add(oid);
    include(oid);
    const commit = parseCommit(obj.data);
    includeTree(commit.tree);
    if (stopAt?.has(oid)) continue;
    if (maxDepth !== undefined && depth + 1 >= maxDepth) {
      boundary.add(oid);
      continue;
    }
    for (const p of commit.parents) queue.push({ oid: p, depth: depth + 1 });
  }
  return { commits, objects, boundary };
}

function sendPackForFetch(
  repo: Repo,
  wants: string[],
  haves: string[],
  shallowBounds: string[],
  deepen: number | undefined,
): { pack: Buffer | null; shallow: string[]; unshallow: string[]; ack: string[] } {
  const cacheKey = `${repo.packVersion}|${[...wants].sort().join(',')}|${[...haves].sort().join(',')}|${[...shallowBounds].sort().join(',')}|${deepen ?? ''}`;
  const cached = repo.packCache.get(cacheKey);
  const shallowSet = new Set(shallowBounds);
  const want = closureObjects(repo, wants, undefined, deepen);
  const have = closureObjects(repo, haves, shallowSet);
  const sentCommits = new Set([...want.commits].filter((c) => !have.commits.has(c)));
  const sendObjects = new Map<string, GitObj>();
  for (const [oid, obj] of want.objects) if (!have.objects.has(oid)) sendObjects.set(oid, obj);
  let pack: Buffer | null = null;
  if (cached !== undefined) {
    pack = cached;
  } else if (sendObjects.size > 0) {
    const sorted = [...sendObjects.entries()].sort(([a], [b]) => (a < b ? -1 : 1));
    pack = writePack(sorted.map(([, obj]) => obj));
    if (repo.packCache.size > 64) repo.packCache.clear();
    repo.packCache.set(cacheKey, pack);
  }
  const shallowOut: string[] = [];
  for (const c of want.boundary) if (sentCommits.has(c)) shallowOut.push(c);
  const unshallow: string[] = [];
  for (const s of shallowBounds) {
    if (sentCommits.has(s)) continue; // handled as a fresh boundary or fully sent
    if (!have.commits.has(s)) continue;
    const parents = commitParents(repo, s);
    if (parents.some((p) => sentCommits.has(p))) {
      unshallow.push(s);
    } else if (parents.length > 0 && parents.every((p) => !sentCommits.has(p) && !have.commits.has(p))) {
      if (!shallowOut.includes(s)) shallowOut.push(s);
    }
  }
  const ack: string[] = [];
  for (const h of haves) if (repo.objects.has(h)) ack.push(h);
  return { pack, shallow: shallowOut, unshallow, ack };
}

function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  const CHUNK = 32768;
  for (let off = 0; off < pack.length; off += CHUNK) {
    const slice = pack.subarray(off, Math.min(pack.length, off + CHUNK));
    parts.push(pkt(Buffer.concat([Buffer.from([1]), slice])));
  }
  return Buffer.concat(parts);
}

function handleUploadPackV2(repo: Repo, body: Buffer): Buffer {
  const packets = decodePktLines(body);
  const lines: string[] = [];
  let seenDelim = false;
  for (const p of packets) {
    if (p.kind === 'delim') {
      seenDelim = true;
      continue;
    }
    if (p.kind === 'flush') break;
    if (p.kind === 'data') lines.push(p.payload.toString('utf8'));
  }
  void seenDelim;
  const command = lines[0]?.trim() ?? '';
  if (command === 'command=ls-refs') {
    const args = { peel: false, symrefs: false, prefixes: [] as string[] };
    for (const l of lines.slice(1)) {
      const t = l.trim();
      if (t === 'peel') args.peel = true;
      else if (t === 'symrefs') args.symrefs = true;
      else if (t.startsWith('ref-prefix ')) args.prefixes.push(t.slice('ref-prefix '.length));
    }
    return lsRefsResponse(repo, args);
  }
  if (command !== 'command=fetch') return Buffer.from('0000', 'ascii');
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let deepen: number | undefined;
  for (const l of lines.slice(1)) {
    const t = l.trim();
    if (t.startsWith('want ')) wants.push(t.slice(5).trim());
    else if (t.startsWith('have ')) haves.push(t.slice(5).trim());
    else if (t.startsWith('shallow ')) shallow.push(t.slice(8).trim());
    else if (t.startsWith('deepen ')) {
      const n = Number(t.slice(7).trim());
      if (Number.isSafeInteger(n) && n > 0) deepen = n;
    }
  }
  const { pack, shallow: shallowOut, unshallow, ack } = sendPackForFetch(repo, wants, haves, shallow, deepen);
  const parts: Buffer[] = [];
  parts.push(pkt('acknowledgments\n'));
  if (ack.length === 0) parts.push(pkt('NAK\n'));
  else for (const a of ack) parts.push(pkt(`ACK ${a}\n`));
  parts.push(PKT_DELIM);
  if (shallowOut.length > 0 || unshallow.length > 0) {
    parts.push(pkt('shallow-info\n'));
    for (const s of shallowOut) parts.push(pkt(`shallow ${s}\n`));
    for (const s of unshallow) parts.push(pkt(`unshallow ${s}\n`));
    parts.push(PKT_DELIM);
  }
  if (pack !== null) {
    parts.push(pkt('packfile\n'));
    parts.push(sidebandPack(pack));
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function handleUploadPackV0(repo: Repo, body: Buffer): Buffer {
  const packets = decodePktLines(body);
  const sections: string[][] = [[]];
  for (const p of packets) {
    if (p.kind === 'flush') {
      sections.push([]);
      continue;
    }
    if (p.kind === 'data') sections[sections.length - 1].push(p.payload.toString('utf8'));
  }
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let deepen: number | undefined;
  for (const section of sections) {
    for (const raw of section) {
      const t = raw.trim();
      const firstSpace = t.indexOf(' ');
      const head = firstSpace < 0 ? t : t.slice(0, firstSpace);
      const rest = firstSpace < 0 ? '' : t.slice(firstSpace + 1);
      if (head === 'want') wants.push(rest.split(' ')[0]);
      else if (head === 'have') haves.push(rest);
      else if (head === 'shallow') shallow.push(rest);
      else if (head === 'deepen') {
        const n = Number(rest);
        if (Number.isSafeInteger(n) && n > 0) deepen = n;
      }
    }
  }
  const { pack, shallow: shallowOut, unshallow, ack } = sendPackForFetch(repo, wants, haves, shallow, deepen);
  const parts: Buffer[] = [];
  if (ack.length === 0) parts.push(pkt('NAK\n'));
  else for (const a of ack) parts.push(pkt(`ACK ${a}\n`));
  for (const s of shallowOut) parts.push(pkt(`shallow ${s}\n`));
  for (const s of unshallow) parts.push(pkt(`unshallow ${s}\n`));
  if (pack !== null) parts.push(sidebandPack(pack));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function handleReceivePack(repo: Repo, body: Buffer): Buffer {
  const packets = decodePktLines(body);
  const commands: Array<{ oldOid: string; newOid: string; ref: string; caps: string }> = [];
  let packStart = -1;
  // Find the first flush: everything after it (raw bytes) is the packfile.
  let off = 0;
  let firstFlushEnd = -1;
  while (off + 4 <= body.length) {
    const lenHex = body.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(lenHex)) break;
    const len = parseInt(lenHex, 16);
    if (len === 0) {
      firstFlushEnd = off + 4;
      break;
    }
    if (len < 4 || off + len > body.length) break;
    off += len;
  }
  void packets;
  void packStart;
  if (firstFlushEnd < 0) {
    // No flush: malformed; treat the whole body as pkt-lines.
    firstFlushEnd = body.length;
  }
  const cmdBuf = body.subarray(0, firstFlushEnd);
  const packBuf = body.subarray(firstFlushEnd);
  for (const p of decodePktLines(cmdBuf)) {
    if (p.kind !== 'data') continue;
    const text = p.payload.toString('utf8');
    const nul = text.indexOf('\0');
    const main = nul >= 0 ? text.slice(0, nul) : text;
    const caps = nul >= 0 ? text.slice(nul + 1) : '';
    const m = /^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)\s*$/.exec(main.trim());
    if (!m) continue;
    commands.push({ oldOid: m[1], newOid: m[2], ref: m[3], caps });
  }
  const sideband = commands.length > 0 && commands[0].caps.includes('side-band-64k');

  let unpackOk = true;
  let unpackDetail = 'ok';
  if (packBuf.length > 0) {
    try {
      const objects = readPack(packBuf, (oid) => repo.objects.get(oid));
      for (const [oid, obj] of objects) {
        if (!repo.objects.has(oid)) {
          repo.objects.set(oid, obj);
          repo.packVersion += 1;
        }
      }
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : 'unpack failed';
    }
  }

  const reportLines: string[] = [];
  reportLines.push(`unpack ${unpackOk ? 'ok' : unpackDetail}\n`);
  for (const cmd of commands) {
    let ok = false;
    let reason = '';
    if (!cmd.ref.startsWith('refs/')) {
      reason = 'invalid ref';
    } else if (!unpackOk) {
      reason = 'unpack failed';
    } else if (cmd.newOid === ZERO_OID) {
      const cur = repo.refs.get(cmd.ref);
      if (cur === undefined) reason = 'remote ref does not exist';
      else if (cmd.oldOid !== ZERO_OID && cmd.oldOid !== cur) reason = 'non-fast-forward';
      else {
        repo.refs.delete(cmd.ref);
        ok = true;
      }
    } else {
      const obj = repo.objects.get(cmd.newOid);
      if (!obj) {
        reason = 'object not found';
      } else if (cmd.oldOid === ZERO_OID) {
        if (repo.refs.has(cmd.ref)) reason = 'already exists';
        else {
          repo.refs.set(cmd.ref, cmd.newOid);
          ok = true;
        }
      } else {
        const cur = repo.refs.get(cmd.ref);
        if (cur === undefined) reason = 'remote ref does not exist';
        else if (cur !== cmd.oldOid) reason = 'non-fast-forward';
        else if (cmd.newOid === cmd.oldOid) ok = true;
        else {
          const newCommit = peelToCommit(repo, cmd.newOid);
          const oldCommit = peelToCommit(repo, cmd.oldOid);
          if (newCommit === null || oldCommit === null) reason = 'object not found';
          else if (!isAncestor(repo, oldCommit, newCommit)) reason = 'non-fast-forward';
          else {
            repo.refs.set(cmd.ref, cmd.newOid);
            ok = true;
          }
        }
      }
    }
    reportLines.push(ok ? `ok ${cmd.ref}\n` : `ng ${cmd.ref} ${reason}\n`);
  }
  const report = pktLines([...reportLines, 'flush']);
  if (sideband) {
    return Buffer.concat([pkt(Buffer.concat([Buffer.from([1]), report])), PKT_FLUSH]);
  }
  return report;
}

async function handleGit(req: IncomingMessage, res: ServerResponse, path: string, query: URLSearchParams, body: Buffer): Promise<boolean> {
  const method = req.method ?? 'GET';
  const m = /^\/([^/]+)\/([^/]+)\.git\/(.*)$/.exec(path);
  if (!m) return false;
  const owner = decodeURIComponent(m[1]);
  const repoName = decodeURIComponent(m[2]);
  const rest = m[3];
  const repo = findRepo(owner, repoName);
  if (!repo) {
    res.writeHead(404, { 'content-type': JSON_TYPE, 'x-github-request-id': reqId() });
    res.end(JSON.stringify({ message: 'Not Found' }));
    return true;
  }
  if (method === 'GET' && rest === 'info/refs') {
    const service = query.get('service') ?? '';
    if (service === 'git-upload-pack') {
      const proto = req.headers['git-protocol'] ?? '';
      const buf = proto === 'version=2' ? advertisementV2() : advertisementV0(repo, 'git-upload-pack');
      res.writeHead(200, {
        'content-type': 'application/x-git-upload-pack-advertisement',
        'content-length': buf.length,
        'x-github-request-id': reqId(),
      });
      res.end(buf);
      return true;
    }
    if (service === 'git-receive-pack') {
      const buf = advertisementV0(repo, 'git-receive-pack');
      res.writeHead(200, {
        'content-type': 'application/x-git-receive-pack-advertisement',
        'content-length': buf.length,
        'x-github-request-id': reqId(),
      });
      res.end(buf);
      return true;
    }
    res.writeHead(404, { 'content-type': JSON_TYPE, 'x-github-request-id': reqId() });
    res.end(JSON.stringify({ message: 'Not Found' }));
    return true;
  }
  if (method === 'POST' && rest === 'git-upload-pack') {
    const proto = req.headers['git-protocol'] ?? '';
    let buf: Buffer;
    try {
      buf = proto === 'version=2' ? handleUploadPackV2(repo, body) : handleUploadPackV0(repo, body);
    } catch {
      res.writeHead(400, { 'content-type': JSON_TYPE, 'x-github-request-id': reqId() });
      res.end(JSON.stringify({ message: 'Bad Request' }));
      return true;
    }
    res.writeHead(200, {
      'content-type': 'application/x-git-upload-pack-result',
      'content-length': buf.length,
      'x-github-request-id': reqId(),
    });
    res.end(buf);
    return true;
  }
  if (method === 'POST' && rest === 'git-receive-pack') {
    let buf: Buffer;
    try {
      buf = handleReceivePack(repo, body);
    } catch {
      res.writeHead(400, { 'content-type': JSON_TYPE, 'x-github-request-id': reqId() });
      res.end(JSON.stringify({ message: 'Bad Request' }));
      return true;
    }
    res.writeHead(200, {
      'content-type': 'application/x-git-receive-pack-result',
      'content-length': buf.length,
      'x-github-request-id': reqId(),
    });
    res.end(buf);
    return true;
  }
  res.writeHead(404, { 'content-type': JSON_TYPE, 'x-github-request-id': reqId() });
  res.end(JSON.stringify({ message: 'Not Found' }));
  return true;
}

// ---------------------------------------------------------------- GraphQL

interface GqlField {
  alias?: string;
  name: string;
  args: Record<string, unknown>;
  selections?: GqlSel[];
}
interface GqlFrag {
  __frag: true;
  typeCond: string;
  selections: GqlSel[];
}
type GqlSel = GqlField | GqlFrag;
interface GqlOp {
  kind: 'query' | 'mutation';
  selections: GqlSel[];
}

type Tok = { kind: 'punct' | 'name' | 'string' | 'number'; value: string };

function gqlTokenize(src: string): Tok[] {
  const toks: Tok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',') {
      i += 1;
      continue;
    }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (src.startsWith('...', i)) {
      toks.push({ kind: 'punct', value: '...' });
      i += 3;
      continue;
    }
    if ('!$()[]{}:=@&|'.includes(c)) {
      toks.push({ kind: 'punct', value: c });
      i += 1;
      continue;
    }
    if (c === '"') {
      if (src.startsWith('"""', i)) {
        const end = src.indexOf('"""', i + 3);
        const raw = end < 0 ? src.slice(i + 3) : src.slice(i + 3, end);
        toks.push({ kind: 'string', value: raw });
        i = end < 0 ? src.length : end + 3;
        continue;
      }
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const e = src[j + 1];
          out += e === 'n' ? '\n' : e === 't' ? '\t' : e === 'r' ? '\r' : e;
          j += 2;
        } else {
          out += src[j];
          j += 1;
        }
      }
      toks.push({ kind: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(c)) {
      let j = i;
      if (src[j] === '-') j += 1;
      while (j < src.length && /[0-9.]/.test(src[j])) j += 1;
      if (j < src.length && /[eE]/.test(src[j])) {
        j += 1;
        if (src[j] === '+' || src[j] === '-') j += 1;
        while (j < src.length && /[0-9]/.test(src[j])) j += 1;
      }
      toks.push({ kind: 'number', value: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[_A-Za-z]/.test(c)) {
      let j = i;
      while (j < src.length && /[_0-9A-Za-z]/.test(src[j])) j += 1;
      toks.push({ kind: 'name', value: src.slice(i, j) });
      i = j;
      continue;
    }
    i += 1; // skip anything else
  }
  return toks;
}

class GqlParser {
  private pos = 0;
  private readonly toks: Tok[];
  constructor(toks: Tok[]) {
    this.toks = toks;
  }

  private peek(): Tok | undefined {
    return this.toks[this.pos];
  }
  private next(): Tok | undefined {
    return this.toks[this.pos++];
  }
  private expect(value: string): void {
    const t = this.next();
    if (!t || t.value !== value) throw new Error(`expected ${value}, got ${t?.value ?? 'eof'}`);
  }
  private accept(value: string): boolean {
    if (this.peek()?.value === value) {
      this.pos += 1;
      return true;
    }
    return false;
  }

  parseDocument(): GqlOp[] {
    const ops: GqlOp[] = [];
    while (this.pos < this.toks.length) {
      ops.push(this.parseOperation());
    }
    return ops;
  }

  private parseOperation(): GqlOp {
    let kind: 'query' | 'mutation' = 'query';
    const t = this.peek();
    if (t?.kind === 'name' && (t.value === 'query' || t.value === 'mutation')) {
      kind = t.value as 'query' | 'mutation';
      this.pos += 1;
      // optional operation name
      if (this.peek()?.kind === 'name') this.pos += 1;
      // optional variable definitions
      if (this.peek()?.value === '(') this.skipParens();
    }
    const selections = this.parseSelectionSet();
    return { kind, selections };
  }

  private skipParens(): void {
    this.expect('(');
    let depth = 1;
    while (this.pos < this.toks.length && depth > 0) {
      const v = this.next()!.value;
      if (v === '(' || v === '[' || v === '{') depth += 1;
      else if (v === ')' || v === ']' || v === '}') depth -= 1;
    }
  }

  private parseSelectionSet(): GqlSel[] {
    this.expect('{');
    const sels: GqlSel[] = [];
    while (this.peek() && this.peek()!.value !== '}') {
      sels.push(this.parseSelection());
    }
    this.expect('}');
    return sels;
  }

  private parseSelection(): GqlSel {
    if (this.peek()?.value === '...') {
      this.pos += 1;
      if (this.peek()?.value === 'on') {
        this.pos += 1;
        const typeCond = this.next()!.value;
        const selections = this.parseSelectionSet();
        return { __frag: true, typeCond, selections };
      }
      // fragment spread (named) — unsupported; skip its selections if any
      if (this.peek()?.kind === 'name') this.pos += 1;
      return { __frag: true, typeCond: '', selections: [] };
    }
    let name = this.next()!.value;
    let alias: string | undefined;
    if (this.peek()?.value === ':') {
      this.pos += 1;
      alias = name;
      name = this.next()!.value;
    }
    const args: Record<string, unknown> = {};
    if (this.peek()?.value === '(') {
      this.pos += 1;
      while (this.peek() && this.peek()!.value !== ')') {
        const argName = this.next()!.value;
        this.expect(':');
        args[argName] = this.parseValue();
      }
      this.expect(')');
    }
    // directives (@...) — skip
    while (this.peek()?.value === '@') {
      this.pos += 1;
      if (this.peek()?.kind === 'name') this.pos += 1;
      if (this.peek()?.value === '(') this.skipParens();
    }
    let selections: GqlSel[] | undefined;
    if (this.peek()?.value === '{') selections = this.parseSelectionSet();
    return { name, alias, args, selections };
  }

  private parseValue(): unknown {
    const t = this.next()!;
    if (t.value === '$') {
      const name = this.next()!.value;
      return { __var: name };
    }
    if (t.value === '[') {
      const list: unknown[] = [];
      while (this.peek() && this.peek()!.value !== ']') list.push(this.parseValue());
      this.expect(']');
      return list;
    }
    if (t.value === '{') {
      const obj: Record<string, unknown> = {};
      while (this.peek() && this.peek()!.value !== '}') {
        const key = this.next()!.value;
        this.expect(':');
        obj[key] = this.parseValue();
      }
      this.expect('}');
      return obj;
    }
    if (t.kind === 'string') return t.value;
    if (t.kind === 'number') return Number(t.value);
    if (t.value === 'true') return true;
    if (t.value === 'false') return false;
    if (t.value === 'null') return null;
    return { __enum: t.value };
  }
}

const TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'author', 'createdAt', 'updatedAt', 'closedAt', 'labels', 'comments', 'url'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'headRef', 'baseRef', 'files', 'author', 'createdAt', 'updatedAt', 'closedAt', 'url'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'url', 'createdAt', 'updatedAt'],
  SearchType: [],
  User: ['id', 'login', 'name', 'email'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFileConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFile: ['path', 'filename'],
  IssueEdge: ['node', 'cursor'],
  PullRequestEdge: ['node', 'cursor'],
  PageInfo: ['hasNextPage', 'endCursor', 'hasPreviousPage', 'startCursor'],
  Comment: ['id', 'body', 'author', 'createdAt', 'updatedAt'],
  CommentEdge: ['node', 'cursor'],
  AddCommentPayload: ['commentEdge', 'clientMutationId'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  Query: ['viewer', 'repository', 'node', '__type', '__schema'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  __Type: ['name', 'fields', 'enumValues'],
  __Field: ['name'],
  __EnumValue: ['name'],
  Ref: ['name', 'target'],
  __Schema: ['types'],
};
const TYPE_ENUMS: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  OrderDirection: ['ASC', 'DESC'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  PullRequestMergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
};

type GqlObj = Record<string, unknown> & { __gqlType: string };

function gqlIssueObj(repo: Repo, issue: Issue): GqlObj {
  return { __gqlType: 'Issue', __repo: repo, __issue: issue, id: issue.nodeId, number: issue.number, title: issue.title, state: issue.state === 'open' ? 'OPEN' : 'CLOSED', body: issue.body };
}
function gqlPrObj(repo: Repo, pr: Pull): GqlObj {
  return {
    __gqlType: 'PullRequest',
    __repo: repo,
    __pr: pr,
    id: pr.nodeId,
    number: pr.number,
    state: pr.merged ? 'MERGED' : pr.state === 'open' ? 'OPEN' : 'CLOSED',
    merged: pr.merged,
    headRefName: pr.headRef,
    baseRefName: pr.baseRef,
    mergeable: pr.mergeable ? 'MERGEABLE' : 'CONFLICTING',
  };
}
function gqlRepoObj(repo: Repo): GqlObj {
  return { __gqlType: 'Repository', __repo: repo, id: repoGlobalId(repo), databaseId: repo.id, name: repo.name, nameWithOwner: `${repo.owner ?? viewerLogin ?? ''}/${repo.name}` };
}

function resolveVars(value: unknown, vars: Record<string, unknown>): unknown {
  if (value !== null && typeof value === 'object') {
    if (Array.isArray(value)) return value.map((v) => resolveVars(v, vars));
    const rec = value as Record<string, unknown>;
    if (typeof rec.__var === 'string') return vars[rec.__var] ?? null;
    if (typeof rec.__enum === 'string') return rec.__enum;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(rec)) out[k] = resolveVars(v, vars);
    return out;
  }
  return value;
}

function issueCursor(number: number): string {
  return b64urlEncode(`issue:${number}`);
}
function cursorNumber(cursor: string): number | null {
  const decoded = b64urlDecode(cursor);
  const m = /^issue:(\d+)$/.exec(decoded);
  return m ? Number(m[1]) : null;
}

function issuesConnection(repo: Repo, args: Record<string, unknown>): GqlObj {
  let list = [...repo.issues.values()];
  const states = args.states;
  if (Array.isArray(states) && states.length > 0) {
    const want = new Set(states.map((s) => String(s).toUpperCase()));
    list = list.filter((i) => want.has(i.state === 'open' ? 'OPEN' : 'CLOSED'));
  }
  const orderBy = (args.orderBy ?? {}) as Record<string, unknown>;
  const direction = String(orderBy.direction ?? 'DESC').toUpperCase();
  list.sort((a, b) => {
    const d = direction === 'ASC' ? a.seq - b.seq : b.seq - a.seq;
    if (d !== 0) return d;
    return direction === 'ASC' ? a.number - b.number : b.number - a.number;
  });
  const after = typeof args.after === 'string' ? cursorNumber(args.after) : null;
  if (after !== null) {
    const idx = list.findIndex((i) => i.number === after);
    if (idx >= 0) list = list.slice(idx + 1);
  }
  const first = typeof args.first === 'number' ? args.first : list.length;
  const page = list.slice(0, first);
  const hasNextPage = list.length > page.length;
  const endCursor = page.length > 0 ? issueCursor(page[page.length - 1].number) : null;
  return {
    __gqlType: 'IssueConnection',
    nodes: page.map((i) => gqlIssueObj(repo, i)),
    edges: page.map((i) => ({ __gqlType: 'IssueEdge', node: gqlIssueObj(repo, i), cursor: issueCursor(i.number) })),
    pageInfo: { __gqlType: 'PageInfo', hasNextPage, endCursor, hasPreviousPage: false, startCursor: page.length > 0 ? issueCursor(page[0].number) : null },
    totalCount: repo.issues.size,
  };
}

function prsConnection(repo: Repo, args: Record<string, unknown>): GqlObj {
  let list = [...repo.pulls.values()].sort((a, b) => b.seq - a.seq);
  const states = args.states;
  if (Array.isArray(states) && states.length > 0) {
    const want = new Set(states.map((s) => String(s).toUpperCase()));
    list = list.filter((p) => want.has(p.merged ? 'MERGED' : p.state === 'open' ? 'OPEN' : 'CLOSED'));
  }
  const first = typeof args.first === 'number' ? args.first : list.length;
  const page = list.slice(0, first);
  const hasNextPage = list.length > page.length;
  return {
    __gqlType: 'PullRequestConnection',
    nodes: page.map((p) => gqlPrObj(repo, p)),
    edges: page.map((p) => ({ __gqlType: 'PullRequestEdge', node: gqlPrObj(repo, p), cursor: issueCursor(p.number) })),
    pageInfo: { __gqlType: 'PageInfo', hasNextPage, endCursor: page.length > 0 ? issueCursor(page[page.length - 1].number) : null, hasPreviousPage: false, startCursor: null },
    totalCount: repo.pulls.size,
  };
}

function gqlFieldValue(typeName: string, obj: GqlObj, field: string, args: Record<string, unknown>, errors: Array<{ message: string }>): unknown {
  const repo = obj.__repo as Repo | undefined;
  switch (typeName) {
    case 'Query': {
      if (field === 'viewer') return { __gqlType: 'User', login: viewerLogin ?? '', id: 'V_1' };
      if (field === 'repository') {
        const owner = String(args.owner ?? '');
        const name = String(args.name ?? '');
        const r = findRepo(owner, name);
        return r ? gqlRepoObj(r) : null;
      }
      if (field === 'node') {
        const decoded = decodeGlobalId(String(args.id ?? ''));
        if (!decoded) return null;
        const r = reposById.get(decoded.repoId);
        if (!r) return null;
        if (decoded.kind === 'R') return gqlRepoObj(r);
        if (decoded.kind === 'I') {
          const issue = r.issues.get(decoded.number);
          return issue ? gqlIssueObj(r, issue) : null;
        }
        if (decoded.kind === 'P') {
          const pr = r.pulls.get(decoded.number);
          return pr ? gqlPrObj(r, pr) : null;
        }
        return null;
      }
      if (field === '__type') {
        const name = String(args.name ?? '');
        if (!(name in TYPE_FIELDS) && !(name in TYPE_ENUMS)) return null;
        return {
          __gqlType: '__Type',
          name,
          fields: (TYPE_FIELDS[name] ?? []).map((n) => ({ __gqlType: '__Field', name: n })),
          enumValues: (TYPE_ENUMS[name] ?? []).map((n) => ({ __gqlType: '__EnumValue', name: n })),
        };
      }
      if (field === '__schema') return { __gqlType: '__Schema', types: [] };
      break;
    }
    case 'Mutation': {
      const input = (args.input ?? {}) as Record<string, unknown>;
      if (field === 'createIssue') {
        const decoded = decodeGlobalId(String(input.repositoryId ?? ''));
        const r = decoded ? reposById.get(decoded.repoId) : undefined;
        if (!r) {
          errors.push({ message: 'repository not found' });
          return { __gqlType: 'CreateIssuePayload', issue: null };
        }
        const issue = createIssue(r, String(input.title ?? ''), typeof input.body === 'string' ? input.body : '', []);
        return { __gqlType: 'CreateIssuePayload', issue: gqlIssueObj(r, issue) };
      }
      if (field === 'closeIssue') {
        const decoded = decodeGlobalId(String(input.issueId ?? ''));
        const r = decoded ? reposById.get(decoded.repoId) : undefined;
        const issue = r?.issues.get(decoded?.number ?? -1);
        if (!issue) {
          errors.push({ message: 'issue not found' });
          return { __gqlType: 'CloseIssuePayload', issue: null };
        }
        issue.state = 'closed';
        return { __gqlType: 'CloseIssuePayload', issue: gqlIssueObj(r!, issue) };
      }
      if (field === 'createPullRequest') {
        const decoded = decodeGlobalId(String(input.repositoryId ?? ''));
        const r = decoded ? reposById.get(decoded.repoId) : undefined;
        if (!r) {
          errors.push({ message: 'repository not found' });
          return { __gqlType: 'CreatePullRequestPayload', pullRequest: null };
        }
        const pr = createPull(r, String(input.title ?? ''), typeof input.body === 'string' ? input.body : '', String(input.headRefName ?? ''), String(input.baseRefName ?? ''));
        if (!pr) {
          errors.push({ message: 'head or base branch does not exist' });
          return { __gqlType: 'CreatePullRequestPayload', pullRequest: null };
        }
        return { __gqlType: 'CreatePullRequestPayload', pullRequest: gqlPrObj(r, pr) };
      }
      if (field === 'mergePullRequest') {
        const decoded = decodeGlobalId(String(input.pullRequestId ?? ''));
        const r = decoded ? reposById.get(decoded.repoId) : undefined;
        const pr = r?.pulls.get(decoded?.number ?? -1);
        if (!pr) {
          errors.push({ message: 'pull request not found' });
          return { __gqlType: 'MergePullRequestPayload', pullRequest: null };
        }
        const result = squashMerge(r!, pr);
        if ('conflict' in result) {
          errors.push({ message: 'merge conflict' });
          return { __gqlType: 'MergePullRequestPayload', pullRequest: gqlPrObj(r!, pr) };
        }
        return { __gqlType: 'MergePullRequestPayload', pullRequest: gqlPrObj(r!, pr) };
      }
      if (field === 'addComment') {
        const decoded = decodeGlobalId(String(input.subjectId ?? ''));
        const r = decoded ? reposById.get(decoded.repoId) : undefined;
        const issue = r?.issues.get(decoded?.number ?? -1);
        if (!issue) {
          errors.push({ message: 'subject not found' });
          return { __gqlType: 'AddCommentPayload', commentEdge: null };
        }
        const comment: Comment = { id: nextGlobalId++, nodeId: '', body: String(input.body ?? ''), seq: nextSeq++ };
        comment.nodeId = globalId('C', r!.id, comment.id);
        issue.comments.push(comment);
        return {
          __gqlType: 'AddCommentPayload',
          commentEdge: { __gqlType: 'CommentEdge', node: { __gqlType: 'Comment', id: comment.nodeId, body: comment.body } },
        };
      }
      break;
    }
    case 'Repository': {
      if (!repo) return null;
      if (field === 'owner') return { __gqlType: 'User', login: repo.owner ?? viewerLogin ?? '', id: 'V_1' };
      if (field === 'defaultBranchRef') return { __gqlType: 'Ref', name: repo.defaultBranch };
      if (field === 'viewerPermission') return 'ADMIN';
      if (field === 'hasIssuesEnabled') return true;
      if (field === 'issue') {
        const issue = repo.issues.get(Number(args.number));
        return issue ? gqlIssueObj(repo, issue) : null;
      }
      if (field === 'issues') return issuesConnection(repo, args);
      if (field === 'pullRequests') return prsConnection(repo, args);
      if (field === 'pullRequest') {
        const pr = repo.pulls.get(Number(args.number));
        return pr ? gqlPrObj(repo, pr) : null;
      }
      if (field === 'description') return repo.description;
      if (field === 'url') return `/${repo.owner ?? ''}/${repo.name}`;
      break;
    }
    case 'PullRequest': {
      const pr = obj.__pr as Pull | undefined;
      if (!pr || !repo) return null;
      if (field === 'files') {
        const first = typeof args.first === 'number' ? args.first : pr.files.length;
        const nodes = pr.files.slice(0, first).map((f) => ({ __gqlType: 'PullRequestChangedFile', path: f.filename, filename: f.filename }));
        return { __gqlType: 'PullRequestChangedFileConnection', nodes, edges: nodes.map((n) => ({ __gqlType: 'PullRequestEdge', node: n, cursor: '' })), pageInfo: { __gqlType: 'PageInfo', hasNextPage: false, endCursor: null, hasPreviousPage: false, startCursor: null }, totalCount: pr.files.length };
      }
      break;
    }
    case 'IssueConnection':
    case 'PullRequestConnection':
    case 'PullRequestChangedFileConnection': {
      break;
    }
    default:
      break;
  }
  // Plain scalar / object fields stored on the object itself.
  if (field in obj && !field.startsWith('__')) return obj[field];
  return undefined;
}

function resolveSelections(
  typeName: string,
  obj: GqlObj,
  selections: GqlSel[],
  vars: Record<string, unknown>,
  errors: Array<{ message: string }>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const known = TYPE_FIELDS[typeName] ?? [];
  for (const sel of selections) {
    if ('__frag' in sel) {
      if (sel.typeCond === '' || sel.typeCond === typeName) {
        Object.assign(out, resolveSelections(typeName, obj, sel.selections, vars, errors));
      }
      continue;
    }
    const field = sel as GqlField;
    const alias = field.alias ?? field.name;
    if (field.name === '__typename') {
      out[alias] = typeName;
      continue;
    }
    if (!known.includes(field.name)) {
      errors.push({ message: `Cannot query field "${field.name}" on type "${typeName}".` });
      out[alias] = null;
      continue;
    }
    const args = resolveVars(field.args, vars) as Record<string, unknown>;
    const value = gqlFieldValue(typeName, obj, field.name, args, errors);
    if (value === undefined) {
      out[alias] = null;
      continue;
    }
    if (field.selections && value !== null && typeof value === 'object') {
      if (Array.isArray(value)) {
        out[alias] = value.map((item) => {
          if (item !== null && typeof item === 'object' && typeof (item as GqlObj).__gqlType === 'string') {
            return resolveSelections((item as GqlObj).__gqlType, item as GqlObj, field.selections!, vars, errors);
          }
          return item;
        });
      } else {
        const child = value as GqlObj;
        const childType = typeof child.__gqlType === 'string' ? child.__gqlType : typeName;
        out[alias] = resolveSelections(childType, child, field.selections, vars, errors);
      }
    } else {
      out[alias] = value;
    }
  }
  return out;
}

function executeGql(doc: string, variables: Record<string, unknown>): { data: unknown; errors?: Array<{ message: string }> } {
  const errors: Array<{ message: string }> = [];
  let ops: GqlOp[];
  try {
    ops = new GqlParser(gqlTokenize(doc)).parseDocument();
  } catch (err) {
    return { data: null, errors: [{ message: err instanceof Error ? err.message : 'parse error' }] };
  }
  const op = ops[0];
  if (!op) return { data: null, errors: [{ message: 'empty document' }] };
  const rootType = op.kind === 'mutation' ? 'Mutation' : 'Query';
  const root: GqlObj = { __gqlType: rootType };
  const data = resolveSelections(rootType, root, op.selections, variables, errors);
  return errors.length > 0 ? { data, errors } : { data };
}

async function handleGraphql(req: IncomingMessage, res: ServerResponse, body: Buffer): Promise<void> {
  if (!checkAuth(req)) {
    sendJson(res, 401, { message: 'Requires authentication' });
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    errJson(res, 400, 'Problems parsing JSON');
    return;
  }
  if (Array.isArray(parsed)) {
    const out = parsed.map((entry) => {
      const rec = (entry ?? {}) as Record<string, unknown>;
      const query = typeof rec.query === 'string' ? rec.query : '';
      const vars = (rec.variables ?? {}) as Record<string, unknown>;
      return executeGql(query, vars);
    });
    sendJson(res, 200, out);
    return;
  }
  const rec = (parsed ?? {}) as Record<string, unknown>;
  const query = typeof rec.query === 'string' ? rec.query : '';
  const vars = (rec.variables ?? {}) as Record<string, unknown>;
  sendJson(res, 200, executeGql(query, vars));
}

// ---------------------------------------------------------------- MCP

const MCP_TOOLS: Array<Record<string, unknown>> = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Issue state: open, closed or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        body: { type: 'string', description: 'Pull request body' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request by number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpToolResult(payload: unknown): Record<string, unknown> {
  const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return { content: [{ type: 'text', text }], structuredContent: payload };
}
function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function rpcResult(id: unknown, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id ?? null, result };
}
function rpcError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

async function handleMcp(req: IncomingMessage, res: ServerResponse, body: Buffer): Promise<void> {
  if (!checkAuth(req)) {
    sendJson(res, 401, { message: 'Bad credentials' });
    return;
  }
  const text = body.toString('utf8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    sendJson(res, 400, rpcError(null, -32700, 'Parse error'));
    return;
  }
  const rec = (parsed ?? {}) as Record<string, unknown>;
  const id = rec.id ?? null;
  const method = typeof rec.method === 'string' ? rec.method : '';
  const params = (rec.params ?? {}) as Record<string, unknown>;

  // Notifications (no id): acknowledge, no JSON-RPC body.
  if (id === null && rec.id === undefined) {
    sendNoBody(res, 202);
    return;
  }

  if (method === 'server/discover') {
    sendJson(res, 200, rpcResult(id, {
      resultType: 'discover',
      supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'],
      capabilities: { tools: {} },
      serverInfo: { name: 'forge', version: '1.0.0' },
      _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'forge', version: '1.0.0' } },
    }));
    return;
  }
  if (method === 'initialize') {
    const offered = (params as Record<string, unknown>).protocolVersion;
    const version = typeof offered === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(offered) ? offered : '2025-11-25';
    sendJson(res, 200, rpcResult(id, {
      protocolVersion: version,
      capabilities: { tools: {} },
      serverInfo: { name: 'forge', version: '1.0.0' },
    }));
    return;
  }
  if (method === 'tools/list') {
    sendJson(res, 200, rpcResult(id, { tools: MCP_TOOLS }));
    return;
  }
  if (method === 'tools/call') {
    const name = typeof params.name === 'string' ? params.name : '';
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    const tool = MCP_TOOLS.find((t) => t.name === name);
    if (!tool) {
      sendJson(res, 200, rpcError(id, -32602, `Unknown tool: ${name}`));
      return;
    }
    const schema = tool.inputSchema as Record<string, unknown>;
    const required = Array.isArray(schema.required) ? (schema.required as string[]) : [];
    const missing = required.filter((k) => args[k] === undefined || args[k] === null || args[k] === '');
    if (missing.length > 0) {
      sendJson(res, 200, rpcResult(id, mcpToolError(`Missing required argument: ${missing.join(', ')}`)));
      return;
    }
    try {
      const result = runMcpTool(name, args);
      if (typeof result === 'string') {
        // Tool-level error message.
        sendJson(res, 200, rpcResult(id, mcpToolError(result)));
        return;
      }
      sendJson(res, 200, rpcResult(id, mcpToolResult(result)));
    } catch (err) {
      sendJson(res, 200, rpcResult(id, mcpToolError(err instanceof Error ? err.message : 'tool failed')));
    }
    return;
  }
  if (method === 'ping') {
    sendJson(res, 200, rpcResult(id, {}));
    return;
  }
  sendJson(res, 200, rpcError(id, -32601, `Method not found: ${method}`));
}

function runMcpTool(name: string, args: Record<string, unknown>): unknown {
  const owner = typeof args.owner === 'string' ? args.owner : '';
  const repoName = typeof args.repo === 'string' ? args.repo : '';
  if (name === 'create_repo') {
    const repoNameArg = typeof args.name === 'string' ? args.name.trim() : '';
    if (repoNameArg === '') return 'Repository name is required';
    if (reposByName.has(repoNameArg)) return 'Repository already exists';
    const repo = createRepo(
      repoNameArg,
      typeof args.description === 'string' ? args.description : '',
      args.private === true,
    );
    if (owner !== '' && repo.owner === null) {
      repo.owner = owner;
      if (viewerLogin === null) viewerLogin = owner;
    }
    return repoObj(repo);
  }
  const repo = owner !== '' && repoName !== '' ? findRepo(owner, repoName) : null;
  if (!repo) return 'Repository not found';
  if (name === 'get_repo') return repoObj(repo);
  if (name === 'create_issue') {
    const title = typeof args.title === 'string' ? args.title : '';
    if (title === '') return 'Issue title is required';
    const issue = createIssue(repo, title, typeof args.body === 'string' ? args.body : '', []);
    return issueObj(repo, issue);
  }
  if (name === 'list_issues') {
    const state = typeof args.state === 'string' ? args.state.toLowerCase() : 'open';
    let list = [...repo.issues.values()];
    if (state !== 'all') list = list.filter((i) => i.state === state);
    list.sort((a, b) => b.seq - a.seq);
    return { issues: list.map((i) => issueObj(repo, i)) };
  }
  if (name === 'create_pull_request') {
    const title = typeof args.title === 'string' ? args.title : '';
    const head = typeof args.head === 'string' ? args.head : '';
    const base = typeof args.base === 'string' ? args.base : repo.defaultBranch;
    const pr = createPull(repo, title, typeof args.body === 'string' ? args.body : '', head, base);
    if (!pr) return 'head or base branch does not exist';
    return pullObj(repo, pr);
  }
  if (name === 'merge_pull_request') {
    const number = typeof args.pull_number === 'number' ? args.pull_number : Number(args.pull_number);
    const pr = repo.pulls.get(number);
    if (!pr) return 'Pull request not found';
    if (pr.merged) return pullObj(repo, pr);
    const result = squashMerge(repo, pr);
    if ('conflict' in result) return 'Merge conflict';
    return pullObj(repo, pr);
  }
  return 'Unknown tool';
}

// ---------------------------------------------------------------- server

function pathOf(req: IncomingMessage): string {
  try {
    return new URL(req.url ?? '/', 'http://entry').pathname;
  } catch {
    return '/';
  }
}

export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const path = pathOf(req);
        const method = req.method ?? 'GET';
        const query = new URL(req.url ?? '/', 'http://entry').searchParams;

        if (method === 'GET' && path === '/healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }

        const isGit = /^\/[^/]+\/[^/]+\.git\//.test(path);
        if (isGit) {
          const body = method === 'POST' ? await readBody(req) : Buffer.alloc(0);
          await handleGit(req, res, path, query, body);
          return;
        }

        if (path === '/api/graphql') {
          if (method !== 'POST') {
            errJson(res, 404, 'Not Found');
            return;
          }
          const body = await readBody(req);
          await handleGraphql(req, res, body);
          return;
        }

        if (path === '/mcp') {
          if (method !== 'POST') {
            errJson(res, 405, 'Method Not Allowed');
            return;
          }
          const body = await readBody(req);
          await handleMcp(req, res, body);
          return;
        }

        if (path === '/api/v3' || path.startsWith('/api/v3/')) {
          let body: unknown = {};
          let badJson = false;
          if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
            const raw = await readBody(req);
            if (raw.length > 0) {
              try {
                body = parseJsonBody(raw);
              } catch {
                badJson = true;
              }
            }
          }
          if (badJson) {
            if (!checkAuth(req)) {
              errJson(res, 401, 'Bad credentials');
              return;
            }
            errJson(res, 400, 'Problems parsing JSON');
            return;
          }
          await handleRest(req, res, path, query, body);
          return;
        }

        errJson(res, 404, 'Not Found');
      } catch (err) {
        if (!res.headersSent) {
          try {
            errJson(res, 500, err instanceof Error ? err.message : 'Internal Server Error');
          } catch {
            // response already gone
          }
        } else {
          try {
            res.end();
          } catch {
            // ignore
          }
        }
      }
    })();
  });
}
