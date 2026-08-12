import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawn } from 'node:child_process';
import { inflateRawSync } from 'node:zlib';

const repoRoot = path.resolve(import.meta.dirname, '..');
const artifactRoot = path.join(repoRoot, 'artifacts');
const evidenceRoot = path.join(repoRoot, 'evidence');
const helm = process.env.HELM_BIN || 'helm.exe';
const attachments = {
  "输入数据包.zip": "9473c365e3da1fb49178152a14ac17aed7935722ab28a2bab2c3794a17c392ff",
  "reference.zip": "93bac6670c80d59dbcb21cf54e70536d7c9329a0f725b7eff3ecd1db54baebbf",
  "关键标准答案.xlsx": "d20ead6308ee7ee2142f9b1aea13f077eabd70887d4d07e0170afdc93b05b27b",
  "任务规格转化.xlsx": "87a903ba95755e8b315ae03197684412a3e0c38b50e4eef45347bc1f87c90312"
};
const deliveryMembers = [
  "output/chart/search-gateway/Chart.yaml",
  "output/chart/search-gateway/templates/_helpers.tpl",
  "output/chart/search-gateway/templates/deployment.yaml",
  "output/chart/search-gateway/templates/hpa.yaml",
  "output/chart/search-gateway/templates/ingress.yaml",
  "output/chart/search-gateway/templates/service.yaml",
  "output/chart/search-gateway/values.schema.json",
  "output/chart/search-gateway/values.yaml",
  "output/rendered/prod-rollback.yaml",
  "output/rendered/prod.yaml",
  "output/rendered/staging.yaml",
  "output/reports/helm_lint_report.txt",
  "output/reports/rollback_delta.csv",
  "output/reports/tenant_limit_matrix.csv"
];
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const sha256File = (file) => sha256(fs.readFileSync(file));
const assert = (value, message) => { if (!value) throw new Error(message); };

function parseZipBytes(data) {
  const files = new Map(); let offset = 0;
  while (offset + 46 <= data.length) {
    if (data.readUInt32LE(offset) !== 0x02014b50) { offset += 1; continue; }
    const method = data.readUInt16LE(offset + 10), compressedSize = data.readUInt32LE(offset + 20), uncompressedSize = data.readUInt32LE(offset + 24), nameLength = data.readUInt16LE(offset + 28), extraLength = data.readUInt16LE(offset + 30), commentLength = data.readUInt16LE(offset + 32), localOffset = data.readUInt32LE(offset + 42);
    const name = data.subarray(offset + 46, offset + 46 + nameLength).toString('utf8').replaceAll('\\', '/');
    if (!name.endsWith('/')) { assert(data.readUInt32LE(localOffset) === 0x04034b50, 'ZIP header error'); const localNameLength = data.readUInt16LE(localOffset + 26), localExtraLength = data.readUInt16LE(localOffset + 28), start = localOffset + 30 + localNameLength + localExtraLength; const compressed = data.subarray(start, start + compressedSize); const body = method === 0 ? compressed : method === 8 ? inflateRawSync(compressed) : null; assert(body && body.length === uncompressedSize, 'ZIP extraction error'); files.set(name, body); }
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return files;
}
const parseZip = (file) => parseZipBytes(fs.readFileSync(file));
async function extractZip(file, destination) { for (const [name, bytes] of parseZip(file)) { const target = path.resolve(destination, name); assert(target.startsWith(path.resolve(destination) + path.sep), 'unsafe ZIP path'); await fsp.mkdir(path.dirname(target), { recursive: true }); await fsp.writeFile(target, bytes); } }
function workbookSheets(file) { const workbook = parseZipBytes(fs.readFileSync(file)).get('xl/workbook.xml')?.toString('utf8') ?? ''; return [...workbook.matchAll(/<(?:[A-Za-z]+:)?sheet[^>]+name="([^"]+)"/gu)].map((match) => match[1]); }
async function run(command, args, cwd, env = process.env) { const started = Date.now(); return await new Promise((resolve) => { let child; try { child = spawn(command, args, { cwd, env, windowsHide: true }); } catch (error) { resolve({ code: 1, stdout: '', stderr: error.stack ?? error.message, elapsed_ms: Date.now() - started }); return; } let stdout = '', stderr = '', settled = false; child.stdout.on('data', (chunk) => { stdout += chunk; }); child.stderr.on('data', (chunk) => { stderr += chunk; }); child.on('error', (error) => { if (!settled) { settled = true; resolve({ code: 1, stdout, stderr: stderr + (error.stack ?? error.message), elapsed_ms: Date.now() - started }); } }); child.on('exit', (code) => { if (!settled) { settled = true; resolve({ code: code ?? 1, stdout, stderr, elapsed_ms: Date.now() - started }); } }); }); }
function treeDigest(root, ignoredTop = new Set()) { const lines = []; function visit(current, prefix = '') { for (const entry of fs.readdirSync(current, { withFileTypes: true }).toSorted((a,b) => a.name.localeCompare(b.name))) { const relative = prefix ? prefix + '/' + entry.name : entry.name; if (!prefix && ignoredTop.has(entry.name)) continue; const full = path.join(current, entry.name); if (entry.isDirectory()) visit(full, relative); else lines.push(relative + '\0' + sha256File(full)); } } visit(root); return sha256(Buffer.from(lines.join('\n'))); }
function outputFiles(root) { const files = []; function visit(current, prefix = 'output') { for (const entry of fs.readdirSync(current, { withFileTypes: true })) { const relative = prefix + '/' + entry.name, full = path.join(current, entry.name); if (entry.isDirectory()) visit(full, relative); else files.push(relative.replaceAll('\\', '/')); } } visit(root); return files.sort(); }
function classifyExecutable(name, bytes) { const lower = name.toLowerCase(); if (bytes.length >= 4 && bytes[0] === 0x7f && bytes.subarray(1,4).toString('ascii') === 'ELF') return 'linux_elf'; if (/\.(?:sh|bash|so)(?:\.|$)/u.test(lower)) return 'posix_member'; if (/^#!.*(?:ba|z|k)?sh/mu.test(bytes.subarray(0,128).toString('utf8'))) return 'posix_shebang'; return null; }
function normalize(name, bytes) { const text = bytes.toString('utf8').replaceAll('\r\n','\n').trimEnd(); if (name.endsWith('.json')) return JSON.stringify(JSON.parse(text)); if (name.endsWith('.csv')) { const [head, ...rows] = text.split('\n'); return head + '\n' + rows.toSorted().join('\n'); } return text; }
function compareDelivery(outputRoot, standard) { assert(JSON.stringify(outputFiles(outputRoot)) === JSON.stringify(deliveryMembers), 'delivery member mismatch'); const hash = crypto.createHash('sha256'); for (const member of deliveryMembers) { const actual = fs.readFileSync(path.join(outputRoot, member.slice('output/'.length))), expected = standard.get(member); assert(expected, 'standard delivery member missing ' + member); const a = normalize(member, actual), e = normalize(member, expected); assert(a === e, 'delivery mismatch ' + member); hash.update(a); } return hash.digest('hex'); }
async function prepare(label, mutate) { const runRoot = path.join(os.tmpdir(), label); await fsp.rm(runRoot, { recursive: true, force: true }); await fsp.mkdir(runRoot, { recursive: true }); await extractZip(path.join(artifactRoot, '输入数据包.zip'), runRoot); const inputRoot = path.join(runRoot, 'input_data'), standard = parseZip(path.join(artifactRoot, 'reference.zip')); for (const [member, bytes] of standard) { if (!member.startsWith('output/chart/search-gateway/')) continue; const target = path.join(inputRoot, ...member.split('/')); await fsp.mkdir(path.dirname(target), { recursive: true }); await fsp.writeFile(target, bytes); } if (mutate) await mutate(inputRoot); return { inputRoot, outputRoot: path.join(inputRoot, 'output'), standard }; }
const execute = async (inputRoot) => await run(process.execPath, ['tools/run_task.mjs'], inputRoot, { ...process.env, HELM_BIN: helm });

await fsp.rm(evidenceRoot, { recursive: true, force: true }); await fsp.mkdir(evidenceRoot, { recursive: true });
assert(process.platform === 'win32' && process.env.GITHUB_ACTIONS === 'true', 'Windows hosted runner required');
for (const [file, expected] of Object.entries(attachments)) assert(sha256File(path.join(artifactRoot, file)) === expected, file + ' checksum mismatch');
const inputArchive = parseZip(path.join(artifactRoot, '输入数据包.zip')), standard = parseZip(path.join(artifactRoot, 'reference.zip'));
assert(JSON.stringify([...standard.keys()].sort()) === JSON.stringify(deliveryMembers), 'standard delivery member list mismatch');
const executableScan = [...inputArchive, ...standard].map(([name, bytes]) => ({ name, classification: classifyExecutable(name, bytes) })).filter((item) => item.classification); assert(executableScan.length === 0, 'platform-specific executable found');
assert(JSON.stringify(workbookSheets(path.join(artifactRoot,'关键标准答案.xlsx'))) === JSON.stringify(['交付物答案清单','固定字段答案','固定集合答案','固定数值答案','允许变体答案']), 'answer workbook sheets mismatch');
assert(JSON.stringify(workbookSheets(path.join(artifactRoot,'任务规格转化.xlsx'))) === JSON.stringify(['任务规格转化']), 'spec workbook sheets mismatch');
const runnerSource = inputArchive.get('input_data/tools/run_task.mjs')?.toString('utf8') ?? ''; assert(!/node:http|node:https|fetch\s*\(|axios|curl|wget/iu.test(runnerSource), 'business runner contains network implementation');
const version = await run(helm, ['version','--short'], repoRoot); assert(version.code === 0 && version.stdout.trim() === 'v3.17.3+ge4da497', 'Helm version mismatch');

const cleanRuns = [];
for (const label of ['Q10416 clean one', 'Q10416 中文 空格 clean two']) { const prepared = await prepare(label); const before = treeDigest(prepared.inputRoot, new Set(['output'])); const result = await execute(prepared.inputRoot); assert(result.code === 0, label + ' failed\n' + result.stdout + '\n' + result.stderr); const after = treeDigest(prepared.inputRoot, new Set(['output'])); assert(before === after, label + ' changed input'); const semantic = compareDelivery(prepared.outputRoot, prepared.standard); cleanRuns.push({ directory_label: label, exit_code: result.code, input_digest_before: before, input_digest_after: after, semantic_digest: semantic, elapsed_ms: result.elapsed_ms }); }
assert(cleanRuns[0].semantic_digest === cleanRuns[1].semantic_digest, 'clean run semantics differ');

const mutation = await prepare('Q10416 tenant limit change', async (inputRoot) => { const file = path.join(inputRoot,'values','env','prod-rollback.yaml'); const text = await fsp.readFile(file,'utf8'); assert(text.includes('"sustainedRps": 550'), 'mutation source not found'); await fsp.writeFile(file, text.replace('"sustainedRps": 550','"sustainedRps": 520')); });
let result = await execute(mutation.inputRoot); assert(result.code === 0, 'positive mutation failed');
const delta = (await fsp.readFile(path.join(mutation.outputRoot,'reports','rollback_delta.csv'),'utf8')).replaceAll('\r\n','\n'); assert(delta.includes(',600,520,tenant_limit_previous'), 'limit change not reflected in rollback delta');
const mutatedManifest = await fsp.readFile(path.join(mutation.outputRoot,'rendered','prod-rollback.yaml'),'utf8'); assert(/tenant-alpha-rps:\s*["']?520["']?/u.test(mutatedManifest), 'limit change not reflected in rendered manifest');

const invalid = await prepare('Q10416 invalid input', async (inputRoot) => { const file = path.join(inputRoot,'values','env','prod.yaml'); const text = await fsp.readFile(file,'utf8'); await fsp.writeFile(file, text.replace('"replicaCount": 6','"replicaCount": 0')); });
result = await execute(invalid.inputRoot); const renderedAbsent = !fs.existsSync(path.join(invalid.outputRoot,'rendered')), reportsAbsent = !fs.existsSync(path.join(invalid.outputRoot,'reports')); assert(result.code !== 0 && renderedAbsent && reportsAbsent, 'invalid input was accepted');

const evidence = { schema_version: 1, task_asset_id: 'helm_search_gateway_tenant_limit_rollback', result: 'PASS', generated_at_utc: new Date().toISOString(), git_commit_sha: process.env.GITHUB_SHA, workflow_run_id: process.env.GITHUB_RUN_ID, runner: { os: process.env.RUNNER_OS, arch: process.env.RUNNER_ARCH, image_os: process.env.ImageOS, image_version: process.env.ImageVersion, node: process.version, powershell_hosted_workflow: true }, software: { main: 'Helm', version: version.stdout.trim(), executed: true, commands: ['helm lint --strict','helm template'] }, attachment_sha256: attachments, workbook_checks: { answer_sheet_names: workbookSheets(path.join(artifactRoot,'关键标准答案.xlsx')), specification_sheet_names: workbookSheets(path.join(artifactRoot,'任务规格转化.xlsx')), task_spec_column_count: 2 }, platform_audit: { platform_specific_members: executableScan, linux_executables_executed: false, no_wsl_required: true, no_linux_container_required: true, no_posix_shell_required: true, no_unix_only_api_required: true, cross_platform_paths: true }, clean_runs: cleanRuns, reference_match: true, positive_mutation: { changed_input: 'prod-rollback alpha sustainedRps 550 to 520', exit_code: 0, delta_changed: true, rendered_manifest_changed: true }, invalid_input: { changed_input: 'prod replicaCount 6 to 0', exit_code: result.code, rendered_absent: renderedAbsent, reports_absent: reportsAbsent }, network: { installation_network_access: 'Helm installation only', formal_run_network_access: 'none, local Helm lint and template only' } };
await fsp.writeFile(path.join(evidenceRoot,'windows-verification.json'), JSON.stringify(evidence,null,2) + '\n'); console.log(JSON.stringify(evidence,null,2));
