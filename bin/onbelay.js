#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  renameSync,
  rmSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageJson = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8"));
const version = readFileSync(join(packageRoot, "VERSION"), "utf8").trim();

if (packageJson.version !== version) {
  fail(`package.json is ${packageJson.version}, but VERSION is ${version}`);
}

const payload = [
  "AGENTS.md",
  "LICENSE",
  "THIRD-PARTY-NOTICES.md",
  "VERSION",
  "hooks",
  "install.sh",
  "operator-profiles",
  "operator-skills",
  "output-styles",
  "scripts",
  "skills",
  "templates",
  "uninstall.sh",
];

const profiles = new Set(["guard", "workflow", "operator", "full", "standard"]);
const installRoot = join(homedir(), ".local", "share", "onbelay");
const versionRoot = join(installRoot, version);

function fail(message) {
  process.stderr.write(`onbelay: ${message}\n`);
  process.exit(1);
}

function help() {
  process.stdout.write(`onbelay ${version}\n\n`);
  process.stdout.write("Usage:\n");
  process.stdout.write("  onbelay install [guard] [--extras] [--keep-existing|--replace-conflicts]\n");
  process.stdout.write("  onbelay doctor [--extras]\n");
  process.stdout.write("  onbelay init\n");
  process.stdout.write("  onbelay uninstall\n\n");
  process.stdout.write("Install adds guardrails, 13 workflow skills, and automatic routing.\n");
  process.stdout.write("Use --extras to add research, wizard, handoff, and output styles.\n");
  process.stdout.write("Use `install guard` for the guardrails alone, with no skills.\n");
}

function assertPlatform() {
  if (process.platform === "win32") {
    fail("native Windows is not supported. Use macOS or Linux");
  }
}

function run(script, args, cwd = process.cwd(), extraEnv = {}) {
  execFileSync("bash", [script, ...args], {
    cwd,
    env: { ...process.env, ...extraEnv },
    stdio: "inherit",
  });
}

function verifyPayload(source, target, relative) {
  if (!existsSync(target)) {
    fail(`${versionRoot} is missing ${relative}`);
  }
  const sourceStat = lstatSync(source);
  const targetStat = lstatSync(target);
  if (sourceStat.isSymbolicLink() || targetStat.isSymbolicLink()) {
    fail(`${versionRoot}/${relative} must not be a symlink`);
  }
  if (sourceStat.isDirectory()) {
    if (!targetStat.isDirectory()) {
      fail(`${versionRoot}/${relative} does not match the published package`);
    }
    for (const name of readdirSync(source)) {
      verifyPayload(join(source, name), join(target, name), join(relative, name));
    }
    return;
  }
  if (!sourceStat.isFile() || !targetStat.isFile()
      || !readFileSync(source).equals(readFileSync(target))) {
    fail(`${versionRoot}/${relative} does not match the published package`);
  }
}

function stagePayload() {
  if (existsSync(versionRoot)) {
    if (!existsSync(join(versionRoot, "VERSION"))) {
      fail(`${versionRoot} exists but is not a valid ${version} installation`);
    }
    const installedVersion = readFileSync(join(versionRoot, "VERSION"), "utf8").trim();
    if (installedVersion !== version || !existsSync(join(versionRoot, "install.sh"))) {
      fail(`${versionRoot} exists but is not a valid ${version} installation`);
    }
    for (const relative of payload) {
      verifyPayload(join(packageRoot, relative), join(versionRoot, relative), relative);
    }
    return versionRoot;
  }

  mkdirSync(installRoot, { recursive: true });
  const staging = join(installRoot, `.${version}-${process.pid}`);
  if (existsSync(staging)) {
    fail(`temporary installation path already exists: ${staging}`);
  }

  mkdirSync(staging);
  try {
    for (const relative of payload) {
      const source = join(packageRoot, relative);
      if (!existsSync(source)) {
        fail(`published package is missing ${relative}`);
      }
      cpSync(source, join(staging, relative), { recursive: true, errorOnExist: true });
    }
    renameSync(staging, versionRoot);
  } catch (error) {
    if (existsSync(staging)) {
      rmSync(staging, { recursive: true, force: true });
    }
    throw error;
  }
  return versionRoot;
}

function parseProfile(args, fallback) {
  const profile = args[0] && profiles.has(args[0]) ? args.shift() : fallback;
  return profile;
}

function installedRoot() {
  const candidates = [versionRoot];
  const claudeRoot = process.env.CLAUDE_CONFIG_DIR || join(homedir(), ".claude");
  const origins = join(claudeRoot, ".onbelay-origins");
  if (existsSync(origins)) {
    candidates.push(...readFileSync(origins, "utf8").split(/\r?\n/).filter(Boolean).reverse());
  }
  return candidates.find((candidate) =>
    existsSync(join(candidate, "VERSION")) && existsSync(join(candidate, "install.sh"))
  );
}

function extrasInstalled() {
  const claudeRoot = process.env.CLAUDE_CONFIG_DIR || join(homedir(), ".claude");
  const candidates = [
    ...["research", "wizard", "handoff"].map((name) =>
      join(claudeRoot, "skills", name)),
    join(claudeRoot, "output-styles", "terse.md"),
  ];
  return candidates.some((candidate) => {
    try {
      return lstatSync(candidate).isSymbolicLink()
        && /\/(operator-skills|output-styles)\//.test(readlinkSync(candidate));
    } catch {
      return false;
    }
  });
}

function install(args) {
  assertPlatform();
  const explicitProfile = args[0] && profiles.has(args[0]);
  let profile = parseProfile(args, "standard");
  if (args.includes("--extras")) {
    if (explicitProfile) fail("--extras cannot be combined with an explicit profile");
    profile = "full";
    args = args.filter((arg) => arg !== "--extras");
  }
  for (const arg of args) {
    if (!["--baseline", "--skills-only", "--keep-existing", "--replace-conflicts"].includes(arg)) {
      fail(`unknown install option: ${arg}`);
    }
  }
  const root = stagePayload();
  run(join(root, "install.sh"), [profile, ...args], process.cwd(),
      { ONBELAY_COMPACT: "1" });
}

// What is actually on this machine, so `doctor` checks the install the user
// HAS rather than the one it assumes they wanted. It defaulted to
// standard/full, so a `install guard` machine, which the README gives its own
// section and recommends to anyone who does not want the skills, got 30
// fabricated errors and exit 1 with nothing wrong. The remediation it printed
// was wrong twice over: `./install.sh` does not exist for an npx user, and
// running it would install the 13 skills they deliberately opted out of.
function detectProfile() {
  const claudeRoot = process.env.CLAUDE_CONFIG_DIR || join(homedir(), ".claude");
  if (extrasInstalled()) return "full";
  const linkedWorkflowSkill = ["ship", "tdd", "review"].some((name) => {
    try {
      return lstatSync(join(claudeRoot, "skills", name)).isSymbolicLink();
    } catch {
      return false;
    }
  });
  if (linkedWorkflowSkill) return "standard";
  try {
    if (lstatSync(join(claudeRoot, "hooks", "guard-bash.py")).isSymbolicLink()) {
      return "guard";
    }
  } catch {
    // fall through
  }
  return "standard";
}

function doctor(args) {
  assertPlatform();
  const explicitProfile = args[0] && profiles.has(args[0]);
  // `args.includes`, not `args[0] ===`. parseProfile SHIFTS the profile off
  // first, so testing position 0 afterwards tested the wrong token:
  // `doctor guard --extras` silently ignored both the conflict and the flag
  // and checked `full`. install() has always used includes; this did not.
  const wantsExtras = args.includes("--extras");
  if (explicitProfile && wantsExtras) {
    fail("--extras cannot be combined with an explicit profile");
  }
  let profile = parseProfile(args, detectProfile());
  if (wantsExtras) {
    profile = "full";
    args = args.filter((arg) => arg !== "--extras");
  }
  if (args.length) {
    fail(`unknown doctor option: ${args[0]}`);
  }
  const root = installedRoot();
  if (!root) {
    fail("no installed payload found. Run install first");
  }
  run(join(root, "install.sh"), [profile, "--check"], process.cwd(),
      { ONBELAY_COMPACT: "1" });
}

function init(args) {
  assertPlatform();
  if (args.length) {
    fail(`init takes no arguments: ${args[0]}`);
  }
  run(join(packageRoot, "scripts", "agent-init"), [], process.cwd());
}

function uninstall(args) {
  assertPlatform();
  const profile = parseProfile(args, "full");
  if (args.length) {
    fail(`unknown uninstall option: ${args[0]}`);
  }
  const root = installedRoot();
  if (!root) {
    fail("no installed payload found");
  }
  run(join(root, "uninstall.sh"), [profile]);
}

const [command = "help", ...args] = process.argv.slice(2);

try {
  if (command === "help" || command === "--help" || command === "-h") help();
  else if (command === "--version" || command === "-v") process.stdout.write(`${version}\n`);
  else if (command === "install") install(args);
  else if (command === "doctor" || command === "check") doctor(args);
  else if (command === "init") init(args);
  else if (command === "uninstall") uninstall(args);
  else fail(`unknown command: ${command}`);
} catch (error) {
  if (error && typeof error.status === "number") {
    process.exit(error.status || 1);
  }
  fail(error instanceof Error ? error.message : String(error));
}
