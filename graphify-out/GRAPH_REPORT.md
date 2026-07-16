# Graph Report - .  (2026-07-16)

## Corpus Check
- 63 files · ~185,159 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 112 nodes · 106 edges · 16 communities (9 shown, 7 thin omitted)
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- Dependencies and PDF Signing
- Electron Build Config
- Electron Package Metadata
- Protected Build Scripts
- Root Dev Dependencies
- Electron Dev Dependencies
- Linux Build Targets
- Electron NPM Scripts
- Root NPM Scripts
- Mac Build Script
- Client Options Interfaces
- Client Batch Result
- Client Definition
- Client Error Result
- Client Health Info
- Client Sign Result

## God Nodes (most connected - your core abstractions)
1. `build` - 9 edges
2. `scripts` - 7 edges
3. `scripts` - 6 edges
4. `author` - 4 edges
5. `linux` - 4 edges
6. `target` - 4 edges
7. `Ensure-Directory()` - 3 edges
8. `Sync-BundledNodeRuntime()` - 3 edges
9. `files` - 3 edges
10. `win` - 3 edges

## Surprising Connections (you probably didn't know these)
- None detected - all connections are within the same source files.

## Import Cycles
- None detected.

## Communities (16 total, 7 thin omitted)

### Community 0 - "Dependencies and PDF Signing"
Cohesion: 0.07
Nodes (27): asn1js, bytenode, cors, dotenv, express, multer, dependencies, asn1js (+19 more)

### Community 1 - "Electron Build Config"
Cohesion: 0.12
Nodes (16): build, afterPack, appId, extraResources, files, mac, productName, win (+8 more)

### Community 2 - "Electron Package Metadata"
Cohesion: 0.15
Nodes (12): author, email, name, url, description, homepage, icon, main (+4 more)

### Community 3 - "Protected Build Scripts"
Cohesion: 0.29
Nodes (6): Clear-Directory(), Ensure-Directory(), Ensure-FileExists(), Invoke-BytenodeCompile(), Invoke-Checked(), Sync-BundledNodeRuntime()

### Community 4 - "Root Dev Dependencies"
Cohesion: 0.20
Nodes (9): esbuild, javascript-obfuscator, devDependencies, esbuild, javascript-obfuscator, name, private, type (+1 more)

### Community 5 - "Electron Dev Dependencies"
Cohesion: 0.29
Nodes (7): electron, devDependencies, electron, electron-builder, @electron/fuses, electron-builder, @electron/fuses

### Community 6 - "Linux Build Targets"
Cohesion: 0.29
Nodes (7): linux, icon, maintainer, target, AppImage, deb, rpm

### Community 7 - "Electron NPM Scripts"
Cohesion: 0.29
Nodes (7): scripts, build, build:linux, build:mac, build:win, dev, electron

### Community 8 - "Root NPM Scripts"
Cohesion: 0.33
Nodes (6): scripts, build:mac, build:protected, build:win, dev, start

## Knowledge Gaps
- **68 isolated node(s):** `build-mac.sh script`, `name`, `version`, `description`, `main` (+63 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **7 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `build` connect `Electron Build Config` to `Electron Package Metadata`, `Linux Build Targets`?**
  _High betweenness centrality (0.129) - this node is a cross-community bridge._
- **Why does `dependencies` connect `Dependencies and PDF Signing` to `Root Dev Dependencies`?**
  _High betweenness centrality (0.119) - this node is a cross-community bridge._
- **Why does `scripts` connect `Electron NPM Scripts` to `Electron Package Metadata`?**
  _High betweenness centrality (0.045) - this node is a cross-community bridge._
- **What connects `build-mac.sh script`, `name`, `version` to the rest of the system?**
  _68 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Dependencies and PDF Signing` be split into smaller, more focused modules?**
  _Cohesion score 0.07407407407407407 - nodes in this community are weakly interconnected._
- **Should `Electron Build Config` be split into smaller, more focused modules?**
  _Cohesion score 0.125 - nodes in this community are weakly interconnected._