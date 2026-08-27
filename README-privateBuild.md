# Private/snapshot build notes (cyclonedx-dotnet-library)

This repo is a long-lived fork of [CycloneDX/cyclonedx-dotnet-library](https://github.com/CycloneDX/cyclonedx-dotnet-library).
It previously carried ~3 years of custom work (a `BomEntity` base class
retrofitted onto ~50 model types, and a large configurable-strategy merge
engine built on it) forked at upstream tag `v6.0.0`. As of 2026-08-27, branch
`privateBuild/20260827-rebase` was **reset to `upstream/main`** (then at
`v12.1.2`) and that capability was re-implemented from scratch, idiomatically,
directly on top of current upstream — see "What's here" below. It is
consumed by the sibling repo `../cyclonedx-cli` **as a set of NuGet
packages**, not as a project reference, so a snapshot build here is only
useful once it is packed and made visible to that other repo. See
`../cyclonedx-cli/README-privateBuild.md` for the end-to-end, two-repo
procedure. This file covers just what happens inside this repo.

Verified against this checkout on 2026-08-27 (branch
`privateBuild/20260827-rebase`).

## 1. Prerequisites: .NET 8 and .NET 10 SDKs

`src/*` projects multi-target `netstandard2.0;net8.0;net10.0`; test
projects target `net8.0;net10.0`. This machine only had the .NET 6/7 SDKs
installed system-wide (`C:\Program Files\dotnet`, admin-owned). Attempting
`winget install Microsoft.DotNet.SDK.8`/`.10` hung indefinitely waiting on a
UAC elevation prompt that can't be answered non-interactively — if you hit
the same thing, kill the stuck `winget`/`dotnet-sdk-*-win-x64` processes and
install per-user instead, no elevation required:

```powershell
Invoke-WebRequest -Uri "https://dot.net/v1/dotnet-install.ps1" -OutFile "$env:TEMP\dotnet-install.ps1" -UseBasicParsing
& "$env:TEMP\dotnet-install.ps1" -Channel 8.0 -InstallDir "$env:LOCALAPPDATA\dotnet-custom" -NoPath
& "$env:TEMP\dotnet-install.ps1" -Channel 10.0 -InstallDir "$env:LOCALAPPDATA\dotnet-custom" -NoPath
```

This installs alongside (not merged with) the system SDKs, and copying into
`C:\Program Files\dotnet` also needs admin rights this session didn't have.
Simplest fix: point `dotnet` at the custom install for this work. Setting
this via `setx`/`[Environment]::SetEnvironmentVariable(..., "User")`
**does not** propagate to already-running shells/processes (only to new
top-level logon sessions) — in this session it had to be exported inline in
every command instead:

```sh
export PATH="$LOCALAPPDATA/dotnet-custom:$PATH"
export DOTNET_ROOT="$LOCALAPPDATA/dotnet-custom"
dotnet --list-sdks   # -> 8.0.424, 10.0.400
```

## 2. Plain build (sanity check)

```sh
dotnet build CycloneDXLibrary.sln -c Debug
```

Builds cleanly across all three target frameworks (`netstandard2.0`,
`net8.0`, `net10.0`) as checked in — no csproj/`.sln` fixes needed this
time (unlike the old `v6.0.0`-era fork, which needed an uncommitted
`netstandard2.0`→`net6.0` retarget hack; that's moot now, upstream already
multi-targets properly).

## 3. What's here: the merge-strategy port

Ported the fork's "merge multiple SBOMs with configurable strategies"
capability onto current upstream, **not** as a literal `BomEntity` port.
Research before starting found: no upstream equivalent exists (no common
base class/interface across model types beyond a minimal `IHasBomRef`);
upstream's own `src/CycloneDX.Utils/Merge.cs` predates the fork's
divergence and has independently grown (397→734 lines) to cover newer
CycloneDX 1.5/1.6 sections the fork's stale `Merge.cs` never got; and the
actual `BomEntity.cs` (2447 lines) turned out to hand-roll C# virtual
dispatch via reflection (`Type→MethodInfo` caches, `MethodInfo.Invoke`)
specifically to avoid using real interfaces — the exact pain point that
prompted re-evaluating the design instead of porting it as-is.

Design used instead — small interfaces with **default interface method**
bodies (C# 8+, requires `net8.0`/`net10.0`; **not available for
`netstandard2.0`**, so this entire capability is `#if NET8_0_OR_GREATER`-
gated and absent from that target, unchanged from before):

- `IBomEntity` (marker) / `IMergeable<T>` / `IEquivalent<T>` — new file
  `src/CycloneDX.Core/Models/Interfaces/IBomEntity.cs`. Each generic
  interface's method has a default body falling back to the type's own
  `IEquatable<T>`, so most model classes need only declare
  `: IMergeable<Foo>, IEquivalent<Foo>` (zero method bodies) to opt in.
  Real logic is written only where it's actually needed: `Component`
  (`src/CycloneDX.Core/Models/Component.cs`, field-by-field reconciliation
  including a `Scope` merge with an enum-selectable resolution — see
  `ComponentConflictResolution` on `MergeStrategy`, deliberately structured
  so a new resolution algorithm is a new enum case + orchestration
  function, not an interface/dispatch change) and `Hash` (content
  fill-in/mismatch-detection).
- `MergeStrategy` (`src/CycloneDX.Core/Models/MergeStrategy.cs`) — config
  POCO, ported from the fork's `BomEntityListMergeHelperStrategy`.
- `MergeableListHelper.Merge<T>` (`src/CycloneDX.Core/MergeableListHelper.cs`)
  — one generic-constrained (`where T : IEquatable<T>, IEquivalent<T>,
  IMergeable<T>`) method merges every mergeable list field in a `Bom`
  (components, services, hashes, external references, authors, ...) via
  real interface dispatch. No reflection anywhere in this path.
- `BomRefWalker.RewriteRefs(bom, rewrite)`
  (`src/CycloneDX.Core/BomRefWalker.cs`) — generalizes the per-type
  ref-rewriting `Merge.cs`'s `HierarchicalMerge` already hand-rolled for
  bom-ref namespacing into one reusable entry point parameterized on an
  arbitrary `Func<string,string>` instead of a fixed namespace prefix.
  Backs both merge's conflict-renaming and `Bom.RenameRef(old, new)`
  (`src/CycloneDX.Core/Models/Bom.cs`, alongside ported
  `BomMetadataUpdate`/`BomMetadataReferThisToolkit`).
- `CycloneDXUtils.FlatMerge(..., MergeStrategy)` /
  `HierarchicalMerge(..., MergeStrategy)` overloads in
  `src/CycloneDX.Utils/Merge.cs`, additive alongside the existing
  fixed-behavior overloads (which are unchanged, so existing callers see
  no behavior change).

**Fixed after initial review** (a second pass caught real behavior
differences from the old fork, not just missing features — worth reading
if you're relying on this):
- The *default* scope-conflict resolution originally landed backwards: the
  old fork's actual code always widened a Required-vs-Optional conflict to
  Required, but this port's first-draft default did the opposite (picked
  Optional) — a live behavior regression for `cyclonedx merge`, not just an
  internal detail. Fixed: `MergeStrategy.Default()` now uses
  `Squash_UpgradeScope`; the narrower reading is still available as
  `Squash_DowngradeScope` (renamed from `Squash` for clarity against its
  contrast).
- `Bom.RenameRef` used to silently rewrite `oldRef` to `newRef` even if
  `newRef` already identified something else in the document, potentially
  making two entities share one bom-ref. Now does a read-only collision
  check first and throws `InvalidOperationException` instead.
- `Dependency` now has a real `Equivalent`/`MergeWith` (matches on `Ref`,
  unions the two `Dependencies` sub-lists, gated by
  `MergeSubsetDependencies`) — previously it only had the `IMergeable<T>`
  default (exact equality), so two BOMs describing the same component with
  different direct-dependency lists would each contribute their own
  `<dependency ref="X">` entry instead of one combined entry. This is a
  separate code path from the `RenameRef` fix above (list-merge vs.
  rename-walker) — fixing one doesn't fix the other.
- `ComponentConflictResolution.Squash_RenameByScope` is now implemented:
  when two `Equivalent` components differ in `Scope`, they're kept as
  distinct entries suffixed `:scope=<value>` (e.g. `lp:scope=Required` /
  `lp:scope=Excluded`) instead of squashed or refused, with every
  back-reference rewritten to match. No suffix is added unless a real
  conflict appears — if every source agrees on `Scope`, the bom-ref is
  untouched. This is a genuinely new feature (the old fork's same-named
  toggle was never actually wired the way its own docs described), landed
  as its own commit. See `ApplyRenameByScope` in `Merge.cs`.

**Still-known gaps**:
- `BomRefWalker` covers the same entities the fork covered three years ago
  (`Metadata.Component`, `Components`, `Services`, `Dependencies`,
  `Compositions`, `Vulnerabilities`, `Annotations`) — not yet the newer
  (1.6) `Declarations`/`Definitions` sections. Not a regression (the fork
  never had these either, they postdate it), just a current limitation.
- CLI exposes `--component-conflict-resolution` (see the CLI README) but
  no other `MergeStrategy` toggle (`UseEntityMerge`,
  `RenameConflictingComponents`, `MergeSubsetDependencies`,
  `TreatDependencyAsExtraProperty`, the `DoBomMetadataUpdate*` group) is
  CLI-selectable yet — all still hardcoded via `MergeStrategy.Default()`.

## 4. Pack & publish to the local feed

Same mechanism as before, bumped for the new base version. NuGet must not
resolve to the real, unmodified `nuget.org` package at the plain `12.1.2`
version this fork also reports — pack under a version that only exists
locally:

```sh
LIBVER=12.1.2.2-privateBuild.20260827   # bump the trailing counter each rebuild
dotnet pack CycloneDXLibrary.sln -c Debug -p:Version="$LIBVER"
for P in src/CycloneDX.Core/bin/Debug/CycloneDX.Core.$LIBVER.nupkg \
         src/CycloneDX.Utils/bin/Debug/CycloneDX.Utils.$LIBVER.nupkg \
         src/CycloneDX.Spdx/bin/Debug/CycloneDX.Spdx.$LIBVER.nupkg \
         src/CycloneDX.Spdx.Interop/bin/Debug/CycloneDX.Spdx.Interop.$LIBVER.nupkg ; do
  dotnet nuget push "$P" -s userhome
done
```

`userhome` is the same folder-based local feed
(`C:\Users\klimov\.nuget`) set up in the prior snapshot-build session; see
`../cyclonedx-cli/README-privateBuild.md` §1 if it needs to be recreated.

## 5. Tests

```sh
dotnet test CycloneDXLibrary.sln --framework net10.0
```

`CycloneDX.Utils.Tests` (includes `MergeStrategyTests.cs`, 18 focused unit
tests covering `Component`/`Hash`/`Dependency` merge logic, the flipped
default scope resolution, `RenameRef` collision refusal, strategy-aware
`FlatMerge`, and three `Squash_RenameByScope` scenarios including the
back-reference-fixup regression a test caught mid-implementation):
**43/43 passed.**
`CycloneDX.Spdx.Tests`/`CycloneDX.Spdx.Interop.Tests`: all passed.
`CycloneDX.Core.Tests`: ~300 failures, **all** in `Protobuf.*` serialization/
validation tests — confirmed unrelated to this work (nothing touched here
involves protobuf), almost certainly this machine lacking the `protoc`
compiler the CI workflow explicitly installs on Linux
(`.github/workflows/dotnetcore.yml`) but that isn't set up here. Worth
installing `protoc` locally to get a clean baseline before trusting this
number as "0 known failures," but it isn't a regression from this session.

## 6. Consuming this snapshot

See `../cyclonedx-cli/README-privateBuild.md`.
