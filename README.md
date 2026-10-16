SLPS: A Security Lattice-Based Proxy Signature for Finance Applications

Research implementation accompanying the paper **“SLPS: A Security Lattice-Based Proxy Signature for Finance Applications”** by Weizhi Wang, Zhidong Xiong, Chenxi Sun, Mengdi Zhao, and Huiyan Chen.

SLPS (Security Lattice-based Proxy Signature) supports ordinary signatures and delegated proxy signatures within a common lattice-based framework. A principal issues an authorization credential to an agent, who then signs messages on the principal’s behalf using the credential and the agent’s own secret key. The paper motivates this construction through supply chain finance digital bills.

This repository provides C source code, a complete workflow demonstration, and a benchmark driver. It reuses Dilithium/ML-DSA arithmetic and SHAKE components; SLPS has its own algorithms and encodings and should not be treated as a FIPS 204 conformant ML-DSA implementation.

## Implemented algorithms

| Paper algorithm | C entry point | Purpose |
| --- | --- | --- |
| Setup | `slps_setup` | Derive shared public parameters from a seed |
| UserKeyGen | `slps_user_key_gen` | Generate a user key pair associated with an identity |
| UserSign | `slps_user_sign` | Generate an ordinary signature |
| UserVerify | `slps_user_verify` | Verify an ordinary signature |
| PrincipalAuthorizeAgent | `slps_principal_authorize_agent` | Issue a credential authorizing an agent |
| CredentialVerify | `slps_credential_verify` | Verify an authorization credential |
| AgentSign | `slps_agent_sign` | Generate a proxy signature |
| AgentVerify | `slps_agent_verify` | Verify a proxy signature |

The workflow is:

```text
Setup -> principal and agent key generation
      -> ordinary signing -> ordinary verification
      -> principal authorization -> credential verification
      -> proxy signing -> proxy verification
```

The construction uses Fiat–Shamir with aborts and credential-based delegation, without Gaussian sampling or trapdoor delegation. The paper presents its correctness and security arguments; those arguments are separate from implementation testing.

## Repository layout

Paths below are relative to the directory containing this README.

```text
.
|-- slps.c / slps.h                 SLPS algorithms and public interface
|-- slps_packing.c / slps_packing.h SLPS serialization
|-- main.c                         End-to-end demonstration and per-operation timing
|-- bench.c                        Seed scanning and repeated timing
|-- config.h / params.h            Parameter selection and size definitions
|-- poly*.c / poly*.h               Polynomial and vector arithmetic
|-- ntt.* / reduce.* / rounding.*   Arithmetic primitives
|-- fips202.* / symmetric*          SHAKE and symmetric primitives
|-- packing.* / sign.*             Supporting Dilithium-style components
|-- randombytes.*                  Platform random-byte implementation
|-- slps.sln / slps.vcxproj         Visual Studio solution and project
|-- rand_slps_cross.txt             Hexadecimal seed data
`-- SLPS_ML-DSA/                    Additional SCLLS implementation files
```

Build the SLPS implementation from this directory. The nested `SLPS_ML-DSA/` directory contains `sclls.c`, `sclls1.c`, and a separate `main.c`; do not mix its sources into the SLPS build. Avoid compiling every C file with a wildcard because `main.c` and `bench.c` define separate program entry points.

## Requirements

- Windows, because the supplied demonstration and benchmark use `windows.h` and `QueryPerformanceCounter`.
- A C compiler: MSVC for the supplied Visual Studio project, or MinGW-w64 GCC for the benchmark command below.
- No external cryptographic library is required for the benchmark build below.

The project file currently requests the `v145` MSVC platform toolset and a Windows 10 SDK. Install the requested toolset or retarget the project to your installed toolset and SDK. The supplied drivers have not been validated on Linux or macOS.

## Quick start

### Full demonstration with Visual Studio

1. Open `slps.sln`.
2. Select **Release** and **x64**.
3. Retarget the toolset/SDK if requested, then build and run the `SLPS` project.

The project includes `main.c`, which exercises all eight algorithms, prints operation times in milliseconds, and reports serialized object sizes. Successful verification should print:

```text
User-Verify: SUCCESS
Credential-Verify: SUCCESS
Agent-Verify: SUCCESS
```

Inspect these messages: the demonstration returns zero even when a verification reports failure. Its fixed seeds, identities, and 32-byte message are reproducible test inputs.

If the linker reports unresolved Windows CryptoAPI functions from `randombytes.c`, add `Advapi32.lib` under **Linker > Input > Additional Dependencies**. The project also lists a root-level `api.h` that is absent from the supplied directory; this is a stale project header entry rather than the SLPS API. The SLPS API is in `slps.h`.

### Benchmark with MinGW-w64 GCC

Open PowerShell in this directory and run:

```powershell
gcc -O2 -DDILITHIUM_MODE=5 -o bench.exe bench.c slps.c slps_packing.c fips202.c ntt.c packing.c poly.c polyvec.c reduce.c rounding.c symmetric-shake.c
.\bench.exe scan 0 1 100000 1
```

This source list builds the benchmark without `main.c`, `sign.c`, or `randombytes.c`. Inputs are derived deterministically inside `bench.c`.

A local Windows/MinGW check of the command above produced:

```text
# mode=scan start=0 count=1 thresh=100000 level=5
Q,0,1,5,4,10,0
S,1,0,1
```

This is a one-input workflow smoke test, not a full correctness or security evaluation. GCC emitted warnings about discarded `const` qualifiers in `polyvec.c`. The Visual Studio demonstration and the other parameter modes were not executed as part of this check.

## Parameter selection

`config.h` defaults to `DILITHIUM_MODE=5`. Define `DILITHIUM_MODE` consistently for all translation units to select another supported mode.

| `DILITHIUM_MODE` | K | L | ETA | Challenge bytes |
| --- | ---: | ---: | ---: | ---: |
| 2 | 4 | 4 | 2 | 32 |
| 3 | 6 | 5 | 4 | 48 |
| 5 (default) | 8 | 7 | 2 | 64 |

All modes use `N=256` and `Q=8380417`. Parameter names are inherited from the underlying code; the mode number is not an independent certification of SLPS security.

The following serialized sizes, in bytes, follow from `params.h` and `slps.h`:

| Object | Mode 2 | Mode 3 | Mode 5 |
| --- | ---: | ---: | ---: |
| Shared public parameters | 32 | 32 | 32 |
| User public key | 2944 | 4416 | 5888 |
| User secret key | 864 | 1504 | 1536 |
| Authorization credential | 2400 | 3312 | 4608 |
| Ordinary signature | 2336 | 3248 | 4544 |
| Proxy signature | 3008 | 4224 | 5856 |

These are SLPS sizes, excluding application framing and separately supplied keys, parameters, and identities. No separate delegated secret key is generated, but public authorization credentials still occupy storage.

## Benchmark usage

### Scan deterministic inputs

```powershell
.\bench.exe scan 0 100 5 1
```

Arguments are `scan <start> <count> <threshold> [verbose]`. Each index deterministically generates a 32-byte master seed using SHAKE256; other inputs are derived using domain labels. A qualifying input must pass all three verifications and use no more than `threshold` loop iterations in each of ordinary signing, authorization, and proxy signing.

| Record | Fields after the prefix |
| --- | --- |
| `F` | index, verification failure mask |
| `Q` | qualifying index, ordinary-sign iterations, authorization iterations, proxy-sign iterations, total iterations, failure mask |
| `V` | same fields as `Q`, for other inputs when verbose output is enabled |
| `S` | scanned inputs, failed inputs, qualifying inputs |

The iteration counters include the accepted attempt. Failure mask bits are `1` for ordinary verification, `2` for credential verification, and `4` for proxy verification; values can be combined.

### Time selected indices

Create a plain-text file containing one decimal index per line. For a small example using index zero:

```powershell
Set-Content -Encoding ascii indices.txt '0'
.\bench.exe time indices.txt 10
```

Arguments are `time <index-file> <repetitions>`, with a positive repetition count. Timing output uses microseconds:

- `T,index,avg_total_us,avg_total_iterations`: averages for one index.
- `A,runs,avg_total_us,avg_user_sign_us,avg_authorize_us,avg_agent_sign_us,avg_total_iterations,failed_runs`: aggregate statistics.

The total time covers setup, both key generations, signing, authorization, and all three verification operations. The three individual timings cover only the three sampling algorithms. The hexadecimal lines in `rand_slps_cross.txt` are not the decimal index format expected by `bench time`.

To time only qualifying indices, collect the index field from `Q` records into the index file. Such results are conditional on the sampling threshold and selected seeds. Report that selection rule, the sample count, failure count, parameter mode, compiler flags, and hardware when comparing performance; they do not automatically represent the average over unrestricted random inputs. The benchmark process exit status alone does not establish verification success; inspect the failure fields.

## API and implementation notes

- Include `slps.h` and allocate buffers using its `SLPS_*BYTES` constants. Ordinary signatures use `SLPS_USERSIGBYTES`.
- Public parameters and identity inputs are each 32 bytes in this implementation.
- Verification returns `0` on success and `-1` on failure.
- The current message-length arguments use `uint8_t`, so callers must restrict messages to at most 255 bytes. Passing a longer length can truncate it. Supporting arbitrary-length messages requires an API and implementation change.
- The demonstration uses fixed randomness for reproducibility. Applications must manage cryptographically secure seeds and secret keys appropriately.
- Rejection-loop counters are global instrumentation; concurrent measurements need additional synchronization or separate processes.
- Application policies such as authorization expiry, revocation, transaction limits, and structured warrant validation require additional application logic. The current authorization interface binds identities and keys, without a separate general-purpose policy field.

This is research code. The supplied drivers demonstrate the intended workflow; they do not constitute a comprehensive negative-test suite, side-channel audit, or production deployment assessment.

## Paper and citation

If you use this implementation in academic work, cite the accompanying paper:

> Weizhi Wang, Zhidong Xiong, Chenxi Sun, Mengdi Zhao, and Huiyan Chen. *SLPS: A Security Lattice-Based Proxy Signature for Finance Applications*.

Publication venue, year, DOI, and a public paper URL are not specified here because they are not established by the supplied manuscript. Add the final bibliographic information when available. `SLPS_paper.pdf` was supplied alongside the source directory; include or link it in the public repository as appropriate.

## License and attribution

No license file was found in the supplied source tree. Reuse permissions are therefore not specified by this README. Before distributing the code, add the chosen project license and retain any applicable upstream copyright and license notices for reused components. The code contains `pqcrystals_dilithium*_ref` namespaces; confirm the provenance and applicable terms of the reused files before release.
