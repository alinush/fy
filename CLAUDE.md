# Benchmark runbook

The blog-post Chunky/Groth21/Golden comparison numbers come from two tests in
`golden/bench_test.go`. This file exists so future-you can re-run them
without reverse-engineering the setup.

## Tests

- **`TestPrintTranscriptSize`** — runs `PVSSDeal` + serialize + deserialize +
  `PVSSVerify` for each configured `(t, n)` and logs the on-wire transcript
  size in bytes and KiB. Per-size cost ≈ one full deal (dominated by PLONK
  proving). Use this when you only need the size column.
- **`TestPrintBenchmarks`** — runs deal, verify, serialize (averaged over 2000
  iters), and decrypt-share (averaged over 500 iters) for each `(t, n)` and
  prints one markdown-friendly row per size: `t  n  size(B)  deal(ms)
  verify(ms)  serialize(ms)  decrypt-share(ms)`. This is what populates the
  blog's Full benchmarks table.

Both tests call `doWarmup` once per binary invocation, which compiles the
eVRF PLONK circuit and materialises the proving/verifying keys so the first
timed measurement is not biased by one-time setup cost.

## Commands

Always run the benches with `GOMAXPROCS=10` so the numbers are comparable
across runs (and roughly match the blog's recorded figures). gnark's PLONK
backend otherwise scales `NbTasks` with `runtime.NumCPU()*2`, so leaving it
unset makes results machine-dependent.

```bash
# Size column for the blog's default 9 (t,n) pairs:
GOMAXPROCS=10 go test ./golden/ -run TestPrintTranscriptSize -v -timeout 2h

# Full deal/verify/serialize/decrypt-share table:
GOMAXPROCS=10 go test ./golden/ -run TestPrintBenchmarks -v -timeout 2h

# Just a couple of small sizes (fast smoke-test):
GOMAXPROCS=10 GOLDEN_SIZES=3:4,6:8 go test ./golden/ -run TestPrintBenchmarks -v -timeout 10m
```

`GOLDEN_SIZES` is a comma list of `t:n` pairs; it overrides the default
`benchSizes` slice in `bench_test.go`.

## Expected runtimes

Each PLONK proof costs ~1.2 s on an M4 Max, and a dealing contains `n`
proofs (dealer is external to the n players). So deal time is roughly
`1.2 · n` seconds:

| n | deal time | full `TestPrintBenchmarks` row |
|---|---|---|
| 4 | ~5 s | ~5 s |
| 64 | ~75 s | ~75 s |
| 256 | ~5 min | ~5 min |
| 1024 | ~20 min | ~20 min |

Full default run (all 9 sizes) ≈ 40 min. Use a long `-timeout` and launch as
a background Bash with `run_in_background: true` and `tee /tmp/foo.txt`; peek
at `/tmp/foo.txt` for progress while waiting for the completion notification.
Do not poll with sleep loops.

`MaxParticipants` in `golden/dkg.go` currently caps `n` at 1024. Raise it if
you need bigger.

## Reading the output

- Transcript sizes match `32 + T·32 + N·64 + 4 + N·584` exactly for a
  BN254+BJJ suite: see the wire-format docstring in `golden/pvss.go`. If the
  measured size deviates, something in the serializer changed.
- Each PLONK proof is a constant 584 bytes for the compiled eVRF circuit; it
  does not depend on `(t, n)`.
- Decrypt-share is flat ~0.30 ms across all sizes — one DH on BJJ + two
  hash-to-curve scalar mults + a scalar subtraction. If this grows with `n`
  something is wrong.

## Threading caveat (matters for comparison)

The benchmarks are **not** single-threaded. `gnark` and `gnark-crypto`
default to `NbTasks = runtime.NumCPU()*2` for MSMs and FFTs, so each PLONK
proof uses all logical cores unless `GOMAXPROCS` is set. The `n` proofs in a
dealing are generated serially in a for-loop; only the per-proof MSM/FFT
work is parallelized.

The blog numbers were taken with `GOMAXPROCS=10` (see Commands above); use
the same value when reproducing.

Chunky (`aptos-dkg`) sets `RAYON_NUM_THREADS=1` and Groth21 (`blstrs`) has no
Rayon integration, so the comparison is still favorable to Golden on deal
time even at `GOMAXPROCS=10`. Flag this when quoting deal numbers.

## PVSS semantics (what the bench measures)

- Dealer is **external** to the `n` players (`makeDealer` creates a fresh key
  pair with ID `n+1`); `players` is a length-`n` slice with IDs `1..n`.
- `PVSSTranscript` contains every field needed for `PVSSVerify`: `RandomMsg`,
  `VSSCommitments` (length T), `Ciphertexts` (length N), `EVRFProofs` (length
  N). It deliberately does NOT include `SessionID`, dealer ID, a separate
  Schnorr identity proof, derived-curve data, count prefixes, or per-entry
  recipient IDs — see the docstring on `PVSSTranscript` for the reasoning.
- If you change the transcript layout, run the unit tests in
  `golden/pvss_test.go` (`TestPVSSSerializeRoundtrip`,
  `TestPVSSDecryptRecoversShamirShare`, `TestPVSSVerifyTamper`,
  `TestPVSSDeserializeRejects`) — they catch both breakage and silent size
  regressions.

## Related external paths

- Blog post (update numbers here after a fresh run):
  `~/repos/alinush.github.io/_posts/2025-11-18-chunky-weighted-pvss-for-field-elements.md`,
  section `### Full benchmarks`.
- Chunky bench (comparison baseline):
  `~/repos/aptos-core/crates/aptos-dkg/benches/pvss.rs`, reproduce via
  `~/repos/aptos-core/crates/aptos-crypto/benches/run-pvss-benches.sh`.
- Groth21 bench (comparison baseline):
  `~/repos/e2e-vss/benches/run-pvss-benches.sh`.
