# Firebox patches — mio

**Upstream base:** mio `1.2.0` (crates.io tarball, commit `a6d831b`).
**Branch:** `firebox-patches` — the rolling head (firebox `docs/reference/forks.md` §2/§3.5).
**Remote:** `jmfirth/firebox-mio`.
**Consumed by:** the codex `[patch.crates-io]` graph (`../firebox-forks/codex`, `codex-rs/Cargo.toml`).

Every patch is `#[cfg]`-scoped to the `(target_os = "wasi", target_env = "p1")` triple.
Non-wasi targets compile byte-identically to upstream 1.2.0.

## The arms

| Arm | Files | What |
|---|---|---|
| **CN8** — wasip1 client sockets | `src/sys/wasip1/mod.rs` (`cfg_net!`/`mod tcp`), `src/net/tcp/{stream,listener}.rs`, `src/sys/mod.rs`, `src/lib.rs` | `tcp::connect` + `tcp::bind` over `std::net`, and the un-gating of `TcpStream::connect` / `TcpListener::bind` on the triple. Upstream's wasip1 backend is *accept-only* because it targets preview1's socket ABI, which has no `sock_connect`/`sock_open`/`sock_bind`; firebox's libc routes `std::net` through the richer `wasix_32v1` namespace, so the client side works at runtime. |
| **ESV** — wasip1 `SourceFd` | `src/sys/wasip1/mod.rs` (`mod sourcefd`), `src/lib.rs` (`pub mod wasi`) | An `event::Source` adapter over `&RawFd`, mirroring `sys/unix/sourcefd.rs`. Upstream exposes `SourceFd` on unix/hermit/non-p1-wasi only; tokio's `process` imp registers child pipe fds through it, so a wasip1 `process` arm needs it here. |
| **#XWJ** — cross-thread `Waker` | `src/sys/wasip1/mod.rs` (`Selector::waker_receiver_fd`, `mod waker`, `drain_waker_fd`), `src/lib.rs`, `src/waker.rs` | A real wasip1 `Waker` over an anonymous `pipe(2)`. Upstream ships none — its own module doc says "there is no way to support to wake-up a thread from calling `poll_oneoff`" — and `src/lib.rs` gates `mod waker` / `pub use waker::Waker` behind `not(target_os = "wasi")`, so `mio::Waker` does not exist as a type. Tokio therefore makes `Handle::unpark()` an empty no-op on wasi, and every foreign-OS-thread wake (`spawn_blocking`, sqlx, cross-worker send) is silently dropped. Companion patch: `jmfirth/firebox-tokio`. |

## #XWJ — the two decisions that are load-bearing, not stylistic

**`pipe(2)`, NOT a loopback socket pair.** The first cut used a 127.0.0.1 TCP socketpair
(bind→connect→accept). It *proved the mechanism* — the futex trace showed a real cross-thread wake
(`WAKE woken=1 by_tid=2`) and the `never-woken` wedge was gone — but `TcpListener::bind("127.0.0.1:0")`
is rejected by firebox's **inbound default-deny** under `--net` (firebox#647 → `EPERM`), so the
runtime failed to build. A pipe needs no listener and works regardless of networking posture,
including with no `--net` at all.

**No `fcntl`, no `O_NONBLOCK`.** wasi-libc's `fcntl` is **variadic** (`fcntl(fd, cmd, ...)`);
calling it through a fixed-arity Rust `extern "C"` mismatches the wasm variadic ABI and **traps**
with an out-of-bounds memory access (`thread_runtime_error frame[0]: func_name=Some("fcntl")`).
So the read end stays *blocking*, and `Selector::select` drains it with a single bounded `read`
**only when `poll_oneoff` reported the waker fd readable** (matched by `userdata`). A read issued
after a readable event never blocks. A blind drain on a blocking read end **would deadlock the
reactor** — that `userdata` check is correctness, not an optimization.

Both diagnostics are banked: `../firebox-backup/codex-xwj-bootfix-2026-06-16/runs/fix-run-1-bind-blocked.txt`
and `runs/fix-run-2-fcntl-oob.txt`.

## Retirement criterion

All three arms retire when **upstream `tokio-rs/mio` ships a real wasip1 `Waker` and wasip1 client
sockets**, and firebox's vendored mio tracks it. Checkable: `mio::Waker` exists on `(wasi, p1)`
upstream **and** `TcpStream::connect` is no longer
`#[cfg(not(all(target_os = "wasi", target_env = "p1")))]`-gated.

## Build status

The #XWJ arm has not been rebuilt since it was reconstituted onto this branch (firebox task #6EJ).
It is byte-identical to the source that produced the validated
`codex-exec-xwj-wakerfix.wasm`; the rebuild is a mechanical re-confirm and is filed as a firebox
follow-up.
