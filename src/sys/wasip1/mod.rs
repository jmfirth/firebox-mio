//! # Notes
//!
//! The current implementation is somewhat limited. The `Waker` is not
//! implemented, as at the time of writing there is no way to support to wake-up
//! a thread from calling `poll_oneoff`.
//!
//! Furthermore the (re/de)register functions also don't work while concurrently
//! polling as both registering and polling requires a lock on the
//! `subscriptions`.
//!
//! Finally `Selector::try_clone`, required by `Registry::try_clone`, doesn't
//! work. However this could be implemented by use of an `Arc`.
//!
//! In summary, this only (barely) works using a single thread.

use std::cmp::min;
use std::io;
#[cfg(all(feature = "net", debug_assertions))]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(feature = "net")]
use crate::{Interest, Token};

cfg_net! {
    pub(crate) mod tcp {
        // FIREBOX wasip1 net arm (CN8 / PE1 verdict A).
        //
        // WHY: mio 1.2.0's wasip1 backend ships *accept-only* because it is written
        // against the standard `wasi` crate's preview1 ABI, whose socket surface is
        // only `sock_accept/recv/send/shutdown` — there is no preview1 `sock_connect`,
        // `sock_open`, or `sock_bind`. So upstream gates out `connect`/`bind`/`listen`
        // and `TcpStream::connect`/`TcpListener::bind` on `(wasi, p1)`.
        //
        // Firebox is different: its libc/std fork routes `std::net` through the richer
        // `wasix_32v1` namespace (`sock_open/connect/bind/listen/...`), so `std::net`
        // outbound TCP works at runtime under `firebox run` TODAY (PE1 step 1+5 proof).
        // We therefore implement the missing mio constructors over `std::net` — the
        // exact `from_std` bridge PE1 proved drives async I/O through the wasip1
        // `poll_oneoff` reactor — rather than over a preview1 ABI that lacks them.
        //
        // This keeps the arm zero-unsafe and reuses an already-proven path: every
        // socket is created/connected/bound by `std::net`, set non-blocking, then
        // handed (as a raw fd via `IoSource`/`Selector::register`) to the existing
        // wasip1 reactor. No new substrate work — the substrate already exposes the
        // full outbound socket surface.
        //
        // RETIREMENT: upstreamable to tokio-rs/mio as "wasip1 client sockets for hosts
        // that expose connect/bind over the socket ABI" (firebox's wasix ABI is what
        // makes the client side possible — a firebox-enabled-semantics gap). Retires
        // when that lands AND firebox's vendored mio tracks it. Until then it lives in
        // the codex `[patch.crates-io]` graph alongside socket2/libc.
        use std::io;
        use std::net::{self, SocketAddr};

        pub(crate) fn accept(listener: &net::TcpListener) -> io::Result<(net::TcpStream, SocketAddr)> {
            let (stream, addr) = listener.accept()?;
            stream.set_nonblocking(true)?;
            Ok((stream, addr))
        }

        /// Issue an outbound TCP connect. Returns a non-blocking, connected
        /// `std::net::TcpStream` that the caller wraps in mio's `IoSource` and
        /// registers with the `poll_oneoff` reactor.
        ///
        /// Unlike mio's unix arm (which issues a *non-blocking* `connect(2)` and
        /// returns immediately with the connect still in flight), firebox's
        /// `std::net::TcpStream::connect` completes the connect synchronously via
        /// `wasix_32v1::sock_connect`. We then flip the socket to non-blocking so
        /// subsequent reads/writes integrate with the reactor exactly like the
        /// proven `from_std` path. This is observably equivalent for mio's
        /// consumers (tokio waits for a writable event before using the stream;
        /// an already-connected socket simply reports writable immediately).
        pub(crate) fn connect(addr: SocketAddr) -> io::Result<net::TcpStream> {
            let stream = net::TcpStream::connect(addr)?;
            stream.set_nonblocking(true)?;
            Ok(stream)
        }

        /// Bind + listen for an inbound TCP listener, returning a non-blocking
        /// `std::net::TcpListener` registered with the reactor by the caller.
        /// Routes through `wasix_32v1::sock_open/bind/listen`. `SO_REUSEADDR` is
        /// applied via std before binding to match mio's unix `bind` shape.
        pub(crate) fn bind(addr: SocketAddr) -> io::Result<net::TcpListener> {
            // `TcpListener::bind` performs socket()+setsockopt(SO_REUSEADDR)+bind()+listen()
            // in std on firebox's wasix-backed libc, mirroring mio's unix `bind`.
            let listener = net::TcpListener::bind(addr)?;
            listener.set_nonblocking(true)?;
            Ok(listener)
        }
    }
}

// FIREBOX wasip1 SourceFd arm (ESV / tokio::process backend).
//
// WHY: mio exposes `SourceFd` (an `event::Source` adapter over a borrowed `&RawFd`)
// only on `unix`/`hermit`/non-p1-`wasi` — never on `(wasi, p1)`. tokio's `process`
// imp registers its child pipe fds with the reactor through `mio::unix::SourceFd`;
// to give tokio a wasip1 `process` arm we need the same adapter on this triple.
//
// The wasip1 `Selector::register/reregister/deregister` already take a raw `wasi::Fd`
// (the same shape the unix `SourceFd` impl uses, just selector-first), so this adapter
// is a thin, zero-unsafe mirror of `sys/unix/sourcefd.rs`. It registers ANY fd that
// can be subscribed via `poll_oneoff` (FD_READ/FD_WRITE) — exactly what a nonblocking
// child stdout/stderr/stdin pipe needs. Exposed via `mio::wasi::SourceFd` (see lib.rs).
//
// RETIREMENT: upstreamable to tokio-rs/mio alongside the CN8 wasip1 client-socket arm
// ("wasip1 SourceFd for hosts that expose poll_oneoff fd readiness"). Retires when that
// lands AND firebox's vendored mio tracks it.
#[cfg(feature = "os-ext")]
pub(crate) mod sourcefd {
    use std::io;
    use std::os::fd::RawFd;

    use crate::{event, Interest, Registry, Token};

    /// Adapter for [`RawFd`] providing an [`event::Source`] implementation on
    /// `(wasi, p1)`. Mirrors `mio::unix::SourceFd`. Does **not** own the fd.
    #[derive(Debug)]
    pub struct SourceFd<'a>(pub &'a RawFd);

    impl<'a> event::Source for SourceFd<'a> {
        fn register(
            &mut self,
            registry: &Registry,
            token: Token,
            interests: Interest,
        ) -> io::Result<()> {
            registry.selector().register(*self.0 as _, token, interests)
        }

        fn reregister(
            &mut self,
            registry: &Registry,
            token: Token,
            interests: Interest,
        ) -> io::Result<()> {
            registry
                .selector()
                .reregister(*self.0 as _, token, interests)
        }

        fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
            registry.selector().deregister(*self.0 as _)
        }
    }
}

#[cfg(feature = "os-ext")]
pub use sourcefd::SourceFd;

/// Unique id for use as `SelectorId`.
#[cfg(all(debug_assertions, feature = "net"))]
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

pub(crate) struct Selector {
    #[cfg(all(debug_assertions, feature = "net"))]
    id: usize,
    /// Subscriptions (reads events) we're interested in.
    subscriptions: Arc<Mutex<Vec<wasi::Subscription>>>,
    // FIREBOX wasip1 cross-thread Waker arm (XWJ — boot lost-wake fix).
    //
    // WHY: upstream wasip1 mio ships *no* `Waker` ("there is no way to wake up a
    // thread from calling `poll_oneoff`", see the module doc). Tokio's IO driver
    // therefore makes `Handle::unpark()` an empty no-op on `target_os = "wasi"`,
    // so any task woken from a *foreign* OS thread (a `spawn_blocking` worker, a
    // sqlx-sqlite connection thread, a cross-worker mpsc send) cannot wake the
    // worker blocked inside `poll_oneoff` — the wake is silently dropped and the
    // awaiting future parks forever. This deterministically wedges codex-exec's
    // in-process app-server boot at the first `spawn_blocking`
    // (`resolve_installation_id`); `tid=1` parks `never-woken` with 0 sockets
    // opened (XWJ breadcrumb proof).
    //
    // FIX: firebox's wasix-libc exports a real POSIX `pipe(2)`, so we can build a
    // genuine self-pipe Waker — exactly the mechanism mio's unix backend uses.
    // (A 127.0.0.1 loopback socket pair was tried FIRST and rejected: binding a
    // listener trips firebox's inbound default-deny under `--net` (firebox#647,
    // EPERM). A pipe needs no listener and works with no networking at all — see
    // the `mod waker` header for the full account.) The receiver fd is registered with the
    // reactor for FD_READ; `wake()` writes a byte from any thread, which makes
    // the receiver readable and forces the in-flight `poll_oneoff` to return.
    // The selector drains the receiver after every poll so the level-triggered
    // `poll_oneoff` re-arms cleanly. Tokio's wasi `unpark()` is wired to this
    // Waker (companion tokio-fork edit).
    //
    // RETIREMENT: retires when upstream tokio-rs/mio gains a real wasip1 Waker
    // (the same "wasip1 wakeups for hosts that expose a pollable socket/fd ABI"
    // upstreamable as the CN8 socket arm) AND firebox's vendored mio tracks it.
    /// Receiver fd + its userdata (token) of the active cross-thread `Waker`, if
    /// one is registered. Drained after a `poll_oneoff` that reported the waker
    /// fd readable, so the level-triggered reactor re-arms. The userdata lets
    /// `select()` drain ONLY when the waker actually fired (a blind drain on a
    /// blocking pipe with no pending byte would deadlock the reactor).
    waker_receiver_fd: Arc<Mutex<Option<(wasi::Fd, wasi::Userdata)>>>,
}

impl Selector {
    pub(crate) fn new() -> io::Result<Selector> {
        Ok(Selector {
            #[cfg(all(debug_assertions, feature = "net"))]
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            subscriptions: Arc::new(Mutex::new(Vec::new())),
            waker_receiver_fd: Arc::new(Mutex::new(None)),
        })
    }

    #[cfg(all(debug_assertions, feature = "net"))]
    pub(crate) fn id(&self) -> usize {
        self.id
    }

    pub(crate) fn select(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        events.clear();

        let mut subscriptions = self.subscriptions.lock().unwrap();

        // If we want to a use a timeout in the `wasi_poll_oneoff()` function
        // we need another subscription to the list.
        if let Some(timeout) = timeout {
            subscriptions.push(timeout_subscription(timeout));
        }

        // `poll_oneoff` needs the same number of events as subscriptions.
        let length = subscriptions.len();
        events.reserve(length);

        debug_assert!(events.capacity() >= length);
        #[cfg(debug_assertions)]
        if length == 0 {
            warn!(
                "calling mio::Poll::poll with empty subscriptions, this likely not what you want"
            );
        }

        let res = unsafe { wasi::poll_oneoff(subscriptions.as_ptr(), events.as_mut_ptr(), length) };

        // Remove the timeout subscription we possibly added above.
        if timeout.is_some() {
            let timeout_sub = subscriptions.pop();
            debug_assert_eq!(
                timeout_sub.unwrap().u.tag,
                wasi::EVENTTYPE_CLOCK.raw(),
                "failed to remove timeout subscription"
            );
        }

        drop(subscriptions); // Unlock.

        match res {
            Ok(n_events) => {
                // Safety: `poll_oneoff` initialises the `events` for us.
                unsafe { events.set_len(n_events) };

                // Remove the timeout event.
                if timeout.is_some() {
                    if let Some(index) = events.iter().position(is_timeout_event) {
                        events.swap_remove(index);
                    }
                }

                // FIREBOX (XWJ): if a cross-thread `Waker` is registered AND its
                // fd actually fired in this poll, drain it. The wasip1 reactor is
                // level-triggered (each `poll_oneoff` re-reads the whole
                // subscription list), so an undrained readable waker byte would
                // make every subsequent poll return immediately and busy-spin.
                // We drain ONLY when the waker event is present: the read-end is a
                // blocking pipe, so a blind drain when no byte is queued would
                // wedge the reactor. The waker's TOKEN_WAKEUP event is left in
                // `events` for tokio's `turn` to recognize and ignore.
                if let Ok(guard) = self.waker_receiver_fd.lock() {
                    if let Some((fd, userdata)) = *guard {
                        let waker_fired = events.iter().any(|e| e.userdata == userdata);
                        if waker_fired {
                            drain_waker_fd(fd);
                        }
                    }
                }

                check_errors(&events)
            }
            Err(err) => Err(io_err(err)),
        }
    }

    pub(crate) fn try_clone(&self) -> io::Result<Selector> {
        Ok(Selector {
            #[cfg(all(debug_assertions, feature = "net"))]
            id: self.id,
            subscriptions: self.subscriptions.clone(),
            // FIREBOX (XWJ): share the same waker receiver fd across clones so a
            // `Waker` registered on the cloned registry drains correctly.
            waker_receiver_fd: self.waker_receiver_fd.clone(),
        })
    }

    cfg_io_source! {
    pub(crate) fn register(
        &self,
        fd: wasi::Fd,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        let mut subscriptions = self.subscriptions.lock().unwrap();

        if interests.is_writable() {
            let subscription = wasi::Subscription {
                userdata: token.0 as wasi::Userdata,
                u: wasi::SubscriptionU {
                    tag: wasi::EVENTTYPE_FD_WRITE.raw(),
                    u: wasi::SubscriptionUU {
                        fd_write: wasi::SubscriptionFdReadwrite {
                            file_descriptor: fd,
                        },
                    },
                },
            };
            subscriptions.push(subscription);
        }

        if interests.is_readable() {
            let subscription = wasi::Subscription {
                userdata: token.0 as wasi::Userdata,
                u: wasi::SubscriptionU {
                    tag: wasi::EVENTTYPE_FD_READ.raw(),
                    u: wasi::SubscriptionUU {
                        fd_read: wasi::SubscriptionFdReadwrite {
                            file_descriptor: fd,
                        },
                    },
                },
            };
            subscriptions.push(subscription);
        }

        Ok(())
    }

    pub(crate) fn reregister(
        &self,
        fd: wasi::Fd,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.deregister(fd)
            .and_then(|()| self.register(fd, token, interests))
    }

    pub(crate) fn deregister(&self, fd: wasi::Fd) -> io::Result<()> {
        let mut subscriptions = self.subscriptions.lock().unwrap();

        let predicate = |subscription: &wasi::Subscription| {
            // Safety: `subscription.u.tag` defines the type of the union in
            // `subscription.u.u`.
            match subscription.u.tag {
                t if t == wasi::EVENTTYPE_FD_WRITE.raw() => unsafe {
                    subscription.u.u.fd_write.file_descriptor == fd
                },
                t if t == wasi::EVENTTYPE_FD_READ.raw() => unsafe {
                    subscription.u.u.fd_read.file_descriptor == fd
                },
                _ => false,
            }
        };

        let mut ret = Err(io::ErrorKind::NotFound.into());

        while let Some(index) = subscriptions.iter().position(predicate) {
            subscriptions.swap_remove(index);
            ret = Ok(())
        }

        ret
    }

    /// FIREBOX (XWJ): record the receiver fd + its userdata (token) of the active
    /// cross-thread `Waker` so `select()` drains it after a `poll_oneoff` that
    /// reported it readable (re-arming the level-triggered reactor). Called by
    /// `Waker::new`.
    pub(crate) fn set_waker_fd(&self, fd: wasi::Fd, userdata: wasi::Userdata) {
        if let Ok(mut guard) = self.waker_receiver_fd.lock() {
            *guard = Some((fd, userdata));
        }
    }

    /// FIREBOX (XWJ): clear the waker receiver fd when the `Waker` is dropped.
    pub(crate) fn clear_waker_fd(&self, fd: wasi::Fd) {
        if let Ok(mut guard) = self.waker_receiver_fd.lock() {
            if matches!(*guard, Some((f, _)) if f == fd) {
                *guard = None;
            }
        }
    }
    }
}

// FIREBOX wasip1 cross-thread Waker (XWJ — boot lost-wake fix). See the rationale
// on `Selector::waker_receiver_fd` above. Mirrors mio's unix pipe waker, backed by
// an anonymous `pipe(2)` (firebox's wasix-libc exports `pipe`/`__wasi_fd_pipe`).
//
// NB: a pipe — NOT a loopback TCP socket pair — is required, because firebox's
// `--net` is default-deny for INBOUND sockets (firebox#647), so binding a loopback
// listener fails with EPERM; a pipe needs no listener and works regardless of the
// networking posture (and even with no `--net` at all).
//
// RETIREMENT: retires when upstream tokio-rs/mio ships a real wasip1 Waker AND
// firebox's vendored mio tracks it.
cfg_io_source! {
    pub(crate) mod waker {
        use std::fmt;
        use std::io;
        use std::sync::Mutex;

        use crate::sys::Selector;
        use crate::Token;

        unsafe extern "C" {
            // firebox wasix-libc exports POSIX `pipe`; `write`/`close` are the
            // standard libc fd ops (all confirmed defined symbols in the
            // self-contained wasix-libc the firebox sysroot ships).
            //
            // NB: deliberately NO `fcntl` here. wasi-libc's `fcntl` is VARIADIC
            // (`fcntl(fd, cmd, ...)`); calling it through a fixed-arity Rust
            // `extern "C"` mismatches the wasm variadic ABI and traps with an
            // out-of-bounds memory access. We keep the read-end blocking and drain
            // it correctly without O_NONBLOCK (see `drain_waker_fd`).
            fn pipe(fds: *mut i32) -> i32;
            fn write(fd: i32, buf: *const u8, count: usize) -> isize;
            fn close(fd: i32) -> i32;
        }

        /// Cross-thread `Waker` backed by an anonymous pipe.
        ///
        /// The read-end (`receiver_fd`) is registered with the reactor for
        /// FD_READ; a `wake()` from any thread writes a byte to the write-end
        /// (`sender_fd`), making the read-end readable and forcing the in-flight
        /// `poll_oneoff` to return. The selector drains the read-end after the
        /// poll so the level-triggered reactor re-arms.
        pub(crate) struct Waker {
            sender_fd: i32,
            receiver_fd: wasi::Fd,
            // Serialize concurrent `wake()` writes; a pipe write of 1 byte is
            // atomic, but the lock keeps the API `Sync`-safe and cheap.
            write_lock: Mutex<()>,
            selector: Selector,
        }

        impl fmt::Debug for Waker {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct("Waker")
                    .field("receiver_fd", &self.receiver_fd)
                    .field("sender_fd", &self.sender_fd)
                    .finish()
            }
        }

        impl Waker {
            pub(crate) fn new(selector: &Selector, token: Token) -> io::Result<Waker> {
                let mut fds = [-1i32; 2];
                // Safety: `fds` is a 2-element array; `pipe` writes the read fd to
                // fds[0] and the write fd to fds[1], returning 0 on success.
                let rc = unsafe { pipe(fds.as_mut_ptr()) };
                if rc != 0 {
                    return Err(io::Error::last_os_error());
                }
                let receiver_fd = fds[0] as wasi::Fd;
                let sender_fd = fds[1];

                let selector = selector.try_clone()?;
                // Register the read-end for readable readiness under `token`
                // (tokio passes TOKEN_WAKEUP). The selector drains this fd after
                // every poll; the fds stay open for the lifetime of the reactor
                // (the Waker is process-lived, like the IO driver). On `Drop` we
                // deregister + close both ends.
                if let Err(e) = selector.register(receiver_fd, token, crate::Interest::READABLE) {
                    unsafe {
                        close(fds[0]);
                        close(sender_fd);
                    }
                    return Err(e);
                }
                // `register` stores the FD_READ subscription under `token.0` as
                // its `userdata`; record both so `select()` can detect the waker
                // event and drain only then.
                selector.set_waker_fd(receiver_fd, token.0 as wasi::Userdata);

                Ok(Waker {
                    sender_fd,
                    receiver_fd,
                    write_lock: Mutex::new(()),
                    selector,
                })
            }

            pub(crate) fn wake(&self) -> io::Result<()> {
                // A single byte makes the read-end readable; the selector drains
                // it after the poll returns. The lock just serializes writers.
                let _guard = self
                    .write_lock
                    .lock()
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "waker write lock poisoned"))?;
                let byte = 1u8;
                // Safety: `sender_fd` is the live write-end of our pipe.
                let n = unsafe { write(self.sender_fd, &byte as *const u8, 1) };
                if n < 0 {
                    let err = io::Error::last_os_error();
                    // A full pipe buffer means a wakeup is already pending — that
                    // is exactly the effect we want, so treat WouldBlock as success.
                    if err.kind() == io::ErrorKind::WouldBlock {
                        return Ok(());
                    }
                    return Err(err);
                }
                Ok(())
            }
        }

        impl Drop for Waker {
            fn drop(&mut self) {
                self.selector.clear_waker_fd(self.receiver_fd);
                let _ = self.selector.deregister(self.receiver_fd);
                // Safety: we own both ends; close them once.
                unsafe {
                    close(self.receiver_fd as i32);
                    close(self.sender_fd);
                }
            }
        }
    }
    pub(crate) use waker::Waker;
}

/// FIREBOX (XWJ): drain the waker receiver (pipe read-end) with a single bounded
/// read. Called by `Selector::select` ONLY when `poll_oneoff` reported the waker
/// fd readable, so at least one byte is queued and this read returns immediately
/// (it never blocks — no `O_NONBLOCK`/`fcntl` needed). A single read consumes up
/// to `buf.len()` bytes; any residual coalesced wake bytes simply re-fire the
/// next poll, which is harmless (the worker is already being woken). Best-effort.
#[cfg(all(feature = "os-poll", any(feature = "net", feature = "os-ext")))]
fn drain_waker_fd(fd: wasi::Fd) {
    unsafe extern "C" {
        fn read(fd: i32, buf: *mut u8, count: usize) -> isize;
    }
    let mut buf = [0u8; 64];
    // Safety: `fd` is the pipe read-end, kept open for the reactor's lifetime by
    // the `Waker`. Borrowed transiently for one read; the read is guaranteed
    // non-blocking by the caller's contract (only invoked after a readable event).
    let _ = unsafe { read(fd as i32, buf.as_mut_ptr(), buf.len()) };
}

/// Token used to a add a timeout subscription, also used in removing it again.
const TIMEOUT_TOKEN: wasi::Userdata = wasi::Userdata::MAX;

/// Returns a `wasi::Subscription` for `timeout`.
fn timeout_subscription(timeout: Duration) -> wasi::Subscription {
    wasi::Subscription {
        userdata: TIMEOUT_TOKEN,
        u: wasi::SubscriptionU {
            tag: wasi::EVENTTYPE_CLOCK.raw(),
            u: wasi::SubscriptionUU {
                clock: wasi::SubscriptionClock {
                    id: wasi::CLOCKID_MONOTONIC,
                    // Timestamp is in nanoseconds.
                    timeout: min(wasi::Timestamp::MAX as u128, timeout.as_nanos())
                        as wasi::Timestamp,
                    // Give the implementation another millisecond to coalesce
                    // events.
                    precision: Duration::from_millis(1).as_nanos() as wasi::Timestamp,
                    // Zero means the `timeout` is considered relative to the
                    // current time.
                    flags: 0,
                },
            },
        },
    }
}

fn is_timeout_event(event: &wasi::Event) -> bool {
    event.type_ == wasi::EVENTTYPE_CLOCK && event.userdata == TIMEOUT_TOKEN
}

/// Check all events for possible errors, it returns the first error found.
fn check_errors(events: &[Event]) -> io::Result<()> {
    for event in events {
        if event.error != wasi::ERRNO_SUCCESS {
            return Err(io_err(event.error));
        }
    }
    Ok(())
}

/// Convert `wasi::Errno` into an `io::Error`.
fn io_err(errno: wasi::Errno) -> io::Error {
    // TODO: check if this is valid.
    io::Error::from_raw_os_error(errno.raw() as i32)
}

pub(crate) type Events = Vec<Event>;

pub(crate) type Event = wasi::Event;

pub(crate) mod event {
    use std::fmt;

    use crate::sys::Event;
    use crate::Token;

    pub(crate) fn token(event: &Event) -> Token {
        Token(event.userdata as usize)
    }

    pub(crate) fn is_readable(event: &Event) -> bool {
        event.type_ == wasi::EVENTTYPE_FD_READ
    }

    pub(crate) fn is_writable(event: &Event) -> bool {
        event.type_ == wasi::EVENTTYPE_FD_WRITE
    }

    pub(crate) fn is_error(_: &Event) -> bool {
        // Not supported? It could be that `wasi::Event.error` could be used for
        // this, but the docs say `error that occurred while processing the
        // subscription request`, so it's checked in `Select::select` already.
        false
    }

    pub(crate) fn is_read_closed(event: &Event) -> bool {
        event.type_ == wasi::EVENTTYPE_FD_READ
            // Safety: checked the type of the union above.
            && (event.fd_readwrite.flags & wasi::EVENTRWFLAGS_FD_READWRITE_HANGUP) != 0
    }

    pub(crate) fn is_write_closed(event: &Event) -> bool {
        event.type_ == wasi::EVENTTYPE_FD_WRITE
            // Safety: checked the type of the union above.
            && (event.fd_readwrite.flags & wasi::EVENTRWFLAGS_FD_READWRITE_HANGUP) != 0
    }

    pub(crate) fn is_priority(_: &Event) -> bool {
        // Not supported.
        false
    }

    pub(crate) fn is_aio(_: &Event) -> bool {
        // Not supported.
        false
    }

    pub(crate) fn is_lio(_: &Event) -> bool {
        // Not supported.
        false
    }

    pub(crate) fn debug_details(f: &mut fmt::Formatter<'_>, event: &Event) -> fmt::Result {
        debug_detail!(
            TypeDetails(wasi::Eventtype),
            PartialEq::eq,
            wasi::EVENTTYPE_CLOCK,
            wasi::EVENTTYPE_FD_READ,
            wasi::EVENTTYPE_FD_WRITE,
        );

        #[allow(clippy::trivially_copy_pass_by_ref)]
        fn check_flag(got: &wasi::Eventrwflags, want: &wasi::Eventrwflags) -> bool {
            (got & want) != 0
        }
        debug_detail!(
            EventrwflagsDetails(wasi::Eventrwflags),
            check_flag,
            wasi::EVENTRWFLAGS_FD_READWRITE_HANGUP,
        );

        struct EventFdReadwriteDetails(wasi::EventFdReadwrite);

        impl fmt::Debug for EventFdReadwriteDetails {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct("EventFdReadwrite")
                    .field("nbytes", &self.0.nbytes)
                    .field("flags", &EventrwflagsDetails(self.0.flags))
                    .finish()
            }
        }

        f.debug_struct("Event")
            .field("userdata", &event.userdata)
            .field("error", &event.error)
            .field("type", &TypeDetails(event.type_))
            .field("fd_readwrite", &EventFdReadwriteDetails(event.fd_readwrite))
            .finish()
    }
}

cfg_os_poll! {
    cfg_io_source! {
        pub(crate) struct IoSourceState;

        impl IoSourceState {
            pub(crate) fn new() -> IoSourceState {
                IoSourceState
            }

            pub(crate) fn do_io<T, F, R>(&self, f: F, io: &T) -> io::Result<R>
            where
                F: FnOnce(&T) -> io::Result<R>,
            {
                // We don't hold state, so we can just call the function and
                // return.
                f(io)
            }
        }
    }
}
