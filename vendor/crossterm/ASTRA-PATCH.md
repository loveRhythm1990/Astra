# Local Astra startup-query prototype

Base: crossterm 0.29.0, as published on crates.io (MIT; see LICENSE).
The package records upstream commit 36d95b26a26e64b0f8c12edfe11f410a6d56a812.
This directory is a local dependency patch, not a new upstream release.
The application must not depend on a modified Cargo registry cache.

## Review status: not ready to ship

This prototype is preserved on `prototype/issue-728-osc-terminal-colors`,
separately from the color/readability changes for PR #729. It has known input
and terminal-restoration regressions; passing the existing tests is not a
release criterion. Before revisiting integration, cover and fix:

- SIGINT during asynchronous startup must restore termios before exit.
- A standalone Esc must be delivered without waiting for another byte; the
  current blocking read loop can bypass both the parser and poll deadlines.
- Startup OSC framing must not change normal-session Esc/Alt semantics.
- Oversized/truncated replies must not leak their tails as keys or swallow
  subsequent Esc keys; recovery must also handle a missing terminator.
- Early palette/theme access must not silently discard the queried colors.
- A missing DA1 response must stay distinct from confirmed lack of Sixel
  support, without falling back to a competing `/dev/tty` reader during TUI use.

Add PTY coverage for those paths, including bare Esc, separate Esc then character,
arrow and Alt sequences, SIGINT, delayed DA1, and oversized response timeouts.
The FIFO/error-preservation fixes below can be proposed upstream independently.

To inspect or re-export the patch against the published 0.29.0 sources, normalize
line endings or use `diff -ru --strip-trailing-cr <upstream> vendor/crossterm`.
Some edited files use LF while the original package contains CRLF files.

## Implementation

The extension adds query_startup_attributes to the existing Unix input reader:
OSC 10/11 and DA1 use one deadline and leave keyboard/paste events in FIFO order.
Late color replies stay internal instead of becoming keystrokes. The two Unix
backends share the existing keyboard parser and a bounded OSC framing layer.
An ambiguous standalone Esc/Alt+] waits up to 40 ms; an unfinished recognized
OSC response expires after 500 ms and is limited to 256 bytes. Bracketed paste
contents are never interpreted as query responses. Querying is startup-only;
callers own terminal modes and must not run an EventStream concurrently.

Also fixes filtered-read FIFO order and preserving skipped events on input errors.
No public Event variants or Windows input behavior are changed.

Changed upstream files:
- Cargo.toml: local patch MSRV is 1.70 (Astra pins a newer toolchain).
- src/terminal/sys/unix.rs: remove redundant parentheses flagged by the pinned toolchain.
- src/event.rs: internal responses and startup query export.
- src/event/filter.rs: DA1 parameters.
- src/event/read.rs: filtered FIFO and error preservation, regression test.
- src/event/sys/unix/parse.rs: OSC framing and DA1 parameter decoding.
- src/event/source/unix.rs, unix/mio.rs, unix/tty.rs: shared bounded parser and deadlines.

Added files: src/event/startup_query.rs, src/event/source/unix/parser.rs.
Astra's PTY integration tests exercise the real query, theme, terminal guard and
EventStream without credentials or network requests. The patch's own tests run
with cargo test --manifest-path vendor/crossterm/Cargo.toml --lib --features event-stream.

Shipping this prototype requires maintaining this fork until a released upstream
API provides the required query and input-preservation behavior. Do not silently
replace it with a library that reads /dev/tty independently of crossterm.
