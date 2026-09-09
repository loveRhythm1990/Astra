use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use nix::pty::{Winsize, openpty};
use serde_json::Value;

use crate::tui::terminal_startup::StartupTerminal;

const CHILD: &str = "tui::terminal_startup::pty_tests::probe_child";
const RESULT: &str = "ASTRA_PROBE_RESULT=";
const INPUT: &str = "a你\x1b[200~pasted\n你好\x1b]11;rgb:ff/ff/ff\x07\x1b[201~";

/// Run the real startup guard, theme getter, terminal guard and EventStream
/// without initializing a session, accessing credentials or contacting a model.
#[test]
fn probe_child() {
    let Ok(case) = std::env::var("ASTRA_TEST_TERMINAL_PROBE") else {
        return;
    };
    if case == "non_tty" {
        let _guard = StartupTerminal::begin().unwrap();
        println!("NO_QUERY");
        return;
    }
    let before = nix::sys::termios::tcgetattr(std::io::stdin()).unwrap();
    let started = Instant::now();
    let mut startup = StartupTerminal::begin().unwrap();
    let elapsed_ms = started.elapsed().as_millis();
    let startup_mode = nix::sys::termios::tcgetattr(std::io::stdin()).unwrap();
    assert_eq!(
        startup_mode.local_flags & nix::sys::termios::LocalFlags::ISIG,
        before.local_flags & nix::sys::termios::LocalFlags::ISIG,
        "startup must retain interrupt signals"
    );
    let bg = crate::tui::terminal_palette::default_bg();
    let fg = crate::tui::terminal_palette::default_fg();
    let theme = *crate::tui::theme::current();
    println!("STARTUP_READY");
    if case == "abort" {
        drop(startup);
        let after = nix::sys::termios::tcgetattr(std::io::stdin()).unwrap();
        println!(
            "{RESULT}{}",
            serde_json::json!({ "restored": before == after })
        );
        return;
    }
    if case == "late" {
        // Replies arrive during ordinary startup output, before TUI ownership.
        std::thread::sleep(Duration::from_millis(100));
    }
    startup.prepare_tui().unwrap();
    let guard = crate::tui::terminal::TerminalGuard::init().unwrap();
    startup.handoff();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let events = runtime.block_on(async {
        use tokio_stream::StreamExt;
        let (_tx, rx) = tokio::sync::broadcast::channel(16);
        let mut stream = crate::tui::event::TuiEventStream::new(rx);
        let mut events = Vec::new();
        while events.len() < 3 {
            let event = tokio::time::timeout(Duration::from_secs(2), stream.next())
                .await
                .expect("input was not preserved")
                .expect("input stream ended");
            match event {
                crate::tui::event::TuiEvent::Key(key) => events.push(format!("key:{:?}", key.code)),
                crate::tui::event::TuiEvent::Paste(text) => events.push(format!("paste:{text}")),
                _ => {}
            }
        }
        // A late OSC reply must not become a fourth keyboard event.
        assert!(
            tokio::time::timeout(Duration::from_millis(40), stream.next())
                .await
                .is_err()
        );
        events
    });
    drop(guard);
    drop(startup);
    let after = nix::sys::termios::tcgetattr(std::io::stdin()).unwrap();
    println!(
        "{RESULT}{}",
        serde_json::json!({
            "elapsed_ms": elapsed_ms,
            "bg": bg,
            "fg": fg,
            "light": theme.is_light,
            "plain": theme.accent == ratatui::style::Color::Reset,
            "events": events,
            "restored": before == after,
        })
    );
}

fn run_case(case: &str) -> (Value, Vec<u8>) {
    let pty = openpty(
        Some(&Winsize {
            ws_row: 40,
            ws_col: 120,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }),
        None,
    )
    .unwrap();
    let mut master = File::from(pty.master);
    let slave = File::from(pty.slave);
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", CHILD, "--nocapture"])
        .env("ASTRA_TEST_TERMINAL_PROBE", case)
        .env("ASTRA_TUI_THEME", "auto")
        .env("TERM", "xterm-256color")
        .env("COLORTERM", "truecolor")
        .env_remove("NO_COLOR")
        .env_remove("ASTRA_TERMINAL_FG")
        .env_remove("ASTRA_TERMINAL_BG")
        .env_remove("COLORFGBG")
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave));
    match case {
        "light" | "fragmented" => {
            command.env("COLORFGBG", "15;0");
        }
        "dark" | "malformed" => {
            command.env("COLORFGBG", "0;15");
        }
        "explicit" => {
            command.env("ASTRA_TUI_THEME", "dark");
        }
        "no_color" => {
            command.env("NO_COLOR", "1");
        }
        "background_override" => {
            command.env("ASTRA_TERMINAL_BG", "#ffffff");
        }
        _ => {}
    }
    // SAFETY: the child only establishes its controlling PTY before exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    drop(command);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut output = Vec::new();
    let mut replied = false;
    let mut sent_input = false;
    let mut cursor_replied = false;
    loop {
        if Instant::now() > deadline {
            child.kill().ok();
            child.wait().ok();
            panic!(
                "PTY case {case} timed out: {}",
                String::from_utf8_lossy(&output)
            );
        }
        let mut descriptor = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor points to one valid pollfd for the owned PTY.
        if unsafe { libc::poll(&mut descriptor, 1, 50) } > 0 {
            let mut chunk = [0; 4096];
            match master.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(count) => output.extend_from_slice(&chunk[..count]),
            }
        }
        if !replied && output.windows(3).any(|bytes| bytes == b"\x1b[c") {
            replied = true;
            if !matches!(case, "late" | "unsupported") {
                master.write_all(INPUT.as_bytes()).unwrap();
                sent_input = true;
            }
            let response = match case {
                "light" | "fragmented" => {
                    "\x1b]10;rgb:0000/0000/0000\x1b\\\x1b]11;rgb:ffff/ffff/ffff\x07"
                }
                "dark" => "\x1b]11;rgb:0000/0000/0000\x1b\\\x1b]10;rgb:eeee/eeee/eeee\x07",
                "background_only" => "\x1b]11;rgb:ffff/ffff/ffff\x07",
                "malformed" => "\x1b]10;#你abc\x07\x1b]11;rgb:bad/nope/ff\x1b\\",
                _ => "",
            };
            if case == "fragmented" {
                for byte in response.as_bytes() {
                    master.write_all(&[*byte]).unwrap();
                    std::thread::sleep(Duration::from_millis(1));
                }
            } else {
                master.write_all(response.as_bytes()).unwrap();
            }
            if case != "unsupported" {
                master.write_all(b"\x1b[?62;4;6c").unwrap();
            }
        }
        if !sent_input && output.windows(13).any(|bytes| bytes == b"STARTUP_READY") {
            if case == "late" {
                master
                    .write_all(b"\x1b]10;rgb:00/00/00\x07\x1b]11;rgb:ff/ff/ff\x1b\\")
                    .unwrap();
            }
            master.write_all(INPUT.as_bytes()).unwrap();
            sent_input = true;
        }
        if !cursor_replied && output.windows(4).any(|bytes| bytes == b"\x1b[6n") {
            master.write_all(b"\x1b[8;1R").unwrap();
            cursor_replied = true;
        }
        if child.try_wait().unwrap().is_some() {
            // Read remaining output on the next poll; the slave closes at exit.
            continue;
        }
    }
    let status = child.wait().unwrap();
    let text = String::from_utf8_lossy(&output);
    assert!(status.success(), "PTY case {case} failed: {text}");
    assert!(
        text.contains("STARTUP_READY\r\n"),
        "startup newline handling: {text}"
    );
    let result = text
        .lines()
        .find_map(|line| line.split_once(RESULT).map(|(_, value)| value))
        .unwrap_or_else(|| panic!("no result for {case}: {text}"));
    let value: Value = serde_json::from_str(result).unwrap();
    assert_eq!(value["restored"], true, "{case}");
    if case == "abort" {
        return (value, output);
    }
    assert_eq!(
        value["events"],
        serde_json::json!([
            "key:Char('a')",
            "key:Char('你')",
            "paste:pasted\n你好\x1b]11;rgb:ff/ff/ff\x07"
        ]),
        "{case}"
    );
    (value, output)
}

#[test]
fn pty_detects_light_dark_and_fragmented_responses() {
    for case in ["light", "fragmented", "background_only", "dark"] {
        let (value, _) = run_case(case);
        assert_eq!(value["light"], case != "dark", "{case}");
        assert_eq!(value["plain"], false, "{case}");
    }
}

#[test]
fn pty_timeout_and_late_responses_preserve_input_and_cached_fallback() {
    for case in ["unsupported", "late"] {
        let (value, output) = run_case(case);
        assert!(value["bg"].is_null(), "{case}");
        let elapsed = value["elapsed_ms"].as_u64().unwrap();
        assert!((100..1000).contains(&elapsed), "{case}: {elapsed}");
        // No terminal echo of the response during startup (the JSON result
        // intentionally contains a pasted OSC, so inspect only the prefix).
        let prefix = String::from_utf8_lossy(&output);
        let prefix = prefix.split(RESULT).next().unwrap();
        assert!(!prefix.contains("rgb:"), "{case}: {prefix}");
    }
}

#[test]
fn pty_honors_manual_modes_and_background_override() {
    for case in ["explicit", "no_color", "background_override"] {
        let (value, output) = run_case(case);
        assert!(
            !output.windows(5).any(|bytes| bytes == b"\x1b]10;"),
            "{case}"
        );
        assert!(
            !output.windows(5).any(|bytes| bytes == b"\x1b]11;"),
            "{case}"
        );
        assert_eq!(value["plain"], case == "no_color", "{case}");
        assert_eq!(value["light"], case == "background_override", "{case}");
    }
}

#[test]
fn pty_malformed_colors_fall_back_without_panicking_or_leaking_keys() {
    let (value, _) = run_case("malformed");
    assert_eq!(value["light"], true);
}

#[test]
fn redirected_io_does_not_emit_terminal_queries() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD, "--nocapture"])
        .env("ASTRA_TEST_TERMINAL_PROBE", "non_tty")
        .env("ASTRA_TUI_THEME", "auto")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!output.stdout.contains(&27));
    assert!(String::from_utf8_lossy(&output.stdout).contains("NO_QUERY"));
}

#[test]
fn pty_aborted_startup_restores_terminal_modes() {
    run_case("abort");
}
