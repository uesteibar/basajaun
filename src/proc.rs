//! Process liveness. A pid alone can be reused, so the start time from `/proc` is recorded too.

/// Start time of `pid` in clock ticks since boot (field 22 of `/proc/<pid>/stat`).
pub fn start_time(pid: u32) -> Option<u64> {
    parse_start_time(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

fn parse_start_time(stat: &str) -> Option<u64> {
    // The command name (field 2) may contain spaces and parentheses: skip to the last ')'.
    let rest = &stat[stat.rfind(')')? + 1..];
    // `rest` starts at field 3 (state); starttime is field 22, so index 19.
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Is the process with this pid (and start time, when known) still running?
pub fn alive(pid: u32, start: Option<u64>) -> bool {
    match start {
        Some(s) => start_time(pid) == Some(s),
        // SAFETY: signal 0 only checks that the process exists.
        None => unsafe { libc::kill(pid as libc::pid_t, 0) == 0 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_time_survives_odd_command_names() {
        let stat = "123 (a) b (c) S 1 123 123 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10 18446744073709551615";
        assert_eq!(parse_start_time(stat), Some(987654));
    }

    #[test]
    fn our_own_process_is_alive_and_a_wrong_start_time_is_not() {
        let me = std::process::id();
        let start = start_time(me);
        assert!(start.is_some());
        assert!(alive(me, start));
        assert!(!alive(me, start.map(|s| s + 1)));
    }
}
