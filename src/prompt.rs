//! Asking on the terminal.

use anyhow::Result;
use std::io::{BufRead, Write};

/// Print `question` (with `[default]`) and read one line; an empty line gives the default.
pub fn ask(question: &str, default: Option<&str>) -> Result<String> {
    match default {
        Some(d) => print!("{question} [{d}]: "),
        None => print!("{question}: "),
    }
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let line = line.trim();
    Ok(if line.is_empty() {
        default.unwrap_or("").to_string()
    } else {
        line.to_string()
    })
}

/// `question [y/N]` or `[Y/n]`; an empty answer takes the default.
pub fn confirm(question: &str, default_yes: bool) -> Result<bool> {
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    let answer = ask(&format!("{question} {hint}"), None)?;
    Ok(parse_yes(&answer, default_yes))
}

fn parse_yes(answer: &str, default_yes: bool) -> bool {
    match answer.trim().to_ascii_lowercase().as_str() {
        "" => default_yes,
        a => matches!(a, "y" | "yes"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_takes_the_default_and_anything_but_yes_is_no() {
        assert!(parse_yes("", true));
        assert!(!parse_yes("", false));
        assert!(parse_yes(" Y ", false));
        assert!(!parse_yes("n", true));
        assert!(!parse_yes("maybe", true));
    }
}
