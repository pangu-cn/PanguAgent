pub const FORBIDDEN_FLAGS: &[&str] = &[
    "--yolo",
    "--auto-approve",
    "--no-verify",
    "--telemetry",
    "--python-executor",
];

pub fn reject_flag(flag: &str) -> Result<(), &'static str> {
    if FORBIDDEN_FLAGS.contains(&flag) {
        Err("flag is forbidden by the negative list")
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_list_flags_fail_closed() {
        for flag in FORBIDDEN_FLAGS {
            assert!(reject_flag(flag).is_err());
        }
        assert!(reject_flag("--checkpoint").is_ok());
    }
}
