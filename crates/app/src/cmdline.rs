const CMDLINE_MAX_BYTES: usize = 0x3F0;

pub(crate) fn truncate_cmdline(mut cmdline: String) -> String {
    if cmdline.len() > CMDLINE_MAX_BYTES {
        let mut end = CMDLINE_MAX_BYTES;
        while end > 0 && !cmdline.is_char_boundary(end) {
            end -= 1;
        }
        cmdline.truncate(end);
    }
    cmdline
}

pub(crate) fn build_cmdline(args: &[String]) -> String {
    args.iter()
        .map(|a| if a.contains(' ') { format!("\"{a}\"") } else { a.clone() })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_command_line_is_clamped_to_the_env_region() {
        assert_eq!(truncate_cmdline("short".into()), "short");

        let long = "a".repeat(CMDLINE_MAX_BYTES * 3);
        let cut = truncate_cmdline(long);
        assert_eq!(cut.len(), CMDLINE_MAX_BYTES);

        let wide = "é".repeat(CMDLINE_MAX_BYTES);
        let cut = truncate_cmdline(wide);
        assert!(cut.len() <= CMDLINE_MAX_BYTES, "{} bytes", cut.len());
        assert!(cut.chars().all(|c| c == 'é'), "cut on a character boundary");
        let utf16_bytes = cut.encode_utf16().count() * 2 + 2;
        assert!(utf16_bytes <= 0xC00, "{utf16_bytes} UTF-16 bytes");
        assert!(cut.len() < 0x400, "{} bytes + NUL", cut.len());
    }
}
