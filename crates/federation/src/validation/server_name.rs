use crate::response::{Error, ErrorCode, InvalidServerNameErrorCode, Root};

#[tracing::instrument(skip(data))]
pub fn parse_and_validate_server_name(data: &mut Root, server_name: &str) {
    if server_name.is_empty() {
        data.error = Some(Error {
            error: "Invalid server name: empty string".to_string(),
            error_code: ErrorCode::InvalidServerName(InvalidServerNameErrorCode::EmptyString),
        });
        return;
    }

    let is_bracketed = server_name.starts_with('[');

    // Split hostname and port, handling IPv6 literals in brackets: [addr] or [addr]:port
    let (hostname, port_str): (&str, &str) = if is_bracketed {
        match server_name.find(']') {
            Some(end) => {
                let inner = &server_name[1..end];
                let rest = &server_name[end + 1..];
                let port = rest.strip_prefix(':').unwrap_or(rest);
                (inner, port)
            }
            None => {
                data.error = Some(Error {
                    error: format!(
                        "Invalid server name: {server_name} (Missing closing bracket for IPv6)"
                    ),
                    error_code: ErrorCode::InvalidServerName(
                        InvalidServerNameErrorCode::InvalidCharacter,
                    ),
                });
                return;
            }
        }
    } else {
        match server_name.find(':') {
            Some(i) => (&server_name[..i], &server_name[i + 1..]),
            None => (server_name, ""),
        }
    };

    // Check if host part is one of:
    // - a valid (ascii) dns name
    // - an IP literal (IPv4 or IPv6)

    if hostname.is_empty() {
        data.error = Some(Error {
            error: "Invalid server name: empty hostname".to_string(),
            error_code: ErrorCode::InvalidServerName(InvalidServerNameErrorCode::EmptyHostname),
        });
        return;
    }

    // Pre-filter before the expensive IpAddr::from_str (which attempts both IPv4 and IPv6):
    // - Bracketed form: inner could be IPv4 or IPv6 → hex digits, ':', '.'
    // - Non-bracketed: only IPv4 is valid per Matrix spec (IPv6 requires brackets) → digits, '.'
    // Anything outside these sets can't be a valid IP, so skip the parse entirely.
    let might_be_ip = if is_bracketed {
        hostname
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.'))
    } else {
        hostname.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    };

    if might_be_ip && hostname.parse::<std::net::IpAddr>().is_ok() {
        // Valid IP literal; validate port if present
        if !port_str.is_empty() && port_str.parse::<u16>().is_err() {
            data.error = Some(Error {
                error: format!("Invalid server name: {server_name} (Invalid port '{port_str}')"),
                error_code: ErrorCode::InvalidServerName(
                    InvalidServerNameErrorCode::InvalidCharacter,
                ),
            });
        }
        return;
    }

    // Not an IP literal — validate as DNS name
    if !hostname.is_ascii() || hostname.len() > 255 {
        data.error = Some(Error {
            error: format!("Invalid server name: {server_name} (Not a valid DNS name)",),
            error_code: ErrorCode::InvalidServerName(InvalidServerNameErrorCode::NotValidDNS),
        });
        return;
    }

    // Single-pass over bytes: detect invalid characters and ".." simultaneously.
    // Since is_ascii() passed above, iterating bytes is equivalent to iterating chars.
    let mut prev_was_dot = false;
    for b in hostname.bytes() {
        if b == b'.' {
            if prev_was_dot {
                data.error = Some(Error {
                    error: format!("Invalid server name: {server_name} (Not a valid DNS name)",),
                    error_code: ErrorCode::InvalidServerName(
                        InvalidServerNameErrorCode::NotValidDNS,
                    ),
                });
                return;
            }
            prev_was_dot = true;
        } else {
            prev_was_dot = false;
            if !b.is_ascii_alphanumeric() && b != b'-' {
                let c = b as char;
                data.error = Some(Error {
                    error: format!("Invalid server name: {server_name} (Invalid character '{c}')",),
                    error_code: ErrorCode::InvalidServerName(
                        InvalidServerNameErrorCode::InvalidCharacter,
                    ),
                });
                return;
            }
        }
    }
}
