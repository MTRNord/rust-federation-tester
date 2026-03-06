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

    // Split hostname and port, handling IPv6 literals in brackets: [addr] or [addr]:port
    let (hostname, port_str): (&str, &str) = if server_name.starts_with('[') {
        match server_name.find(']') {
            Some(end) => {
                let inner = &server_name[1..end];
                let rest = &server_name[end + 1..];
                let port = if rest.starts_with(':') {
                    &rest[1..]
                } else {
                    rest
                };
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

    if hostname.parse::<std::net::IpAddr>().is_ok() {
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
    if !hostname.is_ascii() || hostname.len() > 255 || hostname.contains("..") {
        data.error = Some(Error {
            error: format!("Invalid server name: {server_name} (Not a valid DNS name)",),
            error_code: ErrorCode::InvalidServerName(InvalidServerNameErrorCode::NotValidDNS),
        });
        return;
    }

    // Check for invalid characters in the hostname
    for c in hostname.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != '.' {
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
