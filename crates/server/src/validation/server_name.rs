use crate::response::{Error, ErrorCode, InvalidServerNameErrorCode, Root};

pub fn parse_and_validate_server_name(data: &mut Root, server_name: &str) {
    if server_name.is_empty() {
        data.error = Some(Error {
            error: "Invalid server name: empty string".to_string(),
            error_code: ErrorCode::InvalidServerName(InvalidServerNameErrorCode::EmptyString),
        });
    }

    // Split off the port if it exists
    let parts: Vec<&str> = server_name.split(':').collect();
    let hostname = parts[0];

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

    if hostname.parse::<std::net::IpAddr>().is_err() {
        // Check if it's a valid DNS name
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
}
