use bytes::Buf;

use crate::error::{PgWireError, Result};
use crate::lsn::Lsn;

/// Parsed PostgreSQL error/notice response fields
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ErrorFields {
    pub severity: Option<String>,
    pub code: Option<String>, // SQLSTATE
    pub message: Option<String>,
    pub detail: Option<String>,
    pub hint: Option<String>,
    pub position: Option<String>,
    pub where_: Option<String>,
    pub schema: Option<String>,
    pub table: Option<String>,
    pub column: Option<String>,
    pub data_type: Option<String>,
    pub constraint: Option<String>,
    pub file: Option<String>,
    pub line: Option<String>,
    pub routine: Option<String>,
}

impl ErrorFields {
    /// Parse error fields from payload bytes
    pub fn parse(payload: &[u8]) -> Self {
        let mut fields = ErrorFields::default();
        let mut b = payload;

        while !b.is_empty() {
            let code = b[0];
            b = &b[1..];
            if code == 0 {
                break;
            }
            if let Some(pos) = b.iter().position(|&x| x == 0) {
                let s = String::from_utf8_lossy(&b[..pos]).to_string();
                match code {
                    b'S' => fields.severity = Some(s),
                    b'C' => fields.code = Some(s),
                    b'M' => fields.message = Some(s),
                    b'D' => fields.detail = Some(s),
                    b'H' => fields.hint = Some(s),
                    b'P' => fields.position = Some(s),
                    b'W' => fields.where_ = Some(s),
                    b's' => fields.schema = Some(s),
                    b't' => fields.table = Some(s),
                    b'c' => fields.column = Some(s),
                    b'd' => fields.data_type = Some(s),
                    b'n' => fields.constraint = Some(s),
                    b'F' => fields.file = Some(s),
                    b'L' => fields.line = Some(s),
                    b'R' => fields.routine = Some(s),
                    _ => {} // ignore unknown fields
                }
                b = &b[pos + 1..];
            } else {
                break;
            }
        }

        fields
    }

    /// Format as a human-readable error string
    pub fn to_error_string(&self) -> String {
        match (&self.message, &self.code) {
            (Some(m), Some(c)) => format!("{m} (SQLSTATE {c})"),
            (Some(m), None) => m.clone(),
            (None, Some(c)) => format!("error (SQLSTATE {c})"),
            (None, None) => "unknown server error".to_string(),
        }
    }
}

/// Parse an ErrorResponse payload into a human-readable string.
///
/// For more detailed error information, use `ErrorFields::parse()` instead.
pub fn parse_error_response(payload: &[u8]) -> String {
    ErrorFields::parse(payload).to_error_string()
}

/// Parse an AuthenticationRequest payload.
///
/// Returns (auth_type, remaining_data).
/// Auth types:
/// - 0 = AuthenticationOk
/// - 3 = AuthenticationCleartextPassword
/// - 5 = AuthenticationMD5Password (data contains 4-byte salt)
/// - 10 = AuthenticationSASL (data contains mechanism names)
/// - 11 = AuthenticationSASLContinue
/// - 12 = AuthenticationSASLFinal
pub fn parse_auth_request(payload: &[u8]) -> Result<(i32, &[u8])> {
    if payload.len() < 4 {
        return Err(PgWireError::Protocol("auth request too short".into()));
    }
    let mut b = payload;
    let code = b.get_i32();
    Ok((code, b))
}

/// Server identity reported by `IDENTIFY_SYSTEM`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServerIdentity {
    /// Unique identifier of the database cluster (`systemid`).
    pub system_id: String,
    /// Current timeline.
    pub timeline: u32,
    /// Current WAL flush location (`xlogpos`).
    pub xlog_pos: Lsn,
    /// Database connected to, if any.
    pub dbname: Option<String>,
}

impl ServerIdentity {
    /// Parse the DataRow payload of an `IDENTIFY_SYSTEM` response.
    pub fn from_data_row(payload: &[u8]) -> Result<Self> {
        let columns = parse_data_row(payload)?;
        let [system_id, timeline, xlog_pos, dbname] = columns.as_slice() else {
            return Err(PgWireError::Protocol(format!(
                "IDENTIFY_SYSTEM returned {} columns, expected 4",
                columns.len()
            )));
        };
        let timeline = column_text(*timeline, "timeline")?
            .parse()
            .map_err(|e| PgWireError::Protocol(format!("invalid IDENTIFY_SYSTEM timeline: {e}")))?;
        let xlog_pos = Lsn::parse(column_text(*xlog_pos, "xlogpos")?)
            .map_err(|e| PgWireError::Protocol(format!("invalid IDENTIFY_SYSTEM xlogpos: {e}")))?;
        let dbname = match *dbname {
            Some(value) => Some(column_text(Some(value), "dbname")?.to_owned()),
            None => None,
        };
        Ok(Self {
            system_id: column_text(*system_id, "systemid")?.to_owned(),
            timeline,
            xlog_pos,
            dbname,
        })
    }
}

fn column_text<'a>(value: Option<&'a [u8]>, name: &str) -> Result<&'a str> {
    let bytes =
        value.ok_or_else(|| PgWireError::Protocol(format!("IDENTIFY_SYSTEM {name} is null")))?;
    std::str::from_utf8(bytes)
        .map_err(|_| PgWireError::Protocol(format!("IDENTIFY_SYSTEM {name} is not UTF-8")))
}

/// Split a DataRow payload into its column values, `None` for SQL NULL.
pub fn parse_data_row(payload: &[u8]) -> Result<Vec<Option<&[u8]>>> {
    let truncated = || PgWireError::Protocol("data row truncated".into());
    let mut b = payload;
    if b.len() < 2 {
        return Err(truncated());
    }
    let count = b.get_i16();
    let mut columns = Vec::with_capacity(count.max(0) as usize);
    for _ in 0..count {
        if b.len() < 4 {
            return Err(truncated());
        }
        let len = b.get_i32();
        if len < 0 {
            columns.push(None);
            continue;
        }
        let len = len as usize;
        if b.len() < len {
            return Err(truncated());
        }
        columns.push(Some(&b[..len]));
        b.advance(len);
    }
    Ok(columns)
}

/// Authentication type constants
pub mod auth {
    pub const OK: i32 = 0;
    pub const CLEARTEXT_PASSWORD: i32 = 3;
    pub const MD5_PASSWORD: i32 = 5;
    pub const SASL: i32 = 10;
    pub const SASL_CONTINUE: i32 = 11;
    pub const SASL_FINAL: i32 = 12;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_row(columns: &[Option<&str>]) -> Vec<u8> {
        let mut payload = (columns.len() as i16).to_be_bytes().to_vec();
        for column in columns {
            match column {
                Some(value) => {
                    payload.extend_from_slice(&(value.len() as i32).to_be_bytes());
                    payload.extend_from_slice(value.as_bytes());
                }
                None => payload.extend_from_slice(&(-1i32).to_be_bytes()),
            }
        }
        payload
    }

    #[test]
    fn server_identity_parses_identify_system_row() {
        let row = data_row(&[
            Some("7412345678901234567"),
            Some("2"),
            Some("0/16B3748"),
            Some("postgres"),
        ]);
        let identity = ServerIdentity::from_data_row(&row).unwrap();
        assert_eq!(identity.system_id, "7412345678901234567");
        assert_eq!(identity.timeline, 2);
        assert_eq!(identity.xlog_pos, Lsn::parse("0/16B3748").unwrap());
        assert_eq!(identity.dbname.as_deref(), Some("postgres"));
    }

    #[test]
    fn server_identity_accepts_null_dbname() {
        let row = data_row(&[Some("1"), Some("1"), Some("0/0"), None]);
        assert_eq!(ServerIdentity::from_data_row(&row).unwrap().dbname, None);
    }

    #[test]
    fn server_identity_rejects_null_system_id_and_wrong_column_count() {
        let null_id = data_row(&[None, Some("1"), Some("0/0"), None]);
        assert!(ServerIdentity::from_data_row(&null_id).is_err());
        let short = data_row(&[Some("1"), Some("1"), Some("0/0")]);
        assert!(ServerIdentity::from_data_row(&short).is_err());
    }

    #[test]
    fn parse_data_row_rejects_truncated_payload() {
        let mut row = data_row(&[Some("abcdef")]);
        row.truncate(row.len() - 2);
        assert!(parse_data_row(&row).is_err());
        assert!(parse_data_row(&[0]).is_err());
    }

    #[test]
    fn parse_error_response_extracts_message_and_code() {
        // 'M' "hello" \0 'C' "12345" \0 \0
        let payload = [
            b'M', b'h', b'e', b'l', b'l', b'o', 0, b'C', b'1', b'2', b'3', b'4', b'5', 0, 0,
        ];
        let s = parse_error_response(&payload);
        assert!(s.contains("hello"));
        assert!(s.contains("SQLSTATE 12345"));
    }

    #[test]
    fn parse_error_response_handles_message_only() {
        let payload = [b'M', b't', b'e', b's', b't', 0, 0];
        let s = parse_error_response(&payload);
        assert_eq!(s, "test");
    }

    #[test]
    fn parse_error_response_handles_code_only() {
        let payload = [b'C', b'4', b'2', b'0', b'0', b'0', 0, 0];
        let s = parse_error_response(&payload);
        assert_eq!(s, "error (SQLSTATE 42000)");
    }

    #[test]
    fn parse_error_response_handles_empty() {
        let payload = [0];
        let s = parse_error_response(&payload);
        assert_eq!(s, "unknown server error");
    }

    #[test]
    fn parse_error_response_handles_truly_empty() {
        let payload: &[u8] = &[];
        let s = parse_error_response(payload);
        assert_eq!(s, "unknown server error");
    }

    #[test]
    fn error_fields_parses_all_standard_fields() {
        let mut payload = Vec::new();
        // Build a realistic error response
        payload.extend_from_slice(b"SERROR\0");
        payload.extend_from_slice(b"C42P01\0");
        payload.extend_from_slice(b"Mrelation \"foo\" does not exist\0");
        payload.extend_from_slice(b"Dsome detail\0");
        payload.extend_from_slice(b"Htry this\0");
        payload.extend_from_slice(b"sschema_name\0");
        payload.extend_from_slice(b"ttable_name\0");
        payload.extend_from_slice(b"Fparse_relation.c\0");
        payload.extend_from_slice(b"L1234\0");
        payload.extend_from_slice(b"Rsome_routine\0");
        payload.push(0); // terminator

        let fields = ErrorFields::parse(&payload);

        assert_eq!(fields.severity.as_deref(), Some("ERROR"));
        assert_eq!(fields.code.as_deref(), Some("42P01"));
        assert_eq!(
            fields.message.as_deref(),
            Some("relation \"foo\" does not exist")
        );
        assert_eq!(fields.detail.as_deref(), Some("some detail"));
        assert_eq!(fields.hint.as_deref(), Some("try this"));
        assert_eq!(fields.schema.as_deref(), Some("schema_name"));
        assert_eq!(fields.table.as_deref(), Some("table_name"));
        assert_eq!(fields.file.as_deref(), Some("parse_relation.c"));
        assert_eq!(fields.line.as_deref(), Some("1234"));
        assert_eq!(fields.routine.as_deref(), Some("some_routine"));
    }

    #[test]
    fn error_fields_handles_truncated_payload() {
        // Missing null terminator for value
        let payload = *b"Mhello";
        let fields = ErrorFields::parse(&payload);
        // Should not panic, just skip incomplete field
        assert!(fields.message.is_none());
    }

    #[test]
    fn error_fields_ignores_unknown_field_codes() {
        let payload = [b'X', b'u', b'n', b'k', 0, b'M', b'o', b'k', 0, 0];
        let fields = ErrorFields::parse(&payload);
        // Unknown 'X' field ignored, 'M' field parsed
        assert_eq!(fields.message.as_deref(), Some("ok"));
    }

    #[test]
    fn parse_auth_request_ok() {
        let payload = [0, 0, 0, 0]; // auth type 0 = OK
        let (code, rest) = parse_auth_request(&payload).unwrap();
        assert_eq!(code, auth::OK);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_auth_request_md5_with_salt() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&5i32.to_be_bytes()); // MD5
        payload.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // salt

        let (code, salt) = parse_auth_request(&payload).unwrap();
        assert_eq!(code, auth::MD5_PASSWORD);
        assert_eq!(salt, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parse_auth_request_sasl_with_mechanisms() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&10i32.to_be_bytes()); // SASL
        payload.extend_from_slice(b"SCRAM-SHA-256\0");
        payload.extend_from_slice(b"SCRAM-SHA-256-PLUS\0");
        payload.push(0); // terminator

        let (code, mechanisms) = parse_auth_request(&payload).unwrap();
        assert_eq!(code, auth::SASL);
        assert!(mechanisms.starts_with(b"SCRAM-SHA-256"));
    }

    #[test]
    fn parse_auth_request_rejects_short_payload() {
        let payload = [0, 0, 0]; // only 3 bytes
        let err = parse_auth_request(&payload).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn auth_constants_have_correct_values() {
        assert_eq!(auth::OK, 0);
        assert_eq!(auth::CLEARTEXT_PASSWORD, 3);
        assert_eq!(auth::MD5_PASSWORD, 5);
        assert_eq!(auth::SASL, 10);
        assert_eq!(auth::SASL_CONTINUE, 11);
        assert_eq!(auth::SASL_FINAL, 12);
    }
}
