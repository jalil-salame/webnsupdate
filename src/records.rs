//! Deal with the DNS records

use miette::{ensure, miette, LabeledSpan, Result};

pub fn validate_record_str(record: &str) -> Result<()> {
    validate_line(0, record).map_err(|err| err.with_source_code(String::from(record)))
}

fn validate_line(offset: usize, line: &str) -> Result<()> {
    if line.is_empty() {
        return Ok(());
    }

    ensure!(
        line.len() <= 255,
        miette!(
            labels = [LabeledSpan::new(
                Some("this line".to_string()),
                offset,
                line.len(),
            )],
            help = "fully qualified domain names can be at most 255 characters long",
            url = "https://en.wikipedia.org/wiki/Fully_qualified_domain_name",
            "hostname too long ({} octets)",
            line.len(),
        )
    );
    ensure!(
        line.ends_with('.'),
        miette!(
            labels = [LabeledSpan::new(
                Some("last character".to_string()),
                offset + line.len() - 1,
                1,
            )],
            help = "hostname should be a fully qualified domain name (end with a '.')",
            url = "https://en.wikipedia.org/wiki/Fully_qualified_domain_name",
            "not a fully qualified domain name"
        )
    );

    let mut label_offset = 0usize;
    for label in line.strip_suffix('.').unwrap_or(line).split('.') {
        validate_label(offset + label_offset, label)?;
        label_offset += label.len() + 1;
    }

    Ok(())
}

fn validate_label(offset: usize, label: &str) -> Result<()> {
    ensure!(
        !label.is_empty(),
        miette!(
            labels = [LabeledSpan::new(
                Some("label".to_string()),
                offset,
                label.len(),
            )],
            help = "each label should have at least one character",
            url = "https://en.wikipedia.org/wiki/Fully_qualified_domain_name",
            "empty label",
        )
    );
    ensure!(
        label.len() <= 63,
        miette!(
            labels = [LabeledSpan::new(
                Some("label".to_string()),
                offset,
                label.len(),
            )],
            help = "labels should be at most 63 octets",
            url = "https://en.wikipedia.org/wiki/Fully_qualified_domain_name",
            "label too long ({} octets)",
            label.len(),
        )
    );

    for (octet_offset, octet) in label.bytes().enumerate() {
        validate_octet(offset + octet_offset, octet)?;
    }

    Ok(())
}

fn validate_octet(offset: usize, octet: u8) -> Result<()> {
    let spans = || [LabeledSpan::new(Some("octet".to_string()), offset, 1)];
    ensure!(
        octet.is_ascii(),
        miette!(
            labels = spans(),
            help = "we only accept ascii characters",
            url = "https://en.wikipedia.org/wiki/Hostname#Syntax",
            "invalid octet: '{}'",
            octet.escape_ascii(),
        )
    );

    ensure!(
        octet.is_ascii_alphanumeric() || octet == b'-' || octet == b'_',
        miette!(
            labels = spans(),
            help = "hostnames are only allowed to contain characters in [a-zA-Z0-9_-]",
            url = "https://en.wikipedia.org/wiki/Hostname#Syntax",
            "invalid octet: '{}'",
            octet.escape_ascii(),
        )
    );

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::records::validate_record_str;

    macro_rules! assert_miette_snapshot {
        ($diag:expr) => {{
            use std::borrow::Borrow;

            use insta::{with_settings, assert_snapshot};
            use miette::{GraphicalReportHandler, GraphicalTheme};

            let mut out = String::new();
            GraphicalReportHandler::new_themed(GraphicalTheme::unicode_nocolor())
                .with_width(80)
                .render_report(&mut out, $diag.borrow())
                .unwrap();
            with_settings!({
                description => stringify!($diag)
            }, {
                assert_snapshot!(out);
            });
        }};
    }

    #[test]
    fn valid_records() -> miette::Result<()> {
        for record in [
            "example.com.",
            "example.org.",
            "example.net.",
            "subdomain.example.com.",
        ] {
            validate_record_str(record)?;
        }
        Ok(())
    }

    #[test]
    fn hostname_too_long() {
        let err = validate_record_str("example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.example.net.").unwrap_err();
        assert_miette_snapshot!(err);
    }

    #[test]
    fn not_fqd() {
        let err = validate_record_str("example.net").unwrap_err();
        assert_miette_snapshot!(err);
    }

    #[test]
    fn empty_label() {
        let err = validate_record_str("name..example.org.").unwrap_err();
        assert_miette_snapshot!(err);
    }

    #[test]
    fn label_too_long() {
        let err = validate_record_str("name.an-entremely-long-label-that-should-not-exist-because-it-goes-against-the-spec.example.org.").unwrap_err();
        assert_miette_snapshot!(err);
    }

    #[test]
    fn invalid_ascii() {
        let err = validate_record_str("name.this-is-not-ascii-ß.example.org.").unwrap_err();
        assert_miette_snapshot!(err);
    }

    #[test]
    fn invalid_octet() {
        let err =
            validate_record_str("name.this-character:-is-not-allowed.example.org.").unwrap_err();
        assert_miette_snapshot!(err);
    }
}
