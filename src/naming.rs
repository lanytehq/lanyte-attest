use crate::{AttestError, Result};

const MAX_SEGMENT_LEN: usize = 63;
const MAX_NAME_LEN: usize = 253;

pub fn validate_instance_name(name: &str) -> Result<()> {
    validate_name(name, '.', false)
}

pub fn validate_scope_path(path: &str) -> Result<()> {
    validate_name(path, '/', false)
}

pub fn validate_role_slug(slug: &str) -> Result<()> {
    validate_slug(slug)?;
    let first = slug
        .chars()
        .next()
        .ok_or_else(|| AttestError::Validation("role slug must not be empty".into()))?;
    if !first.is_ascii_lowercase() {
        return Err(AttestError::Validation(
            "role slug must start with a lowercase letter".into(),
        ));
    }
    Ok(())
}

fn validate_name(value: &str, separator: char, role_slug: bool) -> Result<()> {
    if value.is_empty() {
        return Err(AttestError::Validation("name must not be empty".into()));
    }
    if value.len() > MAX_NAME_LEN {
        return Err(AttestError::Validation(format!(
            "name exceeds {MAX_NAME_LEN} characters"
        )));
    }
    if value.starts_with(separator)
        || value.ends_with(separator)
        || value.contains(&format!("{separator}{separator}"))
    {
        return Err(AttestError::Validation(format!(
            "name contains an empty segment around '{separator}'"
        )));
    }

    for segment in value.split(separator) {
        if role_slug {
            validate_role_slug(segment)?;
        } else {
            validate_slug(segment)?;
        }
    }

    Ok(())
}

fn validate_slug(segment: &str) -> Result<()> {
    if segment.is_empty() {
        return Err(AttestError::Validation("segment must not be empty".into()));
    }
    if segment.len() > MAX_SEGMENT_LEN {
        return Err(AttestError::Validation(format!(
            "segment '{segment}' exceeds {MAX_SEGMENT_LEN} characters"
        )));
    }
    if segment.starts_with('-') || segment.ends_with('-') {
        return Err(AttestError::Validation(format!(
            "segment '{segment}' must not start or end with '-'"
        )));
    }
    if !segment
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        return Err(AttestError::Validation(format!(
            "segment '{segment}' contains invalid characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_instance_name, validate_role_slug, validate_scope_path};

    #[test]
    fn accepts_valid_instance_name() {
        validate_instance_name("lanyte-attest").expect("instance name should be valid");
    }

    #[test]
    fn rejects_invalid_instance_name() {
        assert!(validate_instance_name("Lanyte").is_err());
    }

    #[test]
    fn accepts_valid_scope_path() {
        validate_scope_path("lanytehq/core-runtime").expect("scope path should be valid");
        validate_scope_path("3leaps/ipcprims").expect("numeric-leading scope segment is valid");
    }

    #[test]
    fn rejects_invalid_scope_path() {
        assert!(validate_scope_path("lanytehq/").is_err());
    }

    #[test]
    fn accepts_valid_role_slug() {
        validate_role_slug("devlead").expect("role slug should be valid");
    }

    #[test]
    fn rejects_invalid_role_slug() {
        assert!(validate_role_slug("1devlead").is_err());
    }
}
