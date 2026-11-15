//! Selection for the explicitly invoked storage acceptance entry.

enum StorageRoute {
    Headless,
    Platform,
}

/// Ordinary entry never grants native access. Acceptance requires both its
/// build feature and exact permit before selecting the platform operation.
///
/// # Errors
/// Returns the missing authorization or invalid selection reason.
pub fn dispatch<T>(
    acceptance: bool,
    live_feature: bool,
    selection: Option<&str>,
    permit: Option<&str>,
    headless: impl FnOnce() -> T,
    platform: impl FnOnce() -> T,
) -> Result<T, &'static str> {
    let route = if !acceptance {
        StorageRoute::Headless
    } else {
        match selection {
            None | Some("headless") => StorageRoute::Headless,
            Some("platform") if live_feature && permit == Some("real-platform-keyring") => {
                StorageRoute::Platform
            }
            Some("platform") => {
                return Err("platform acceptance requires its feature and exact permit");
            }
            Some(_) => return Err("acceptance storage must be headless or platform"),
        }
    };
    Ok(match route {
        StorageRoute::Headless => headless(),
        StorageRoute::Platform => platform(),
    })
}

/// Supplies the leading argument only for a fully authorized platform entry.
#[cfg(test)]
pub fn child_argument(
    live_feature: bool,
    selection: Option<&str>,
    permit: Option<&str>,
) -> Result<Option<&'static str>, &'static str> {
    dispatch(
        true,
        live_feature,
        selection,
        permit,
        || None,
        || Some("--test-live-platform-keyring"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn route_matrix_calls_only_the_selected_operation() {
        for (entry, feature, selection, permit, expected) in [
            (
                false,
                true,
                Some("platform"),
                Some("real-platform-keyring"),
                Ok(false),
            ),
            (
                true,
                true,
                Some("headless"),
                Some("real-platform-keyring"),
                Ok(false),
            ),
            (
                true,
                false,
                Some("platform"),
                Some("real-platform-keyring"),
                Err(()),
            ),
            (true, true, Some("platform"), None, Err(())),
            (true, true, Some("platform"), Some("wrong"), Err(())),
            (
                true,
                true,
                Some("platform"),
                Some("real-platform-keyring"),
                Ok(true),
            ),
        ] {
            let headless = Cell::new(0);
            let native = Cell::new(0);
            let result = dispatch(
                entry,
                feature,
                selection,
                permit,
                || {
                    headless.set(headless.get() + 1);
                    false
                },
                || {
                    native.set(native.get() + 1);
                    true
                },
            );
            assert_eq!(result.map_err(|_| ()), expected, "route selection");
            assert_eq!(
                headless.get(),
                usize::from(expected == Ok(false)),
                "headless operation count"
            );
            assert_eq!(
                native.get(),
                usize::from(expected == Ok(true)),
                "native operation count"
            );
            if entry {
                assert_eq!(
                    child_argument(feature, selection, permit).map_err(|_| ()),
                    expected.map(|native| native.then_some("--test-live-platform-keyring")),
                    "child entry argument",
                );
            }
        }
    }
}
