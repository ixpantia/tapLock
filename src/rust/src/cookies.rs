use extendr_api::prelude::*;

/// @title Parse cookies
/// @description Parses cookies from a string
///
/// @param x A string containing the cookies
///
/// @return A list containing the cookies
/// @keywords internal
#[extendr]
fn parse_cookies(cookie_string: Option<&str>) -> List {
    // Use unwrap_or to default to an empty string and trim whitespace.
    let input = cookie_string.unwrap_or("").trim();
    if input.is_empty() {
        return List::new(0);
    }

    // Split the cookie string on ';' and process each key=value segment.
    let values = input
        .split(';')
        .filter_map(|segment| {
            let trimmed_segment = segment.trim();
            if trimmed_segment.is_empty() {
                return None;
            }
            // Split on the first '=' character.
            let (raw_key, raw_value) = trimmed_segment.split_once('=')?;
            let key = raw_key.trim();
            if key.is_empty() {
                return None;
            }
            // Trim the raw value and attempt URL decoding.
            let decoded_value = urlencoding::decode(raw_value.trim()).ok()?;
            Some((key, Robj::from(decoded_value.as_ref())))
        })
        .collect::<Vec<_>>();

    List::from_pairs(values)
}

extendr_module! {
    mod cookies;
    fn parse_cookies;
}
