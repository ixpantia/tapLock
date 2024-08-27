#' @keywords internal
fetch_jwks <- function(url) {
  httr2::request(url) |>
    httr2::req_method("GET") |>
    httr2::req_perform() |>
    httr2::resp_body_json() |>
    purrr::pluck("keys") |>
    purrr::map(jose::jwk_read)
}

#' @title New openid configuration
#' @description Creates a new openid configuration object
#'   for the given provider. You can use this function or
#'   the individual provider functions.
#'
#' @param provider The openid provider to use
#' @param app_url The URL of the application
#'   (used to build redirect, login, and logout URLs)
#' @param ... Additional arguments passed to the provider's configuration.
#'   This depends on the provider.
#'
#'   The `"google"` provider accepts the following arguments:
#'   - `client_id`
#'   - `client_secret`
#'
#'   The `"entra_id"` provider accepts the following arguments:
#'   - `client_id`
#'   - `client_secret`
#'   - `tenant_id`
#'
#'   The `"auth0"` provider accepts the following arguments:
#'   - `client_id`
#'   - `client_secret`
#'   - `auth0_domain`
#'
#' @return An openid_config object
#' @export
new_openid_config <- function(provider, app_url, ...) {
  switch(provider,
    entra_id = new_entra_id_config(app_url = app_url, ...),
    google = new_google_config(app_url = app_url, ...),
    auth0 = new_auth0_config(app_url = app_url, ...),
  )
}

#' @title Get the login URL for the app
#' @description Gets the URL that the provider should redirect to
#'   after a login attempt.
#'
#' @param config An openid_config object
#'
#' @return A string containing the login URL
#' @keywords internal
get_login_url <- function(config) {
  UseMethod("get_login_url")
}


#' @title Get the logout URL for the provider
#' @description Gets the URL for SLO (single logout)
#'
#' @param config An openid_config object
#'
#' @return A string containing the logout URL
#' @keywords internal
get_logout_url <- function(config) {
  UseMethod("get_logout_url")
}

#' @title Request a token from the provider
#' @description Requests a token from the provider
#'
#' @param config An openid_config object
#' @param authorization_code The authorization code to use
#'
#' @return An access_token object
#' @keywords internal
request_token <- function(config, authorization_code) {
  UseMethod("request_token")
}

#' @keywords internal
request_token_refresh <- function(config, refresh_token) {
  UseMethod("request_token_refresh")
}

#' @title Decode a token
#' @description Decodes a token
#'
#' @param config An openid_config object
#' @param token The token to decode
#'
#' @return A list containing the decoded token's data
#' @keywords internal
decode_token <- function(config, token) {
  UseMethod("decode_token")
}

#' @title Get the client ID
#' @description Gets the client ID for the provider
#'
#' @param config An openid_config object
#'
#' @return A string containing the client ID
#' @keywords internal
get_client_id <- function(config) {
  UseMethod("get_client_id")
}

#' @title Refresh the JWKS
#' @description Refreshes the JWKS
#'
#' @param config An openid_config object
#' @keywords internal
refresh_jwks <- function(config) {
  UseMethod("refresh_jwks")
}
