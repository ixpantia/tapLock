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
#'   The `"keycloak"` provider accepts the following arguments:
#'   - `base_url`
#'   - `realm`
#'   - `client_id`
#'   - `client_secret`
#'
#' @return An openid_config object
#' @export
new_openid_config <- function(provider, app_url, ...) {
  switch(
    provider,
    entra_id = new_entra_id_config(app_url = app_url, ...),
    google = new_google_config(app_url = app_url, ...),
    keycloak = new_keycloak_config(app_url = app_url, ...)
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
  config$get_authorization_url()
}

POLL_INTERVAL <- 0.005 # nolint: object_name_linter.

async_future_to_promise <- function(x) {
  promises::promise(function(resolve, reject) {
    if (is_error(x)) {
      return(reject(x$value))
    }

    poll_recursive <- function() {
      result <- x$poll()
      if (result$is_pending()) {
        return(later::later(poll_recursive, POLL_INTERVAL))
      }
      if (result$is_ready()) {
        return(resolve(result$value()))
      }
      if (result$is_error()) return(reject(result$error()))
    }

    poll_recursive()
  })
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
  async_future_to_promise(config$request_token(authorization_code))
}

#' @keywords internal
request_token_refresh <- function(config, refresh_token) {
  async_future_to_promise(config$request_token_refresh(refresh_token))
}
