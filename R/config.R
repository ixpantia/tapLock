fetch_jwks <- function(url) {
  httr2::request(url) |>
    httr2::req_method("GET") |>
    httr2::req_perform() |>
    httr2::resp_body_json() |>
    purrr::pluck("keys") |>
    purrr::map(jose::jwk_read)
}

#' @export
new_openid_config <- function(provider, ...) {
  switch(provider,
    entra_id = new_entra_id_config(...),
    google = new_google_config(...)
  )
}

#' @export
get_login_url <- function(config) {
  UseMethod("get_login_url")
}

#' @export
get_logout_url <- function(config) {
  UseMethod("get_logout_url")
}

#' @export
request_token <- function(config, authorization_code) {
  UseMethod("request_token")
}

#' @export
decode_token <- function(config, token) {
  UseMethod("decode_token")
}

#' @export
get_client_id <- function(config) {
  UseMethod("get_client_id")
}

#' @export
refresh_jwks <- function(config) {
  UseMethod("refresh_jwks")
}
