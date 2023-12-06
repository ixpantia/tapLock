ENTRA_ID_BASE_URL <- "https://login.microsoftonline.com"

build_entra_id_login_url <- function(auth_url, client_id, redirect_uri) {
  url <- httr2::url_parse(auth_url)
  url$query <- list(
    client_id = client_id,
    redirect_uri = redirect_uri,
    response_mode = "form_post",
    response_type = "code",
    prompt = "login",
    scope = glue::glue("{client_id}/.default")
  )
  httr2::url_build(url)
}

new_entra_id_config <- function(tenant_id, client_id, client_secret, redirect_uri) {
  auth_url <- glue::glue("{ENTRA_ID_BASE_URL}/{tenant_id}/oauth2/v2.0/authorize")
  token_url <- glue::glue("{ENTRA_ID_BASE_URL}/{tenant_id}/oauth2/v2.0/token")
  jwks_url <- glue::glue("{ENTRA_ID_BASE_URL}/{tenant_id}/discovery/v2.0/keys")
  login_url <- build_entra_id_login_url(auth_url, client_id, redirect_uri)
  structure(
    list(
      tenant_id = tenant_id,
      client_id = client_id,
      client_secret = client_secret,
      redirect_uri = redirect_uri,
      auth_url = auth_url,
      token_url = token_url,
      jwks_url = jwks_url,
      login_url = login_url,
      jwks = fetch_jwks(jwks_url)
    ),
    class = c("entra_id_config", "openid_config")
  )
}

#' @export
get_login_url.entra_id_config <- function(config) {
  config$login_url
}

#' @export
get_logout_url.entra_id_config <- function(config) {
  stop("Logout not implemented for Entra ID")
}

#' @export
request_token.entra_id_config <- function(config, authorization_code) {
  res <- httr2::request(config$token_url) |>
    httr2::req_method("POST") |>
    httr2::req_body_form(
      code = authorization_code,
      client_id = config$client_id,
      client_secret = config$client_secret,
      grant_type = "authorization_code",
      redirect_uri = config$redirect_uri
    ) |>
    httr2::req_perform()
  resp_status <- httr2::resp_status(res)
  if (resp_status != 200) {
    stop(httr2::resp_body_string(res))
  }
  resp_body <- httr2::resp_body_json(res)
  access_token(config, resp_body$access_token)
}

#' @export
decode_token.entra_id_config <- function(config, token) {
  decoded <- config$jwks |>
    purrr::map(function(jwk) {
      tryCatch(
        jose::jwt_decode_sig(token, jwk),
        error = function(e) {
          NULL
        }
      )
    }) |>
    purrr::discard(is.null) |>
    purrr::pluck(1, .default = NULL)
  if (is.null(decoded)) {
    stop("Unable to decode token")
  }
  return(decoded)
}

#' @export
get_client_id.entra_id_config <- function(config) {
  config$client_id
}
