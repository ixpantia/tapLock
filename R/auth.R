#' @export
access_token <- function(config, token) {
  UseMethod("access_token")
}

#' @export
access_token.google_config <- function(config, token) {
  token_data <- decode_token(config, token)
  structure(
    list(
      access_token = token,
      exp = lubridate::as_datetime(token_data$exp),
      iat = lubridate::as_datetime(token_data$iat),
      token_data = token_data
    ),
    class = c("google_token", "access_token")
  )
}

#' @export
access_token.entra_id_config <- function(config, token) {
  token_data <- decode_token(config, token)
  structure(
    list(
      access_token = token,
      exp = lubridate::as_datetime(token_data$exp),
      iat = lubridate::as_datetime(token_data$iat),
      token_data = token_data
    ),
    class = c("entra_id_token", "access_token")
  )
}

#' @export
print.access_token <- function(x, ...) {
  expiration_date <- expires_at(x)
  # Format the expiration date as a string
  expiration_date <- format(
    expiration_date,
    tz = "UTC",
    usetz = TRUE,
    format = "%Y-%m-%d %H:%M:%OS3"
  )
  cat(
    "Access Token:",
    "(Expires At)", expiration_date,
    "\n",
    sep = " "
  )
}

#' @export
is_valid <- function(token) {
  !is_expired(token)
}

#' @export
is_expired <- function(token) {
  Sys.time() > token$exp
}

#' @export
get_bearer <- function(token) {
  paste0("Bearer ", token$access_token)
}

#' @export
get_access_token <- function(token) {
  token$access_token
}

#' @export
expires_in <- function(token) {
  token$exp - Sys.time()
}

#' @export
expires_at <- function(token) {
  token$exp
}

#' @export
get_token_field <- function(token, field) {
  token$token_data[[field]]
}
