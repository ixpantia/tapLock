#' @export
access_token <- function(config, token) {
  UseMethod("access_token")
}

#' @export
access_token.entra_id_config <- function(config, token) {
  token_data <- decode_token(config, token)
  structure(
    list(
      access_token = token,
      exp = lubridate::as_datetime(token_data$exp),
      iat = lubridate::as_datetime(token_data$iat),
      nbf = lubridate::as_datetime(token_data$nbf),
      name = token_data$name,
      given_name = token_data$given_name,
      family_name = token_data$family_name,
      unique_name = token_data$unique_name,
      aud = token_data$aud
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
    "(Unique Name)", get_unique_name(x),
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
get_audience <- function(token) {
  token$aud
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
get_name <- function(token) {
  token$name
}

#' @export
get_given_name <- function(token) {
  token$given_name
}

#' @export
get_family_name <- function(token) {
  token$family_name
}

#' @export
get_unique_name <- function(token) {
  token$unique_name
}
