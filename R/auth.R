#' @title Create a new Access Token
#' @description Creates a new access token from a config and a token string
#'
#' @param config An openid_config object
#' @param token_str A string containing the access token to decode
#'
#' @return An access_token object
#' @keywords internal
#' @noRd
access_token <- function(config, token_str) {
  if (length(token_str) == 0) {
    return(error("No access_token provided"))
  }
  config$decode_token(token_str)
}

#' @title Print an access token
#' @description Prints an access token's expiration date
#'
#' @param x An access_token object
#' @param ... Ignored
#' @return No return value, called for side effects
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
  return()
}

#' @title Check if an access token is valid
#' @description Checks if an access token is valid
#'   by checking if it is expired
#'
#' @param token An access_token object
#'
#' @return A boolean indicating if the token is valid
#' @export
is_valid <- function(token) {
  !is_expired(token)
}

#' @title Check if an access token is expired
#' @description Checks if an access token is expired
#'
#' @param token An access_token object
#'
#' @return A boolean indicating if the token is expired
#' @export
is_expired <- function(token) {
  Sys.time() > token$exp
}

#' @title Get the Authorization header for an access token
#' @description Gets the Authorization header for an access token
#'
#' @param token An access_token object
#'
#' @return A string containing the Authorization header
#' @keywords internal
#' @noRd
add_bearer <- function(token) {
  paste0("Bearer ", token)
}

#' @title Get the access token string
#' @description Gets the access token string
#'
#' @param token An access_token object
#'
#' @return A string containing the access token
#' @keywords internal
#' @noRd
get_access_token <- function(token) {
  token$access_token
}

#' @title Get the expiration time of an access token
#' @description Gets the expiration time of an access token
#'
#' @param token An access_token object
#'
#' @return A duration object containing the time until the token expires
#' @export
expires_in <- function(token) {
  token$exp - Sys.time()
}

#' @title Get the expiration date and time of an access token
#' @description Gets the expiration date and time of an access token
#'
#' @param token An access_token object
#'
#' @return A POSIXct object containing the date and time the token expires
#' @export
expires_at <- function(token) {
  token$exp
}
