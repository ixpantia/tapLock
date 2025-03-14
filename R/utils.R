#' @title Remove bearer from token
#' @description Removes the "Bearer " prefix from a token
#'
#' @param token A string containing the token
#'
#' @return A string containing the token without the "Bearer " prefix
#' @keywords internal
remove_bearer <- function(token) {
  if (is.null(token)) {
    return(NULL)
  }
  token <- stringr::str_remove(token, "^Bearer ")
  return(token)
}

#' @title Parse cookies
#' @description Parses cookies from a string
#'
#' @param x A string containing the cookies
#'
#' @return A list containing the cookies
#' @keywords internal
parse_cookies <- function(x) {
  if (is.null(x)) {
    return(list())
  }
  cookie_pairs <- stringr::str_split(x, "; ")
  cookie_pairs <- purrr::map(cookie_pairs, ~ stringr::str_split(.x, "=", n = 2))[[1]]
  cookie_pairs <- purrr::map(cookie_pairs, function(.x) {
    .x[2] <- curl::curl_unescape(.x[2])
    stats::setNames(.x[2], .x[1])
  })
  cookie_pairs <- purrr::flatten(cookie_pairs)
  return(cookie_pairs)
}

#' @title Build a cookie
#' @description Builds an HttpOnly cookie from a key and value
#'
#' @param key A string containing the cookie key
#' @param value A string containing the cookie value
#'
#' @return A string containing the cookie
#' @keywords internal
build_cookie <- function(key, value) {
  glue::glue("{key}={value}; path=/; SameSite=Lax; HttpOnly")
}

map_null <- function(x, f) {
  if (is.null(x)) {
    return(NULL)
  }
  return(f(x))
}

add_trailing_slash_to_path <- function(path) {
  if (!stringr::str_ends(path, "/")) {
    path <- glue::glue("{path}/")
  }
  return(path)
}

if_length_0 <- function(x, y) {
  if (length(x) == 0) {
    return(y)
  }
  return(x)
}
