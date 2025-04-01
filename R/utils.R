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
