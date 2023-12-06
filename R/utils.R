remove_bearer <- function(token) {
  if (is.null(token)) {
    return(NULL)
  }
  token <- stringr::str_remove(token, "^Bearer ")
  return(token)
}

parse_cookies <- function(x) {
  if (is.null(x)) {
    return(list())
  }
  cookie_pairs <- stringr::str_split(x, "; ")
  cookie_pairs <- purrr::map(cookie_pairs, ~ stringr::str_split(.x, "=", n = 2))[[1]]
  cookie_pairs <- purrr::map(cookie_pairs, function(.x) {
    .x[2] <- curl::curl_unescape(.x[2])
    setNames(.x[2], .x[1])
  })
  cookie_pairs <- purrr::flatten(cookie_pairs)
  return(cookie_pairs)
}

build_cookie <- function(key, value) {
  glue::glue("{key}={value}; path=/; SameSite=Lax; HttpOnly")
}

build_redirect_uri <- function(app_url) {
  url <- httr2::url_parse(app_url)
  path <- url$path
  if (stringr::str_ends(path, "/")) {
    url$path <- glue::glue("{path}login")
  } else {
    url$path <- glue::glue("{path}/login")
  }
  httr2::url_build(url)
}
