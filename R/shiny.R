#' @keywords internal
rsso_server <- function(config, server_func) {
  function(input, output, session) {
    cookies <- parse_cookies(session$request$HTTP_COOKIE)

    if (is.null(cookies$access_token)) {
      stop("No access token")
    }

    token <- access_token(config, remove_bearer(cookies$access_token))

    if (is_expired(token)) {
      stop("Token expired")
    }

    session$userData$token <- token

    server_func(input, output, session)
  }
}

internal_add_auth_layers <- function(config, tower) {
  UseMethod("internal_add_auth_layers")
}

#' @export
add_auth_layers <- function(tower, config) {
  internal_add_auth_layers(config, tower)
}

#' @title Get the access token
#'
#' @description Gets the access token from the session to be used
#'   for internal logic.
#'
#' @param session A Shiny session
#'
#' @return An access_token object
#' @export
token <- function(session = shiny::getDefaultReactiveDomain()) {
  session$userData$token
}
