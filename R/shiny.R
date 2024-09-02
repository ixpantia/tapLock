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
