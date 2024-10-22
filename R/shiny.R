internal_add_auth_layers <- function(config, tower) {
  UseMethod("internal_add_auth_layers")
}

#' @title Add authentication middle ware to a 'tower' object
#' @description Attaches the necessary authentication layers
#'   to a 'tower' object. This will secure any layer added
#'   after.
#' @param tower A 'tower' object from the package 'tower'
#' @param config An 'openid_config' object
#' @return A modified 'tower' object with authentication layers
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
