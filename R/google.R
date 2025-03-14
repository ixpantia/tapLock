#' @title Create a new google_config object
#' @description Creates a new google_config object
#'
#' @param client_id The client ID for the app
#' @param client_secret The client secret for the app
#' @param app_url The URL for the app
#'
#' @return A google_config object
#' @export
new_google_config <- function(client_id, client_secret, app_url, use_refresh_token = TRUE) {
  initialize_google_runtime(client_id, client_secret, app_url, use_refresh_token)
}
