#' @title Create a new keycloak_config object
#' @description Creates a new keycloak_config object
#'
#' @param base_url The base URL for the Keycloak instance
#' @param realm The realm for the app
#' @param client_id The client ID for the app
#' @param client_secret The client secret for the app
#' @param app_url The URL for the app
#' @param use_refresh_token Enable the use of refresh tokens
#'
#' @return A keycloak_config object
#' @export
new_keycloak_config <- function(
  base_url,
  realm,
  client_id,
  client_secret,
  app_url,
  use_refresh_token = TRUE
) {
  runtime_result <- initialize_keycloak_runtime(
    client_id = client_id,
    client_secret = client_secret,
    app_url = app_url,
    base_url = base_url,
    realm = realm,
    use_refresh_token = use_refresh_token
  )
  if (is_error(runtime_result)) {
    rlang::abort(runtime_result$value)
  }
  return(runtime_result)
}
