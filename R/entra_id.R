#' @title Create a new entra_id_config object
#' @description Creates a new entra_id_config object
#'
#' @param tenant_id The tenant ID for the app
#' @param client_id The client ID for the app
#' @param client_secret The client secret for the app
#' @param app_url The URL for the app
#' @param use_refresh_token Enable the use of refresh tokens
#'
#' @return An entra_id_config object
#' @export
new_entra_id_config <- function(tenant_id, client_id, client_secret, app_url, use_refresh_token = TRUE) {
  runtime_result <- initialize_entra_id_runtime(
    client_id = client_id,
    client_secret = client_secret,
    tenant_id = tenant_id,
    app_url = app_url,
    use_refresh_token = use_refresh_token
  )
  if (is_error(runtime_result)) {
    rlang::abort(runtime_result$value)
  }
  return(runtime_result)
}
