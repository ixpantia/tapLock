#' @export
access_token <- R6::R6Class(
  classname = "entra_id_token",
  public = list(
    initialize = function(token, config, refresh_token = NULL) {
      private$access_token <- token
      private$refresh_token <- refresh_token
      token <- config$decode_token(token)
      private$exp <- lubridate::as_datetime(token$exp)
      private$iat <- lubridate::as_datetime(token$iat)
      private$nbf <- lubridate::as_datetime(token$nbf)
      private$name <- token$name
      private$given_name <- token$given_name
      private$family_name <- token$family_name
      private$unique_name <- token$unique_name
      private$aud <- token$aud
    },
    is_valid = function() {
      !self$is_expired()
    },
    is_expired = function() {
      Sys.time() > private$exp
    },
    get_bearer = function() {
      paste0("Bearer ", private$access_token)
    },
    get_access_token = function() {
      private$access_token
    },
    get_refresh_token = function() {
      private$refresh_token
    },
    get_audience = function() {
      private$aud
    },
    expires_in = function() {
      private$exp - Sys.time()
    },
    expires_at = function() {
      private$exp
    },
    get_name = function() {
      private$name
    },
    get_given_name = function() {
      private$given_name
    },
    get_family_name = function() {
      private$family_name
    },
    get_unique_name = function() {
      private$unique_name
    }
  ),
  private = list(
    access_token = NULL,
    refresh_token = NULL,
    exp = NULL,
    iat = NULL,
    nbf = NULL,
    name = NULL,
    given_name = NULL,
    family_name = NULL,
    unique_name = NULL,
    aud = NULL
  )
)
