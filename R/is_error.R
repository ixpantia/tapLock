is_error <- function(res) {
  methods::is(res, "error")
}

error <- function(msg) {
  structure(class = "error", list(value = msg))
}
