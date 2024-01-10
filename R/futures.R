
#' @title Use futures for asynchronous computations
#' @description Enable a future plan for asynchronous computations.
#'   Since tapLock needs to do calls to external APIs, it can be a good idea
#'   to use future to make the calls asynchronous.
#'
#'   This function is just meant as a convenience function for the user.
#'   We recommend that you read the documentation for the future package
#'   to understand how to use it.
#' @param plan A plan object. Defaults to a multicore plan.
#' @param workers Number of workers to use. Defaults to 1.
#' @return This function is called for its side effect.
#' @export
use_futures <- function(plan = future::multicore, workers = 1) {
  future::plan(plan, workers = workers)
}
