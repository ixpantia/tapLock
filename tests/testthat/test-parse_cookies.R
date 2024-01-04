test_that("coorkie parsing works!", {
  EXAMPLE_COOKIE <- "foo=bar; baz=quux"
  EXPECTED_RESULT <- list(foo = "bar", baz = "quux")
  result <- parse_cookies(EXAMPLE_COOKIE)
  testthat::expect_equal(result, EXPECTED_RESULT)
})
