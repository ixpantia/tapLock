test_that("Returns empty list for NULL input", {
  expect_equal(parse_cookies(NULL), list())
})

test_that("Returns empty list for empty string", {
  expect_equal(parse_cookies(""), list())
})

test_that("Parses simple cookies", {
  cookie <- "foo=bar; baz=quux"
  expected <- list(foo = "bar", baz = "quux")
  expect_equal(parse_cookies(cookie), expected)
})

test_that("Trims whitespace properly", {
  cookie <- " foo = bar ; baz = quux "
  expected <- list(foo = "bar", baz = "quux")
  expect_equal(parse_cookies(cookie), expected)
})

test_that("Ignores empty segments", {
  cookie <- "foo=bar; ; ; baz=quux;;"
  expected <- list(foo = "bar", baz = "quux")
  expect_equal(parse_cookies(cookie), expected)
})

test_that("Decodes URL-encoded values", {
  cookie <- "foo=bar%20baz"
  expected <- list(foo = "bar baz")
  expect_equal(parse_cookies(cookie), expected)
})

test_that("Ignores segments with empty key", {
  cookie <- "=value; foo=bar"
  expected <- list(foo = "bar")
  expect_equal(parse_cookies(cookie), expected)
})

test_that("Skips cookies with invalid URL encoding", {
  # This cookie has an invalid URL encoding for the value,
  # so it should be skipped entirely.
  cookie <- "foo=%E0%A4%A"
  expected <- list()
  # We need to do this for the check to work
  names(expected) <- character(0)
  expect_equal(parse_cookies(cookie), expected)
})

