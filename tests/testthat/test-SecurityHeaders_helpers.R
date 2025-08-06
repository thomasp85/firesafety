test_that("validate_csp handles NULL input correctly", {
  # Should return NULL when input is NULL
  expect_null(validate_csp(NULL))
})

test_that("validate_csp validates input types", {
  # Invalid input types should error
  expect_snapshot(validate_csp("not a list"), error = TRUE)
  expect_snapshot(validate_csp(list(invalid_directive = "value")), error = TRUE)
})

test_that("validate_csp accepts valid CSP directives created with csp()", {
  # Simple valid CSP
  valid_csp <- csp(
    default_src = "self",
    script_src = c("self", "https://example.com"),
    style_src = c("self", "unsafe-inline")
  )

  result <- validate_csp(valid_csp)
  expect_type(result, "list")
  expect_equal(length(result), 3)
  expect_equal(result$default_src, "'self'")
  expect_equal(result$script_src, c("'self'", "https://example.com"))
  expect_equal(result$style_src, c("'self'", "'unsafe-inline'"))
})

test_that("validate_csp adds single quotes to special keywords", {
  # Test that special keywords get quoted correctly
  csp_with_keywords <- csp(
    script_src = c("self", "none", "unsafe-inline", "unsafe-eval", "https://example.com")
  )

  result <- validate_csp(csp_with_keywords)
  expect_equal(
    result$script_src,
    c("'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "https://example.com")
  )
})

test_that("validate_csp normalizes quoted values", {
  # Test that already quoted values are handled correctly
  csp_with_quotes <- csp(
    script_src = c("'self'", "self", "'none'", "none")
  )

  result <- validate_csp(csp_with_quotes)
  expect_equal(
    result$script_src,
    c("'self'", "'self'", "'none'", "'none'")
  )
})

test_that("validate_csp warns about inapplicable directives", {
  # unsafe-eval is not applicable to style_src
  expect_snapshot(
    validate_csp(csp(style_src = c("self", "unsafe-eval")))
  )

  # Check that the inapplicable value is removed
  result <- suppressWarnings(validate_csp(csp(style_src = c("self", "unsafe-eval"))))
  expect_equal(result$style_src, "'self'")
})

test_that("validate_csp warns about superseeded directives", {
  # strict-dynamic superseeds self and unsafe-inline in script_src
  expect_snapshot(
    validate_csp(csp(script_src = c("self", "unsafe-inline", "strict-dynamic")))
  )

  # Check that superseeded values are removed
  result <- suppressWarnings(
    validate_csp(csp(script_src = c("self", "unsafe-inline", "strict-dynamic")))
  )
  expect_equal(result$script_src, "'strict-dynamic'")
})

test_that("validate_csp handles nonce values", {
  # Test nonce values are properly handled
  nonce_csp <- csp(script_src = c("self", "nonce-abcdef123456"))

  result <- validate_csp(nonce_csp)
  expect_equal(result$script_src, c("'self'", "'nonce-abcdef123456'"))
})

test_that("validate_csp handles hash values", {
  # Test hash values are properly handled
  hash_csp <- csp(
    script_src = c(
      "self",
      "sha256-abcdef123456",
      "sha384-abcdef123456",
      "sha512-abcdef123456"
    )
  )

  result <- validate_csp(hash_csp)
  expect_equal(
    result$script_src,
    c("'self'", "'sha256-abcdef123456'", "'sha384-abcdef123456'", "'sha512-abcdef123456'")
  )
})

test_that("validate_csp handles empty elements", {
  # Test that empty elements are removed
  csp_with_empty <- csp(
    default_src = "self",
    script_src = character(0),
    style_src = NULL
  )

  result <- validate_csp(csp_with_empty)
  expect_equal(names(result), "default_src")
  expect_equal(result$default_src, "'self'")
})

test_that("validate_csp handles complex real-world examples", {
  # Test a more complex real-world CSP example
  complex_csp <- csp(
    default_src = "none",
    script_src = c("self", "strict-dynamic", "https://example.com"),
    style_src = c("self", "unsafe-inline"),
    img_src = c("self", "data:"),
    connect_src = "self",
    font_src = c("self", "https://fonts.gstatic.com"),
    frame_ancestors = "none",
    base_uri = "self",
    form_action = "self",
    upgrade_insecure_requests = TRUE
  )

  # We expect a warning about strict-dynamic superseeding self
  expect_snapshot(
    validate_csp(complex_csp)
  )

  # Check the result (suppressing the expected warning)
  result <- suppressWarnings(validate_csp(complex_csp))
  expect_equal(length(result), 10)
  expect_equal(result$default_src, "'none'")
  expect_equal(result$script_src, c("'strict-dynamic'"))
  expect_equal(result$frame_ancestors, "'none'")
  expect_equal(result$upgrade_insecure_requests, "")
})

test_that("validate_csp handles boolean flag directives", {
  # Test boolean flag directives like sandbox, require_trusted_types_for and upgrade_insecure_requests
  boolean_flags_csp <- csp(
    default_src = "self",
    sandbox = TRUE,
    require_trusted_types_for = TRUE,
    upgrade_insecure_requests = TRUE
  )

  expect_equal(boolean_flags_csp$sandbox, "")
  expect_equal(boolean_flags_csp$require_trusted_types_for, "")
  expect_equal(boolean_flags_csp$upgrade_insecure_requests, "")
})
