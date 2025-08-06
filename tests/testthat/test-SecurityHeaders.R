test_that("SecurityHeaders initializes with default parameters", {
  sec_headers <- SecurityHeaders$new()
  expect_s3_class(sec_headers, "SecurityHeaders")
  expect_s3_class(sec_headers, "R6")
  expect_true(sec_headers$name == "security_headers")

  # Test that all default values are set correctly
  expect_type(sec_headers$content_security_policy, "list")
  expect_null(sec_headers$content_security_policy_report_only)
  expect_null(sec_headers$cross_origin_embedder_policy)
  expect_equal(sec_headers$cross_origin_opener_policy, "same-origin")
  expect_equal(sec_headers$cross_origin_resource_policy, "same-origin")
  expect_true(sec_headers$origin_agent_cluster)
  expect_equal(sec_headers$referrer_policy, "no-referrer")
  expect_type(sec_headers$strict_transport_security, "list")
  expect_true(sec_headers$x_content_type_options)
  expect_false(sec_headers$x_dns_prefetch_control)
  expect_true(sec_headers$x_download_options)
  expect_equal(sec_headers$x_frame_options, "SAMEORIGIN")
  expect_equal(sec_headers$x_permitted_cross_domain_policies, "none")
  expect_false(sec_headers$x_xss_protection)
})

test_that("SecurityHeaders initializes with custom parameters", {
  # Create custom CSP and STS values
  custom_csp <- csp(
    default_src = "none",
    script_src = c("self", "https://example.com"),
    style_src = "self"
  )

  custom_sts <- sts(
    max_age = 31536000,  # 1 year
    include_sub_domains = TRUE,
    preload = TRUE
  )

  # Initialize with custom values
  sec_headers <- SecurityHeaders$new(
    content_security_policy = custom_csp,
    cross_origin_embedder_policy = "require-corp",
    strict_transport_security = custom_sts,
    x_frame_options = "DENY",
    x_xss_protection = TRUE
  )

  # Verify custom values were set correctly
  # Note that validate_csp adds quotes to special keywords
  expect_equal(sec_headers$content_security_policy$default_src, "'none'")
  expect_equal(sec_headers$content_security_policy$script_src, c("'self'", "https://example.com"))
  expect_equal(sec_headers$content_security_policy$style_src, "'self'")
  expect_equal(sec_headers$cross_origin_embedder_policy, "require-corp")
  expect_equal(sec_headers$strict_transport_security, custom_sts)
  expect_equal(sec_headers$x_frame_options, "DENY")
  expect_true(sec_headers$x_xss_protection)
})

test_that("content_security_policy field validates input", {
  sec_headers <- SecurityHeaders$new()

  # Test valid CSP update
  valid_csp <- csp(default_src = "self", script_src = "none")
  expect_no_error(sec_headers$content_security_policy <- valid_csp)
  # Note that validate_csp adds quotes around special keywords
  expect_equal(sec_headers$content_security_policy$default_src, "'self'")
  expect_equal(sec_headers$content_security_policy$script_src, "'none'")

  # Test setting to NULL
  expect_no_error(sec_headers$content_security_policy <- NULL)
  expect_null(sec_headers$content_security_policy)
})

test_that("cross_origin_embedder_policy field validates input", {
  sec_headers <- SecurityHeaders$new()

  # Test valid values
  expect_no_error(sec_headers$cross_origin_embedder_policy <- "unsafe-none")
  expect_equal(sec_headers$cross_origin_embedder_policy, "unsafe-none")

  expect_no_error(sec_headers$cross_origin_embedder_policy <- "require-corp")
  expect_equal(sec_headers$cross_origin_embedder_policy, "require-corp")

  expect_no_error(sec_headers$cross_origin_embedder_policy <- "credentialless")
  expect_equal(sec_headers$cross_origin_embedder_policy, "credentialless")

  expect_no_error(sec_headers$cross_origin_embedder_policy <- NULL)
  expect_null(sec_headers$cross_origin_embedder_policy)

  # Test invalid value
  expect_snapshot(sec_headers$cross_origin_embedder_policy <- "invalid-value", error = TRUE)
})

test_that("cross_origin_opener_policy field validates input", {
  sec_headers <- SecurityHeaders$new()

  # Test valid values
  expect_no_error(sec_headers$cross_origin_opener_policy <- "unsafe-none")
  expect_equal(sec_headers$cross_origin_opener_policy, "unsafe-none")

  expect_no_error(sec_headers$cross_origin_opener_policy <- "same-origin-allow-popups")
  expect_equal(sec_headers$cross_origin_opener_policy, "same-origin-allow-popups")

  expect_no_error(sec_headers$cross_origin_opener_policy <- "same-origin")
  expect_equal(sec_headers$cross_origin_opener_policy, "same-origin")

  expect_no_error(sec_headers$cross_origin_opener_policy <- "noopener-allow-popups")
  expect_equal(sec_headers$cross_origin_opener_policy, "noopener-allow-popups")

  expect_no_error(sec_headers$cross_origin_opener_policy <- NULL)
  expect_null(sec_headers$cross_origin_opener_policy)

  # Test invalid value
  expect_snapshot(sec_headers$cross_origin_opener_policy <- "invalid-value", error = TRUE)
})

test_that("cross_origin_resource_policy field validates input", {
  sec_headers <- SecurityHeaders$new()

  # Test valid values
  expect_no_error(sec_headers$cross_origin_resource_policy <- "same-site")
  expect_equal(sec_headers$cross_origin_resource_policy, "same-site")

  expect_no_error(sec_headers$cross_origin_resource_policy <- "same-origin")
  expect_equal(sec_headers$cross_origin_resource_policy, "same-origin")

  expect_no_error(sec_headers$cross_origin_resource_policy <- "cross-origin")
  expect_equal(sec_headers$cross_origin_resource_policy, "cross-origin")

  expect_no_error(sec_headers$cross_origin_resource_policy <- NULL)
  expect_null(sec_headers$cross_origin_resource_policy)

  # Test invalid value
  expect_snapshot(sec_headers$cross_origin_resource_policy <- "invalid-value", error = TRUE)
})

test_that("strict_transport_security field validates input", {
  sec_headers <- SecurityHeaders$new()

  # Test valid STS values
  valid_sts <- sts(max_age = 63072000, include_sub_domains = TRUE)
  expect_no_error(sec_headers$strict_transport_security <- valid_sts)
  expect_equal(sec_headers$strict_transport_security, valid_sts)

  # Test STS with preload
  valid_sts_preload <- sts(
    max_age = 31536000, # 1 year minimum required for preload
    include_sub_domains = TRUE,
    preload = TRUE
  )
  expect_no_error(sec_headers$strict_transport_security <- valid_sts_preload)

  # Test invalid STS with preload (max_age too small)
  invalid_sts_preload <- list(
    max_age = 10000, # Too small for preload
    include_sub_domains = TRUE,
    preload = TRUE
  )
  expect_snapshot(sec_headers$strict_transport_security <- invalid_sts_preload, error = TRUE)

  # Test invalid STS with preload (include_sub_domains missing)
  invalid_sts_preload2 <- list(
    max_age = 31536000,
    include_sub_domains = FALSE,
    preload = TRUE
  )
  expect_snapshot(sec_headers$strict_transport_security <- invalid_sts_preload2, error = TRUE)

  # Test invalid STS structure
  expect_snapshot(sec_headers$strict_transport_security <- list(invalid = "value"), error = TRUE)
})

test_that("boolean fields validate input correctly", {
  sec_headers <- SecurityHeaders$new()

  # Test origin_agent_cluster
  expect_no_error(sec_headers$origin_agent_cluster <- FALSE)
  expect_false(sec_headers$origin_agent_cluster)

  expect_no_error(sec_headers$origin_agent_cluster <- TRUE)
  expect_true(sec_headers$origin_agent_cluster)

  expect_no_error(sec_headers$origin_agent_cluster <- NULL)
  expect_null(sec_headers$origin_agent_cluster)

  # Test x_content_type_options
  expect_no_error(sec_headers$x_content_type_options <- FALSE)
  expect_false(sec_headers$x_content_type_options)

  expect_no_error(sec_headers$x_content_type_options <- TRUE)
  expect_true(sec_headers$x_content_type_options)

  expect_no_error(sec_headers$x_content_type_options <- NULL)
  expect_null(sec_headers$x_content_type_options)

  # Test x_xss_protection
  expect_no_error(sec_headers$x_xss_protection <- TRUE)
  expect_true(sec_headers$x_xss_protection)

  expect_no_error(sec_headers$x_xss_protection <- FALSE)
  expect_false(sec_headers$x_xss_protection)

  expect_no_error(sec_headers$x_xss_protection <- NULL)
  expect_null(sec_headers$x_xss_protection)

  # Test invalid boolean value
  expect_snapshot(sec_headers$origin_agent_cluster <- "not-a-boolean", error = TRUE)
})

test_that("prepare_headers creates correct header values", {
  sec_headers <- SecurityHeaders$new()

  # We need to access the private method directly
  headers <- sec_headers$.__enclos_env__$private$prepare_headers()

  expect_type(headers, "list")
  expect_true("content-security-policy" %in% names(headers))
  expect_true("cross-origin-opener-policy" %in% names(headers))
  expect_true("cross-origin-resource-policy" %in% names(headers))
  expect_true("origin-agent-cluster" %in% names(headers))
  expect_true("referrer-policy" %in% names(headers))
  expect_true("strict-transport-security" %in% names(headers))
  expect_true("x-content-type-options" %in% names(headers))
  expect_true("x-dns-prefetch-control" %in% names(headers))
  expect_true("x-download-options" %in% names(headers))
  expect_true("x-frame-options" %in% names(headers))
  expect_true("x-permitted-cross-domain-policies" %in% names(headers))
  expect_true("x-xss-protection" %in% names(headers))

  # Check specific values
  expect_equal(headers[["cross-origin-opener-policy"]], "same-origin")
  expect_equal(headers[["cross-origin-resource-policy"]], "same-origin")
  expect_equal(headers[["origin-agent-cluster"]], "?1")
  expect_equal(headers[["referrer-policy"]], "no-referrer")
  expect_equal(headers[["x-content-type-options"]], "nosniff")
  expect_equal(headers[["x-dns-prefetch-control"]], "off")
  expect_equal(headers[["x-download-options"]], "noopen")
  expect_equal(headers[["x-frame-options"]], "SAMEORIGIN")
  expect_equal(headers[["x-permitted-cross-domain-policies"]], "none")
  expect_equal(headers[["x-xss-protection"]], "0")
})

test_that("SecurityHeaders integrates with fiery", {
  skip_if_not_installed("fiery")

  # Create a fiery app and SecurityHeaders plugin
  app <- fiery::Fire$new()
  sec_headers <- SecurityHeaders$new(
    strict_transport_security = NULL  # Disable STS to avoid protocol redirect setup
  )

  # Should not error
  expect_no_error(app$attach(sec_headers))

  # Check that headers were added to the app using the header() method
  # The header() method both sets and gets headers
  expect_true(!is.null(app$header("content-security-policy")))
  expect_true(!is.null(app$header("cross-origin-opener-policy")))
  expect_true(!is.null(app$header("cross-origin-resource-policy")))

  # Test with STS enabled
  app2 <- fiery::Fire$new()
  sec_headers2 <- SecurityHeaders$new()

  expect_no_error(app2$attach(sec_headers2))

  # Check that STS header was added and protocol upgrade route was created
  expect_true(!is.null(app2$header("strict-transport-security")))
  expect_true(!is.null(app2$plugins$header_routr))
})

test_that("SecurityHeaders handles CSP with reporting endpoints", {
  # Create CSP with reporting endpoint
  csp_with_report <- csp(
    default_src = "self",
    report_to = "https://example.com/reports"
  )

  sec_headers <- SecurityHeaders$new(
    content_security_policy = csp_with_report
  )

  # Access private prepare_headers method directly
  headers <- sec_headers$.__enclos_env__$private$prepare_headers()

  # Check that reporting-endpoints header was created
  expect_true("reporting-endpoints" %in% names(headers))
  expect_match(headers[["reporting-endpoints"]], "csp-endpoint=\"https://example.com/reports\"")

  # Check that report_to was translated to report_uri and endpoint name in CSP
  expect_match(headers[["content-security-policy"]], "report-to csp-endpoint")
  expect_match(headers[["content-security-policy"]], "report-uri https://example.com/reports")
})

test_that("SecurityHeaders handles multiple reporting endpoints", {
  # Create CSP and CSPRO with different reporting endpoints
  csp_with_report <- csp(
    default_src = "self",
    report_to = "https://example.com/reports"
  )

  cspro_with_report <- csp(
    default_src = "none",
    report_to = "https://example.com/report-only"
  )

  sec_headers <- SecurityHeaders$new(
    content_security_policy = csp_with_report,
    content_security_policy_report_only = cspro_with_report
  )

  # Access private prepare_headers method directly
  headers <- sec_headers$.__enclos_env__$private$prepare_headers()

  # Check that reporting-endpoints header has both endpoints
  expect_true("reporting-endpoints" %in% names(headers))
  expect_match(headers[["reporting-endpoints"]], "csp-endpoint=\"https://example.com/reports\"")
  expect_match(headers[["reporting-endpoints"]], "cspro-endpoint=\"https://example.com/report-only\"")
})
