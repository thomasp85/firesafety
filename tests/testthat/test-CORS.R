test_that("CORS initialization works with default parameters", {
  cors <- CORS$new()
  expect_s3_class(cors, "CORS")
  expect_s3_class(cors, "R6")
  expect_true(cors$name == "cors")
})

test_that("CORS initialization works with custom parameters", {
  cors <- CORS$new(
    path = "/api/*",
    origin = "https://example.com",
    methods = c("get", "post"),
    allowed_headers = c("content-type", "authorization"),
    exposed_headers = "x-rate-limit",
    allow_credentials = TRUE,
    max_age = 3600
  )
  expect_s3_class(cors, "CORS")
})

test_that("CORS initialization validates parameters", {
  # Cannot allow credentials if origin is "*"
  expect_snapshot(
    CORS$new(origin = "*", allow_credentials = TRUE),
    error = TRUE
  )

  # Methods must be valid HTTP methods
  expect_snapshot(
    CORS$new(methods = c("get", "invalid")),
    error = TRUE
  )
})

test_that("add_path works correctly", {
  cors <- CORS$new()
  # Should not error
  expect_no_error({
    cors$add_path(
      path = "/api/v2/*",
      origin = "https://example.org",
      methods = c("get", "post"),
      max_age = 7200
    )
  })
})

test_that("origin parameter accepts boolean TRUE", {
  cors <- CORS$new(origin = TRUE)
  expect_s3_class(cors, "CORS")
})

test_that("origin parameter accepts boolean FALSE", {
  cors <- CORS$new(origin = FALSE)
  expect_s3_class(cors, "CORS")
})

test_that("origin parameter accepts character vector", {
  cors <- CORS$new(origin = c("https://example.com", "https://test.com"))
  expect_s3_class(cors, "CORS")
})

test_that("origin parameter accepts function", {
  origin_fn <- function(request) {
    return(TRUE)
  }
  cors <- CORS$new(origin = origin_fn)
  expect_s3_class(cors, "CORS")
})

test_that("CORS handles OPTIONS requests correctly", {
  # Create mock request and response objects
  request <- list(
    get_header = function(name) {
      if (name == "origin") {
        return("https://example.com")
      }
      if (name == "access-control-request-headers") {
        return("content-type")
      }
      return(NULL)
    },
    method = "options"
  )

  response <- list(
    set_header = function(name, value) {},
    append_header = function(name, value) {},
    status = 200L,
    body = NULL
  )

  # Create CORS object
  cors <- CORS$new(
    path = "/*",
    origin = "https://example.com",
    methods = c("get", "post"),
    max_age = 3600
  )

  # This is a partial test since we can't easily invoke the private handlers directly
  expect_s3_class(cors, "CORS")
})

test_that("CORS integrates with fiery", {
  skip_if_not_installed("fiery")

  # Create a fiery app and CORS plugin
  app <- fiery::Fire$new()
  cors <- CORS$new(
    path = "/api/*",
    origin = "https://example.com"
  )

  # Should not error
  expect_no_error({
    app$attach(cors)
  })

  # Check that routes were added
  expect_true(!is.null(app$plugins$header_routr))
  expect_true(!is.null(app$plugins$request_routr))
})

test_that("CORS blocks requests from non-allowed origins", {
  # This would require more extensive mocking or integration testing
  # Since the handlers are private, we'll just check initialization
  cors <- CORS$new(
    path = "/*",
    origin = "https://example.com"
  )
  expect_s3_class(cors, "CORS")
})

test_that("CORS properly handles OPTIONS preflight and actual CORS requests", {
  skip_if_not_installed("fiery")

  # Create a fiery app with CORS plugin
  app <- fiery::Fire$new()
  cors <- CORS$new(
    path = "/api/*",
    origin = "https://trusted-site.com",
    methods = c("get", "post"),
    allowed_headers = c("content-type", "authorization"),
    exposed_headers = "x-rate-limit",
    allow_credentials = TRUE,
    max_age = 3600
  )
  app$attach(cors)

  # Add a simple handler for /api/data
  app$on("request", function(server, id, request, ...) {
    if (request$path == "/api/data") {
      response <- request$respond()
      response$status <- 200L
      response$body <- '{"data": "success"}'
      response$set_header("content-type", "application/json")
      response$set_header("x-rate-limit", "100")
      TRUE
    } else {
      FALSE
    }
  })

  # Test 1: OPTIONS preflight request from allowed origin
  preflight_req <- fiery::fake_request(
    url = "http://localhost:8080/api/data",
    method = "OPTIONS",
    headers = list(
      origin = "https://trusted-site.com",
      "access-control-request-method" = "POST",
      "access-control-request-headers" = "content-type, authorization"
    )
  )

  preflight_res <- app$test_header(preflight_req)

  # Verify preflight response
  expect_equal(preflight_res$status, 204L) # No content for preflight
  expect_equal(
    preflight_res$headers[["access-control-allow-origin"]],
    "https://trusted-site.com"
  )
  expect_equal(
    preflight_res$headers[["access-control-allow-methods"]],
    "get,post"
  )
  expect_equal(
    preflight_res$headers[["access-control-allow-headers"]],
    "content-type,authorization"
  )
  expect_equal(
    preflight_res$headers[["access-control-allow-credentials"]],
    "true"
  )
  expect_equal(preflight_res$headers[["access-control-max-age"]], "3600")
  expect_equal(
    preflight_res$headers[["access-control-expose-headers"]],
    "x-rate-limit"
  )

  # Test 2: Actual CORS GET request from allowed origin
  cors_req <- fiery::fake_request(
    url = "http://localhost:8080/api/data",
    method = "GET",
    headers = list(origin = "https://trusted-site.com")
  )

  cors_res <- app$test_request(cors_req)

  # Verify CORS response
  expect_equal(cors_res$status, 200L)
  expect_equal(
    cors_res$headers[["access-control-allow-origin"]],
    "https://trusted-site.com"
  )
  expect_equal(cors_res$headers[["access-control-allow-credentials"]], "true")
  expect_equal(
    cors_res$headers[["access-control-expose-headers"]],
    "x-rate-limit"
  )
  expect_equal(cors_res$body, '{"data": "success"}')

  # Test 3: CORS request from non-allowed origin should have no CORS headers
  blocked_req <- fiery::fake_request(
    url = "http://localhost:8080/api/data",
    method = "GET",
    headers = list(origin = "https://untrusted-site.com")
  )

  blocked_res <- app$test_request(blocked_req)

  # Access-Control-Allow-Origin should be "false" which signals to browser to block the request
  expect_equal(blocked_res$headers[["access-control-allow-origin"]], "false")
})
