test_that("ResourceIsolation initialization works with default parameters", {
  ri <- ResourceIsolation$new()
  expect_s3_class(ri, "ResourceIsolation")
  expect_s3_class(ri, "R6")
  expect_true(ri$name == "resource_isolation")
})

test_that("ResourceIsolation initialization works with custom parameters", {
  ri <- ResourceIsolation$new(
    path = "/api/*",
    allowed_site = "same-origin",
    forbidden_navigation = "all",
    allow_cors = FALSE
  )
  expect_s3_class(ri, "ResourceIsolation")
})

test_that("ResourceIsolation validates allowed_site parameter", {
  # allowed_site must be one of the valid options
  expect_snapshot(
    ResourceIsolation$new(allowed_site = "invalid"),
    error = TRUE
  )
})

test_that("ResourceIsolation validates forbidden_navigation parameter", {
  # forbidden_navigation must be valid destinations or 'all'
  expect_snapshot(
    ResourceIsolation$new(forbidden_navigation = "invalid"),
    error = TRUE
  )

  # 'all' is a valid special value
  expect_no_error(
    ResourceIsolation$new(forbidden_navigation = "all")
  )
})

test_that("add_path works correctly", {
  ri <- ResourceIsolation$new()

  # Should not error
  expect_no_error({
    ri$add_path(
      path = "/api/v2/*",
      allowed_site = "cross-site",
      forbidden_navigation = c("object", "embed", "iframe"),
      allow_cors = TRUE
    )
  })
})

test_that("add_path validates parameters", {
  ri <- ResourceIsolation$new()

  # allowed_site must be valid
  expect_snapshot(
    ri$add_path(path = "/api/*", allowed_site = "invalid"),
    error = TRUE
  )

  # forbidden_navigation must be valid
  expect_snapshot(
    ri$add_path(path = "/api/*", allowed_site = "same-site", forbidden_navigation = "invalid"),
    error = TRUE
  )
})

test_that("allow_request function handles missing sec-fetch headers", {
  # Create a mock request without sec-fetch headers
  request <- list(
    has_header = function(name) { return(FALSE) },
    get_header = function(name) { return(NULL) },
    method = "get"
  )

  # Request without sec-fetch headers should be allowed
  expect_true(allow_request(request, c("same-site"), c("object"), TRUE))
})

test_that("allow_request function handles CORS requests", {
  # Create a mock request for CORS
  request <- list(
    has_header = function(name) { return(TRUE) },
    get_header = function(name) {
      if (name == "sec-fetch-mode") return("cors")
      if (name == "sec-fetch-site") return("cross-site")
      return(NULL)
    },
    method = "get"
  )

  # CORS request should be allowed when allow_cors = TRUE
  expect_true(allow_request(request, c("same-site"), c("object"), TRUE))

  # CORS request should be blocked when allow_cors = FALSE
  expect_false(allow_request(request, c("same-site"), c("object"), FALSE))
})

test_that("allow_request function handles site restrictions", {
  # Create mock requests with different sec-fetch-site values
  same_origin_request <- list(
    has_header = function(name) { return(TRUE) },
    get_header = function(name) {
      if (name == "sec-fetch-mode") return("no-cors")
      if (name == "sec-fetch-site") return("same-origin")
      return(NULL)
    },
    method = "get"
  )

  same_site_request <- list(
    has_header = function(name) { return(TRUE) },
    get_header = function(name) {
      if (name == "sec-fetch-mode") return("no-cors")
      if (name == "sec-fetch-site") return("same-site")
      return(NULL)
    },
    method = "get"
  )

  cross_site_request <- list(
    has_header = function(name) { return(TRUE) },
    get_header = function(name) {
      if (name == "sec-fetch-mode") return("no-cors")
      if (name == "sec-fetch-site") return("cross-site")
      return(NULL)
    },
    method = "get"
  )

  # Test with same-origin restriction
  expect_true(allow_request(same_origin_request, c("same-origin", "none"), c("object"), FALSE))
  expect_false(allow_request(same_site_request, c("same-origin", "none"), c("object"), FALSE))
  expect_false(allow_request(cross_site_request, c("same-origin", "none"), c("object"), FALSE))

  # Test with same-site restriction
  expect_true(allow_request(same_origin_request, c("same-site", "same-origin", "none"), c("object"), FALSE))
  expect_true(allow_request(same_site_request, c("same-site", "same-origin", "none"), c("object"), FALSE))
  expect_false(allow_request(cross_site_request, c("same-site", "same-origin", "none"), c("object"), FALSE))

  # Test with cross-site (permissive) restriction
  expect_true(allow_request(same_origin_request, c("cross-site", "same-site", "same-origin", "none"), c("object"), FALSE))
  expect_true(allow_request(same_site_request, c("cross-site", "same-site", "same-origin", "none"), c("object"), FALSE))
  expect_true(allow_request(cross_site_request, c("cross-site", "same-site", "same-origin", "none"), c("object"), FALSE))
})

test_that("allow_request function handles navigation requests", {
  # Create mock navigation requests with different sec-fetch-dest values
  nav_request_document <- list(
    has_header = function(name) { return(TRUE) },
    get_header = function(name) {
      if (name == "sec-fetch-mode") return("navigate")
      if (name == "sec-fetch-site") return("cross-site")
      if (name == "sec-fetch-dest") return("document")
      return(NULL)
    },
    method = "get"
  )

  nav_request_object <- list(
    has_header = function(name) { return(TRUE) },
    get_header = function(name) {
      if (name == "sec-fetch-mode") return("navigate")
      if (name == "sec-fetch-site") return("cross-site")
      if (name == "sec-fetch-dest") return("object")
      return(NULL)
    },
    method = "get"
  )

  # Test allowing document navigation but forbidding object navigation
  expect_true(allow_request(nav_request_document, c("same-origin", "none"), c("object", "embed"), FALSE))
  expect_false(allow_request(nav_request_object, c("same-origin", "none"), c("object", "embed"), FALSE))
})

test_that("ResourceIsolation integrates with fiery", {
  skip_if_not_installed("fiery")

  # Create a fiery app and ResourceIsolation plugin
  app <- fiery::Fire$new()
  ri <- ResourceIsolation$new(
    path = "/api/*",
    allowed_site = "same-site"
  )

  # Should not error
  expect_no_error({
    app$attach(ri)
  })

  # Check that routes were added
  expect_true(!is.null(app$plugins$header_routr))
})

test_that("ResourceIsolation properly blocks or allows requests based on Sec-Fetch headers", {
  skip_if_not_installed("fiery")

  # Create a fiery app with ResourceIsolation plugin
  app <- fiery::Fire$new()
  ri <- ResourceIsolation$new(
    path = "/api/*",
    allowed_site = "same-site",
    forbidden_navigation = c("iframe", "object", "embed"),
    allow_cors = TRUE
  )
  app$attach(ri)

  # Add less restrictive policy for public resources
  ri$add_path(
    path = "/public/*",
    allowed_site = "cross-site"
  )

  # Add more restrictive policy for sensitive resources
  ri$add_path(
    path = "/admin/*",
    allowed_site = "same-origin",
    forbidden_navigation = "all",
    allow_cors = FALSE
  )

  # Add a simple handler for content paths
  app$on("request", function(server, id, request, ...) {
    # Only handle requests that pass resource isolation
    response <- request$respond()
    response$status <- 200L
    response$body <- '{"result": "success"}'
    response$set_header("content-type", "application/json")
    TRUE
  })

  # Test 1: Request with no Sec-Fetch headers should be allowed (browsers without support)
  basic_req <- fiery::fake_request(
    url = "http://localhost:8080/api/data",
    method = "GET",
    headers = list()
  )

  basic_res <- app$test_header(basic_req)
  expect_null(basic_res)

  # Test 2: Same-site request to /api/* should be allowed
  same_site_req <- fiery::fake_request(
    url = "http://localhost:8080/api/data",
    method = "GET",
    headers = list(
      "sec-fetch-site" = "same-site",
      "sec-fetch-mode" = "no-cors",
      "sec-fetch-dest" = "image"
    )
  )

  same_site_res <- app$test_header(same_site_req)
  expect_null(same_site_res)

  # Test 3: Cross-site request to /api/* should be blocked
  cross_site_req <- fiery::fake_request(
    url = "http://localhost:8080/api/data",
    method = "GET",
    headers = list(
      "sec-fetch-site" = "cross-site",
      "sec-fetch-mode" = "no-cors",
      "sec-fetch-dest" = "image"
    )
  )

  cross_site_res <- app$test_header(cross_site_req)
  expect_equal(cross_site_res$status, 403L)

  # Test 4: CORS request to /api/* should be allowed because allow_cors = TRUE
  cors_req <- fiery::fake_request(
    url = "http://localhost:8080/api/data",
    method = "GET",
    headers = list(
      "sec-fetch-site" = "cross-site",
      "sec-fetch-mode" = "cors",
      "sec-fetch-dest" = "empty"
    )
  )

  cors_res <- app$test_header(cors_req)
  expect_null(cors_res)

  # Test 5: Navigation to iframe (forbidden) should be blocked
  iframe_req <- fiery::fake_request(
    url = "http://localhost:8080/api/data",
    method = "GET",
    headers = list(
      "sec-fetch-site" = "cross-site",
      "sec-fetch-mode" = "navigate",
      "sec-fetch-dest" = "iframe"
    )
  )

  iframe_res <- app$test_header(iframe_req)
  expect_equal(iframe_res$status, 403L)

  # Test 6: Navigation to document should be allowed (not forbidden)
  nav_req <- fiery::fake_request(
    url = "http://localhost:8080/api/data",
    method = "GET",
    headers = list(
      "sec-fetch-site" = "cross-site",
      "sec-fetch-mode" = "navigate",
      "sec-fetch-dest" = "document"
    )
  )

  nav_res <- app$test_header(nav_req)
  expect_null(nav_res)

  # Test 7: Cross-site request to /public/* should be allowed (less restrictive)
  public_req <- fiery::fake_request(
    url = "http://localhost:8080/public/file.js",
    method = "GET",
    headers = list(
      "sec-fetch-site" = "cross-site",
      "sec-fetch-mode" = "no-cors",
      "sec-fetch-dest" = "script"
    )
  )

  public_res <- app$test_header(public_req)
  expect_null(public_res)

  # Test 8: CORS request to /admin/* should be blocked because allow_cors = FALSE
  admin_cors_req <- fiery::fake_request(
    url = "http://localhost:8080/admin/users",
    method = "GET",
    headers = list(
      "sec-fetch-site" = "cross-site",
      "sec-fetch-mode" = "cors",
      "sec-fetch-dest" = "empty"
    )
  )

  admin_cors_res <- app$test_header(admin_cors_req)
  expect_equal(admin_cors_res$status, 403L)

  # Test 9: Same-site (but not same-origin) request to /admin/* should be blocked
  admin_samesite_req <- fiery::fake_request(
    url = "http://localhost:8080/admin/users",
    method = "GET",
    headers = list(
      "sec-fetch-site" = "same-site",
      "sec-fetch-mode" = "no-cors",
      "sec-fetch-dest" = "empty"
    )
  )

  admin_samesite_res <- app$test_header(admin_samesite_req)
  expect_equal(admin_samesite_res$status, 403L)

  # Test 10: Same-origin request to /admin/* should be allowed
  admin_sameorigin_req <- fiery::fake_request(
    url = "http://localhost:8080/admin/users",
    method = "GET",
    headers = list(
      "sec-fetch-site" = "same-origin",
      "sec-fetch-mode" = "no-cors",
      "sec-fetch-dest" = "empty"
    )
  )

  admin_sameorigin_res <- app$test_header(admin_sameorigin_req)
  expect_null(admin_sameorigin_res)
})
