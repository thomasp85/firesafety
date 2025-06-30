#' Plugin for setting security related headers
#'
#' @description
#' This plugin is inspired by [Helmet.js](https://helmetjs.github.io/) and aids
#' you in setting response headers relevant for security of your fiery server.
#' All defaults are taken from Helmet.js as well except for the max-age of the
#' `Strict-Transport-Security` header which has been doubled to 2 years which is
#' the recommendation.
#'
#' @details
#' Web security is a complicated subject and it is impossible for this document
#' to stay current and true at all times as well as be able to learn the user of
#' all the intricacies of web security. It is **strongly** advised that you
#' familiarise yourself with this subject if you plan on exposing a fiery
#' webserver to the public. A good starting point is
#' [MDN's guide on web security](https://developer.mozilla.org/docs/Web/Security).
#'
#' This plugin concerns 14 different headers that are in one way or another
#' implicated in security. Some of them are only relevant if you serve HTML
#' content on the web and have no effect on e.g. a server providing a REST api.
#' These have been marked with **UI** below
#' In that case they can be turned off (by setting them to `NULL`). However, it
#' is advised that you only steer away from the defaults if you have a good
#' grasp of the implications. The headers are set very efficiently so removing
#' some unneeded ones will only have an effect on the size of the response, not
#' the handling time.
#'
#' ## Headers
#' ### `Content-Security-Policy` (**UI**)
#' This header provides finely grained control over what code can be executed on
#' the site you provide and thus help in preventing cross-site scripting (XSS)
#' attacks. The configuration of this header is complicated and you can read
#' more about it at [the header reference](https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/Content-Security-Policy)
#' and [the CSP section of the security guide](https://developer.mozilla.org/docs/Web/Security/Practical_implementation_guides/CSP)
#'
#' The plugin does some light validation of the data structure you provide and
#' you can use the [csp()] constructure to get argument tab-completion.
#'
#' ### `Content-Security-Policy-Report-Only` (**UI**)
#' This header is like `Content-Security-Policy` above except that it doesn't
#' enforce the policy but rather report any violations to a URL of your choice.
#' The reason for providing this is that setting up CSP correctly can be
#' difficult and may lead to your site not working correctly. Therefore, if you
#' apply CSP to an already excisting site it is often a good idea to start with
#' using this header and monitor where issues may arise before turning on the
#' policy fully. You provide the URL to send violation reports to with the
#' `report_to` directive which should be set to a URL. You can find more
#' information on this header at
#' [the header reference](https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/Content-Security-Policy-Report-Only)
#'
#' ### `Cross-Origin-Embedder-Policy` (**UI**)
#' This header controls which ressources can be embedded in a document. If set
#' to e.g. `require-corp` then only ressources that implements CORP or CORS can
#' be embedded. It is not set by default in Headgear. Read more about this
#' header at [MDN](https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy)
#'
#' ### `Cross-Origin-Opener-Policy` (**UI**)
#' This header controls and restricts access from cross-origin windows opened
#' from the site. It helps isolate new documents and prevent a type of attack known
#' as XS-Leaks. Read more about this header at [MDN](https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy)
#' and about XS-Leaks [in the security guide](https://developer.mozilla.org/docs/Web/Security/Attacks/XS-Leaks)
#'
#' ### `Cross-Origin-Ressource-Policy`
#' This header controls where the given response can be used. If you e.g. return
#' an image along with `Cross-Origin-Ressource-Policy: same-site`, then this
#' image is blocked from being loaded by other sites.
#' Read more about this header at [MDN](https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/Cross-Origin-Ressource-Policy)
#' and about CORP in general [in the security guide](https://developer.mozilla.org/docs/Web/Security/Practical_implementation_guides/CORP)
#'
#' ### `Origin-Agent-Cluster` (**UI**)
#' This header helps isolate documents served from the same site into separate
#' processes. This can improve performance of other tabs if a ressource
#' intensive tab is opened but also prevent certain information from being
#' available to code running in the tab. Read more about this header at
#' [MDN](https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/Origin-Agent-Cluster)
#'
#' ### `Referrer-Policy` (**UI**)
#' This header instructs what to include in the `Referer` header when navigating
#' away from the document. This can potentially lead to information leakage
#' which can be alleviated using this header. Read more about this header at
#' [MDN](https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
#' as well as the [security implications of the `Referer` header](https://developer.mozilla.org/docs/Web/Security/Referer_header:_privacy_and_security_concerns)
#'
#' ### `Strict-Transport-Security`
#' This header informs a browser that the given ressource should only be
#' accessed using HTTPS. This preference is cached by the browser and the next
#' time the ressource is accessed over HTTP it is automatically changed to HTTPS
#' before the request is made. This header should only be sent over HTTPS to
#' prevent a manipulator-in-the-middle from alterning its settings. In order for
#' this to happen Headgear will automatically redirect any HTTP requests to
#' HTTPS if this header is set. Read more about this header at
#' [MDN](https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security)
#'
#' ### `X-Content-Type-Options`
#' This header instruct the client that the MIME type provided by the
#' `Content-Type` should be respected and mime-type sniffing avoided. Setting
#' this can help prevent certain XSS attacks. Read more about this header at
#' [MDN](https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options)
#' and about its security implication in the
#' [security guide](https://developer.mozilla.org/docs/Web/Security/Practical_implementation_guides/MIME_types)
#'
#' ### `X-DNS-Prefetch-Control` (**UI**)
#' This header controls DNS prefetching and domain name resolution. A browser
#' may do this in the background when a site is loaded which can reduce latency
#' when a user clicks a link. However, it may also leak sensitive information so
#' turning it off may increase user privacy. Read more about this header at
#' [MDN](https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/X-DNS-Prefetch-Control)
#'
#' ### `X-Download-Options` (**UI**)
#' This is an old header only relevant to Internet Explorer 8 and below that
#' prevents downloaded content from having access to your site's context.
#'
#' ### `X-Frame-Options` (**UI**)
#' This header has been superseeded by the `frame-ancestor` directive in the
#' `Content-Security-Policy` header but may still be good to set for older
#' browsers. It controls whether a site is allowed to be rendered inside a frame
#' in another document. Preventing this can prevent click-jacking attacks. Read
#' more about this header at [MDN](https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/X-Frame-Options)
#'
#' ### `X-Permitted-Cross-Domain-Policies`
#' This header controls cross-origin access of a ressource from a document
#' running in a web client such as Adobe Flash Player or Microsoft Silverlight.
#' The demise of these technologies have made this header less important. Read
#' more about this header at [MDN](https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/X-Permitted-Cross-Domain-Policies)
#'
#' ### `X-XSS-Protection` (**UI**)
#' This header has been deprecated in favor of the more powerful
#' `Content-Security-Policy` header. In fact using XSS filtering can incur a
#' security vulnerability which is why the default for Headgear is to turn the
#' feature off (by setting `X-XSS-Protection: 0` rather than omitting the
#' header). Read more about this header at
#' [MDN](https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/X-XSS-Protection)
#'
#' @usage NULL
#' @format NULL
#'
#' @section Initialization:
#' A new 'Headgear'-object is initialized using the \code{new()} method on the
#' generator and pass in any settings deviating from the defaults
#'
#' \strong{Usage}
#' \tabular{l}{
#'  \code{headgear <- Headgear$new(...)}
#' }
#'
#' @section Fiery plugin:
#' A Headgear object is a fiery plugin and can be used by passing it to the
#' `attach()` method of the fiery server object. Once attached all requests
#' created will be prepopulated with the given headers. Any request handler is
#' permitted to remove one or more of the headers to opt out of them.
#'
#' @export
#'
#' @examplesIf requireNamespace("fiery", quietly = TRUE)
#' # Create a plugin that turns off UI-related security headers
#' headgear <- Headgear$public_methods$initialize(
#'   content_security_policy = NULL,
#'   cross_origin_embedder_policy = NULL,
#'   cross_origin_opener_policy = NULL,
#'   origin_agent_cluster = NULL,
#'   referrer_policy = NULL,
#'   x_dns_prefetch_control = NULL,
#'   x_download_options = NULL,
#'   x_frame_options = NULL,
#'   x_xss_protection = NULL
#' )
#'
#' # Use it with a fiery server
#' app <- fiery::Fire$new()
#'
#' app$attach(headgear)
#'
Headgear <- R6::R6Class(
  "Headgear",
  public = list(
    #' @description Initialize a new Headgear object
    #' @param content_security_policy Set the value of the `Content-Security-Policy`
    #' header. See [csp()] for documentation of its values
    #' @param content_security_policy_report_only Set the value of the
    #' `Content-Security-Policy-Report-Only` header. See [csp()] for
    #' documentation of its values
    #' @param cross_origin_embedder_policy Set the value of the
    #' `Cross-Origin-Embedder-Policy`. Possible values are `"unsafe-none"`,
    #' `"require-corp"`, and `"credentialless"`
    #' @param cross_origin_opener_policy Set the value of the
    #' `Cross-Origin-Opener-Policy`. Possible values are `"unsafe-none"`,
    #' `"same-origin-allow-popups"`, `"same-origin"`, and
    #' `"noopener-allow-popups"`
    #' @param cross_origin_resource_policy Set the value of the
    #' `Cross-Origin-Resource-Policy`. Possible values are `"same-site"`,
    #' `"same-origin"`, and `"cross-origin"`
    #' @param origin_agent_cluster Set the value of the
    #' `Origin-Agent-Cluster`. Possible values are `TRUE` and `FALSE`
    #' @param referrer_policy Set the value of the
    #' `Referrer-Policy`. Possible values are `"no-referrer"`,
    #' `"no-referrer-when-downgrade"`, `"origin"`, `"origin-when-cross-origin"`,
    #' `"same-origin"`, `"strict-origin"`, `"strict-origin-when-cross-origin"`,
    #' and `"unsafe-url"`
    #' @param strict_transport_security Set the value of the
    #' `Strict-Transport-Security` header. See [sts()] for documentation of its
    #' values
    #' @param x_content_type_options Set the value of the
    #' `X-Content-Type-Options`. Possible values are `TRUE` and `FALSE`
    #' @param x_dns_prefetch_control Set the value of the
    #' `X-DNS-Prefetch-Control`. Possible values are `TRUE` and `FALSE`
    #' @param x_download_options Set the value of the
    #' `X-Download-Options`. Possible values are `TRUE` and `FALSE`
    #' @param x_frame_options Set the value of the
    #' `X-Frame-Options`. Possible values are `"DENY"` and `"SAMEORIGIN"`
    #' @param x_permitted_cross_domain_policies Set the value of the
    #' `X-Permitted-Cross-Domain-Policies`. Possible values are `"none"`,
    #' `"master-only"`, `"by-content-type"`, `"by-ftp-filename"`, `"all"`, and
    #' `"none-this-response"`
    #' @param x_xss_protection Set the value of the
    #' `X-XSS-Protection`. Possible values are `TRUE` and `FALSE`
    #'
    initialize = function(
      content_security_policy = csp(
        default = "self",
        script = "self",
        script_attr = "none",
        style = c("self", "https:", "unsafe-inline"),
        img = c("self", "data:"),
        font = c("self", "https:", "data:"),
        object = "none",
        base_uri = "self",
        form_action = "self",
        frame_ancestor = "self",
        upgrade_insecure_requests = TRUE
      ),
      content_security_policy_report_only = NULL,
      cross_origin_embedder_policy = NULL,
      cross_origin_opener_policy = "same-origin",
      cross_origin_resource_policy = "same-origin",
      origin_agent_cluster = TRUE,
      referrer_policy = "no-referrer",
      strict_transport_security = sts(
        max_age = 63072000,
        include_sub_domains = TRUE
      ),
      x_content_type_options = TRUE,
      x_dns_prefetch_control = FALSE,
      x_download_options = TRUE,
      x_frame_options = "SAMEORIGIN",
      x_permitted_cross_domain_policies = "none",
      x_xss_protection = FALSE
    ) {
      self$content_security_policy <- content_security_policy
      self$content_security_policy_report_only <- content_security_policy_report_only
      self$cross_origin_embedder_policy <- cross_origin_embedder_policy
      self$cross_origin_opener_policy <- cross_origin_opener_policy
      self$cross_origin_resource_policy <- cross_origin_resource_policy
      self$origin_agent_cluster <- origin_agent_cluster
      self$referrer_policy <- referrer_policy
      self$strict_transport_security <- strict_transport_security
      self$x_content_type_options <- x_content_type_options
      self$x_dns_prefetch_control <- x_dns_prefetch_control
      self$x_download_options <- x_download_options
      self$x_frame_options <- x_frame_options
      self$x_permitted_cross_domain_policies <- x_permitted_cross_domain_policies
      self$x_xss_protection <- x_xss_protection
    },
    #' @description Method for use by `fiery` when attached as a plugin. Should
    #' not be called directly.
    #' @param app The fiery server object
    #' @param ... Ignored
    #'
    on_attach = function(app, ...) {
      headers <- private$prepare_headers()
      must_upgrade <- !is.null(self$strict_transport_security)

      for (header in names(headers)) {
        if (header == "reporting-endpoints") {
          app$header(header, headers[[header]])
        }
        app$header(header, headers[[header]])
      }

      if (must_upgrade) {
        if (is.null(app$plugins$header_routr)) {
          rs <- routr::RouteStack()
          rs$attach_to <- "header"
          app$attach(rs)
        }
        upgrade_route <- routr::Route$new(
          any = list("/" = function(request, response, ...) {
            if (request$protocol != "https") {
              response <- request$respond()
              response$status <- 308L
              response$set_header(
                "Location",
                sub("^(\\w+?):", "^\\1s:", request$url)
              )
              response$remove_header("strict-transport-security")
              FALSE
            } else {
              TRUE
            }
          })
        )
        app$plugins$header_routr$add_route(upgrade_route, "upgrade_protocol")
      }
    }
  ),
  active = list(
    #' @field content_security_policy Set or get the value of the
    #' `Content-Security-Policy` header. See [csp()] for documentation of its
    #' values
    #'
    content_security_policy = function(value) {
      if (missing(value)) {
        return(private$CSP)
      }
      value <- validate_csp(value)
      private$CSP <- value
    },
    #' @field content_security_policy_report_only Set or get the value of the
    #' `Content-Security-Policy-Report-Only` header. See [csp()] for
    #' documentation of its values
    #'
    content_security_policy_report_only = function(value) {
      if (missing(value)) {
        return(private$CSPRO)
      }
      value <- validate_csp(value)
      private$CSPRO <- value
    },
    #' @field cross_origin_embedder_policy Set or get the value of the
    #' `Cross-Origin-Embedder-Policy`. Possible values are `"unsafe-none"`,
    #' `"require-corp"`, and `"credentialless"`
    #'
    cross_origin_embedder_policy = function(value) {
      if (missing(value)) {
        return(private$COEP)
      }
      if (!is.null(value)) {
        value <- arg_match0(
          value,
          c(
            "unsafe-none",
            "require-corp",
            "credentialless"
          )
        )
      }
      private$COOP <- value
    },
    #' @field cross_origin_opener_policy Set or get the value of the
    #' `Cross-Origin-Opener-Policy`. Possible values are `"unsafe-none"`,
    #' `"same-origin-allow-popups"`, `"same-origin"`, and
    #' `"noopener-allow-popups"`
    #'
    cross_origin_opener_policy = function(value) {
      if (missing(value)) {
        return(private$COOP)
      }
      if (!is.null(value)) {
        value <- arg_match0(
          value,
          c(
            "unsafe-none",
            "same-origin-allow-popups",
            "same-origin",
            "noopener-allow-popups"
          )
        )
      }
      private$COOP <- value
    },
    #' @field cross_origin_resource_policy Set or get the value of the
    #' `Cross-Origin-Resource-Policy`. Possible values are `"same-site"`,
    #' `"same-origin"`, and `"cross-origin"`
    #'
    cross_origin_resource_policy = function(value) {
      if (missing(value)) {
        return(private$CORP)
      }
      if (!is.null(value)) {
        value <- arg_match0(
          value,
          c("same-site", "same-origin", "cross-origin")
        )
      }
      private$CORP <- value
    },
    #' @field origin_agent_cluster Set or get the value of the
    #' `Origin-Agent-Cluster`. Possible values are `TRUE` and `FALSE`
    #'
    origin_agent_cluster = function(value) {
      if (missing(value)) {
        return(private$OAC)
      }
      check_bool(value, allow_null = TRUE)
      private$OAC <- value
    },
    #' @field referrer_policy Set or get the value of the
    #' `Referrer-Policy`. Possible values are `"no-referrer"`,
    #' `"no-referrer-when-downgrade"`, `"origin"`, `"origin-when-cross-origin"`,
    #' `"same-origin"`, `"strict-origin"`, `"strict-origin-when-cross-origin"`,
    #' and `"unsafe-url"`
    #'
    referrer_policy = function(value) {
      if (missing(value)) {
        return(private$RP)
      }
      if (!is.null(value)) {
        value <- arg_match0(
          value,
          c(
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "unsafe-url"
          )
        )
      }
      private$RP <- value
    },
    #' @field strict_transport_security Set or get the value of the
    #' `Strict-Transport-Security` header. See [sts()] for documentation of its
    #' values
    #'
    strict_transport_security = function(value) {
      if (missing(value)) {
        return(private$STS)
      }
      if (!is.null(value)) {
        if (
          !(is_bare_list(value) &&
            is_named(value) &&
            all(
              names(value) %in% c("max_age", "include_sub_domains", "preload")
            ))
        ) {
          stop_input_type(
            value,
            "a list with elements `max_age`, `include_sub_domains`, and `preload`",
            allow_null = TRUE
          )
        }
        check_number_whole(value$max_age, min = 0, allow_infinite = FALSE)
        check_bool(value$include_sub_domains, allow_null = TRUE)
        check_bool(value$preload, allow_null = TRUE)
        if (
          isTRUE(value$preload) &&
            !(value$max_age >= 31536000 && isTRUE(value$include_sub_domains))
        ) {
          cli::cli_abort("{.arg preload} can only be set if {.code include_sub_domains == TRUE} and {.code max_age >= 31536000}")
        }
      }
      private$STS <- value
    },
    #' @field x_content_type_options Set or get the value of the
    #' `X-Content-Type-Options`. Possible values are `TRUE` and `FALSE`
    #'
    x_content_type_options = function(value) {
      if (missing(value)) {
        return(private$XCTO)
      }
      check_bool(value, allow_null = TRUE)
      private$XCTO <- value
    },
    #' @field x_dns_prefetch_control Set or get the value of the
    #' `X-DNS-Prefetch-Control`. Possible values are `TRUE` and `FALSE`
    #'
    x_dns_prefetch_control = function(value) {
      if (missing(value)) {
        return(private$XDPC)
      }
      check_bool(value, allow_null = TRUE)
      private$XDPC <- value
    },
    #' @field x_download_options Set or get the value of the
    #' `X-Download-Options`. Possible values are `TRUE` and `FALSE`
    #'
    x_download_options = function(value) {
      if (missing(value)) {
        return(private$XDO)
      }
      check_bool(value, allow_null = TRUE)
      private$XCTO <- value
    },
    #' @field x_frame_options Set or get the value of the
    #' `X-Frame-Options`. Possible values are `"DENY"` and `"SAMEORIGIN"`
    #'
    x_frame_options = function(value) {
      if (missing(value)) {
        return(private$XFO)
      }
      if (!is.null(value)) {
        value <- arg_match0(
          toupper(value),
          c("DENY", "SAMEORIGIN"),
          "value"
        )
      }
      private$XFO <- value
    },
    #' @field x_permitted_cross_domain_policies Set or get the value of the
    #' `X-Permitted-Cross-Domain-Policies`. Possible values are `"none"`,
    #' `"master-only"`, `"by-content-type"`, `"by-ftp-filename"`, `"all"`, and
    #' `"none-this-response"`
    #'
    x_permitted_cross_domain_policies = function(value) {
      if (missing(value)) {
        return(private$XPCDP)
      }
      if (!is.null(value)) {
        value <- arg_match0(
          value,
          c(
            "none",
            "master-only",
            "by-content-type",
            "by-ftp-filename",
            "all",
            "none-this-response"
          )
        )
      }
      private$XPCDP <- value
    },
    #' @field x_xss_protection Set or get the value of the
    #' `X-XSS-Protection`. Possible values are `TRUE` and `FALSE`
    x_xss_protection = function(value) {
      if (missing(value)) {
        return(private$XXP)
      }
      check_bool(value, allow_null = TRUE)
      private$XXP <- value
    }
  ),
  private = list(
    CSP = NULL,
    CSPRO = NULL,
    COEP = NULL,
    COOP = NULL,
    CORP = NULL,
    OAC = NULL,
    RP = NULL,
    STS = NULL,
    XCTO = NULL,
    XDPC = NULL,
    XDO = NULL,
    XFO = NULL,
    XPCDP = NULL,
    XXP = NULL,

    prepare_headers = function() {
      headers <- list()
      if (!is.null(self$content_security_policy)) {
        csp <- self$content_security_policy
        if ("report_to" %in% names(csp)) {
          csp$report_uri <- csp$report_to
          csp$report_to <- "csp-endpoint"
          headers[["reporting-endpoints"]] <- paste0("csp-endpoint=\"", csp$report_uri, "\"")
        }
        headers[["content-security-policy"]] <- paste(
          gsub("_", "-", names(csp)),
          vapply(csp, paste, character(1), collapse = " "),
          collapse = "; "
        )
      }
      if (!is.null(self$content_security_policy_report_only)) {
        csp <- self$content_security_policy_report_only
        if ("report_to" %in% names(csp)) {
          csp$report_uri <- csp$report_to
          csp$report_to <- "cspro-endpoint"
          headers[["reporting-endpoints"]] <- paste0(c(
            headers[["reporting-endpoints"]],
            paste0("cspro-endpoint=\"", csp$report_uri, "\"")
          ), collapse = ", ")
        }
        headers[["content-security-policy-report-only"]] <- paste(
          gsub("_", "-", names(csp)),
          vapply(csp, paste, character(1), collapse = " "),
          collapse = "; "
        )
      }
      headers[[
        "cross-origin-embedder-policy"
      ]] <- self$cross_origin_embedder_policy
      headers[["cross-origin-opener-policy"]] <- self$cross_origin_opener_policy
      headers[[
        "cross-origin-resource-policy"
      ]] <- self$cross_origin_resource_policy
      if (!is.null(self$origin_agent_cluster)) {
        headers[["origin-agent-cluster"]] <- if (self$origin_agent_cluster) {
          "?1"
        } else {
          "?0"
        }
      }
      headers[["referrer-policy"]] <- self$referrer_policy
      if (!is.null(self$strict_transport_security)) {
        headers[["strict-transport-security"]] <- paste0(
          c(
            paste0("max-age=", self$strict_transport_security$max_age),
            if (isTRUE(self$strict_transport_security$include_sub_domains)) {
              "includeSubDomain"
            },
            if (isTRUE(self$strict_transport_security$preload)) "preload"
          ),
          collapse = "; "
        )
      }
      if (isTRUE(self$x_content_type_options)) {
        headers[["x-content-type-options"]] <- "nosniff"
      }
      if (!is.null(self$x_dns_prefetch_control)) {
        headers[["x-dns-prefetch-control"]] <- if (
          self$x_dns_prefetch_control
        ) {
          "on"
        } else {
          "off"
        }
      }
      if (isTRUE(self$x_download_options)) {
        headers[["x-download-options"]] <- "noopen"
      }
      headers[["x-frame-options"]] <- self$x_frame_options
      headers[[
        "x-permitted-cross-domain-policies"
      ]] <- self$x_permitted_cross_domain_policies
      if (!is.null(self$x_xss_protection)) {
        headers[["x-xss-protection"]] <- if (self$x_xss_protection) {
          "1; mode=block"
        } else {
          "0"
        }
      }
      headers[lengths(headers) != 0]
    }
  )
)
