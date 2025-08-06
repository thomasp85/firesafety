# validate_csp validates input types

    Code
      validate_csp("not a list")
    Condition
      Error:
      ! `value` must be a list with elements `child_src`, `connect_src`, `default_src`, `fenced_frame_src`, `font_src`, `frame_src`, `img_src`, `manifest_src`, `media_src`, `object_src`, `prefetch_src`, `script_src`, `script_src_elem`, `script_src_attr`, `style_src`, `style_src_elem`, `style_src_attr`, `worker_src`, ..., `trusted_types`, and `upgrade_insecure_requests` or `NULL`, not the string "not a list".

---

    Code
      validate_csp(list(invalid_directive = "value"))
    Condition
      Error:
      ! `value` must be a list with elements `child_src`, `connect_src`, `default_src`, `fenced_frame_src`, `font_src`, `frame_src`, `img_src`, `manifest_src`, `media_src`, `object_src`, `prefetch_src`, `script_src`, `script_src_elem`, `script_src_attr`, `style_src`, `style_src_elem`, `style_src_attr`, `worker_src`, ..., `trusted_types`, and `upgrade_insecure_requests` or `NULL`, not a list.

# validate_csp warns about inapplicable directives

    Code
      validate_csp(csp(style_src = c("self", "unsafe-eval")))
    Condition
      Warning:
      "'unsafe-eval'" is not applicable to the style_src directive. Ignoring
    Output
      $style_src
      [1] "'self'"
      

# validate_csp warns about superseeded directives

    Code
      validate_csp(csp(script_src = c("self", "unsafe-inline", "strict-dynamic")))
    Condition
      Warning:
      "'self'" and "'unsafe-inline'" are superseeded by 'strict-dynamic' in script_src. Ignoring
    Output
      $script_src
      [1] "'strict-dynamic'"
      

# validate_csp handles complex real-world examples

    Code
      validate_csp(complex_csp)
    Condition
      Warning:
      "'self'" and "https://example.com" are superseeded by 'strict-dynamic' in script_src. Ignoring
    Output
      $connect_src
      [1] "'self'"
      
      $default_src
      [1] "'none'"
      
      $font_src
      [1] "'self'"                    "https://fonts.gstatic.com"
      
      $img_src
      [1] "'self'" "data:" 
      
      $script_src
      [1] "'strict-dynamic'"
      
      $style_src
      [1] "'self'"          "'unsafe-inline'"
      
      $base_uri
      [1] "'self'"
      
      $form_action
      [1] "'self'"
      
      $frame_ancestors
      [1] "'none'"
      
      $upgrade_insecure_requests
      [1] ""
      

