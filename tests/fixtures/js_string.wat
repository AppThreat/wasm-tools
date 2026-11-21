;; JS String Builtins (phase 5): a module importing the reserved
;; `wasm:js-string` builtin set. Chrome 130+/Firefox 134+/Safari 26.2 ship
;; it; capability detection maps it to js-strings + js.host.
(module
  (import "wasm:js-string" "length" (func $length (param externref) (result i32)))
  (import "wasm:js-string" "cast" (func $cast (param externref) (result externref)))
  (import "wasm:js-string" "concat" (func $concat (param externref externref) (result externref)))
  (func (export "len") (param externref) (result i32)
    (call $length (local.get 0))
  )
  (func (export "twice") (param externref) (result externref)
    (call $concat (local.get 0) (local.get 0))
  )
)
