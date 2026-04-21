(module
  (type $t0 (func (param i32)))
  (type $t1 (func (param i32 i32)))
  (type $t2 (func (param i32) (result i32)))

  (import "js" "console_log" (func $console_log (type $t0)))
  (import "wbg" "__wbindgen_throw" (func $wbindgen_throw (type $t1)))
  (import "wasm:js-string" "length" (func $js_string_length (type $t2)))

  (func (export "run")
    i32.const 1
    call $console_log)

  (func (export "__wbindgen_start")
    i32.const 0
    i32.const 0
    call $wbindgen_throw)
)

