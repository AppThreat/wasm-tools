(module
  (type $ret_ref (func (result externref)))
  (type $ret_i64 (func (result i64)))
  (type $pair_ret (func (result i32 i64)))
  (type $ref_to_i64 (func (param externref) (result i64)))
  (type $log_t (func (param i32)))
  (type $unary_i32 (func (param i32) (result i32)))

  (import "js" "get_ref" (func $get_ref (type $ret_ref)))
  (import "js" "get_i64" (func $get_i64 (type $ret_i64)))
  (import "js" "pair" (func $pair (type $pair_ret)))
  (import "js" "to_i64" (func $to_i64 (type $ref_to_i64)))
  (import "js" "console_log" (func $console_log (type $log_t)))

  (table $t0 1 funcref)
  (elem (i32.const 0) func $id)

  (func $id (type $unary_i32) (param i32) (result i32)
    local.get 0
  )

  ;; Exported tiny trampoline with conversion pressure + dynamic dispatch.
  (func (export "__wbindgen_start") (result i32)
    call $get_i64
    i32.wrap_i64
    call $console_log
    i32.const 0
    ref.func $id
    table.set $t0
    i32.const 7
    i32.const 0
    call_indirect $t0 (type $unary_i32)
  )

  ;; Unguarded call_ref to surface guard-quality risk metrics.
  (func (export "callref_unsafe") (param i32) (result i32)
    local.get 0
    ref.func $id
    call_ref $unary_i32
  )
)
