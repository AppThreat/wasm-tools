(module
  (import "env" "log" (func $log (param i32)))
  (type $helper_t (func (param i32) (result i32)))
  (table 2 funcref)
  (elem (i32.const 0) $helper)
  (func $helper (param i32) (result i32)
    local.get 0)
  (func $run (export "run")
    i32.const 7
    call $log
    i32.const 1
    i32.const 0
    call_indirect (type $helper_t)
    drop)
  (func $dead
    i32.const 99
    call $log)
)
