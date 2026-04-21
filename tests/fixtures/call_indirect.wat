(module
  (type $sig (func (param i32) (result i32)))
  (table 2 funcref)
  (elem (i32.const 0) $f1 $f2)

  (func $f1 (param i32) (result i32) (i32.const 42))
  (func $f2 (param i32) (result i32) (i32.const 99))

  (func (export "apply") (param $idx i32) (param $val i32) (result i32)
    local.get $val
    local.get $idx
    ;; call_indirect requires both a type index and a table index
    call_indirect (type $sig)
  )
)