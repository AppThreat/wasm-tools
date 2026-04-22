(module
  (table $t2 i64 1 externref)
  (table $t3 i64 2 funcref)
  (elem (table $t3) (i64.const 1) func $dummy)
  (func $dummy)
  (func (export "get-externref") (param i64) (result externref)
    local.get 0
    table.get $t2
  )
  (func $f3 (export "get-funcref") (param i64) (result funcref)
    local.get 0
    table.get $t3
  )
  (func (export "set-externref") (param i64 externref)
    local.get 0
    local.get 1
    table.set $t2
  )
  (func (export "set-funcref") (param i64 funcref)
    local.get 0
    local.get 1
    table.set $t3
  )
  (func (export "set-funcref-from") (param i64 i64)
    local.get 0
    local.get 1
    table.get $t3
    table.set $t3
  )
)

