(module
  (table $t32 10 externref)
  (table $t64 i64 10 externref)
  (func (export "fill32") (param i32 externref i32)
    local.get 0
    local.get 1
    local.get 2
    table.fill $t32
  )
  (func (export "fill64") (param i64 externref i64)
    local.get 0
    local.get 1
    local.get 2
    table.fill $t64
  )
  (func (export "get64") (param i64) (result externref)
    local.get 0
    table.get $t64
  )
)

