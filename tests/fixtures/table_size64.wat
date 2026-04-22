(module
  (table $t0 i64 0 externref)
  (table $t1 i64 1 externref)
  (table $t2 i64 0 2 externref)
  (table $t3 i64 3 8 externref)
  (func (export "size-t0") (result i64)
    table.size $t0
  )
  (func (export "size-t1") (result i64)
    table.size $t1
  )
  (func (export "size-t2") (result i64)
    table.size $t2
  )
  (func (export "size-t3") (result i64)
    table.size $t3
  )
  (func (export "grow-t0") (param i64)
    ref.null extern
    local.get 0
    table.grow $t0
    drop
  )
  (func (export "grow-t1") (param i64)
    ref.null extern
    local.get 0
    table.grow $t1
    drop
  )
  (func (export "grow-t2") (param i64)
    ref.null extern
    local.get 0
    table.grow $t2
    drop
  )
  (func (export "grow-t3") (param i64)
    ref.null extern
    local.get 0
    table.grow $t3
    drop
  )
)

