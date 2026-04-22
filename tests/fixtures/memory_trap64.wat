(module
  (memory (export "mem") i64 1)
  (func $addr_limit (result i64)
    memory.size
    i64.const 65536
    i64.mul
  )
  (func (export "store") (param i64 i32)
    call $addr_limit
    local.get 0
    i64.add
    local.get 1
    i32.store
  )
  (func (export "load") (param i64) (result i32)
    call $addr_limit
    local.get 0
    i64.add
    i32.load
  )
  (func (export "grow") (param i64) (result i64)
    local.get 0
    memory.grow
  )
)

