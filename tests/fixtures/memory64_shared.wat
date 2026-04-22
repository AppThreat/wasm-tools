(module
  (memory (export "mem") i64 1 3 shared)

  (func (export "size") (result i64)
    memory.size
  )

  (func (export "grow") (param i64) (result i64)
    local.get 0
    memory.grow
  )
)

