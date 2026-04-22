(module
  (memory (export "mem") i64 1 1)
  (data (i64.const 0) "\00\00\00\00\00\00\00\00")
  (data "WXYZ")
  (func (export "init")
    i64.const 8
    i32.const 0
    i32.const 4
    memory.init 1
    data.drop 1
  )
  (func (export "copy")
    i64.const 16
    i64.const 8
    i64.const 4
    memory.copy
  )
  (func (export "fill")
    i64.const 24
    i32.const 170
    i64.const 3
    memory.fill
  )
  (func (export "load8") (param i64) (result i32)
    local.get 0
    i32.load8_u
  )
)

