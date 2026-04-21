(module
  (memory 1)
  (data "bulk-memory-data")

  (func (export "bulk_memory")
    i32.const 0
    i32.const 0
    i32.const 4
    memory.init 0
    data.drop 0

    i32.const 8
    i32.const 65
    i32.const 3
    memory.fill
  )
)

