;; Threads fixture – atomic memory operations on shared memory
(module
  (memory (export "mem") 1 1 shared)

  (func (export "atomic_add") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.atomic.rmw.add offset=0
  )

  (func (export "atomic_notify") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    memory.atomic.notify offset=0
  )

  (func (export "atomic_wait32") (param i32 i32 i64) (result i32)
    local.get 0
    local.get 1
    local.get 2
    memory.atomic.wait32 offset=0
  )
)

