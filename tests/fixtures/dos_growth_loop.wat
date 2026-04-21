(module
  (memory 1)

  (func (export "grow_loop")
    (loop
      i32.const 1
      memory.grow
      drop
      br 0
    )
  )
)

