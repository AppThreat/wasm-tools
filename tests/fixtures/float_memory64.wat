(module
  (memory (export "mem") i64 1 1)
  (func (export "f32.load0") (result f32)
    i64.const 0
    f32.load
  )
  (func (export "f64.load8") (result f64)
    i64.const 0
    f64.load offset=8
  )
  (func (export "f32.store")
    i64.const 0
    f32.const 1.5
    f32.store
  )
  (func (export "f64.store")
    i64.const 16
    f64.const 2.5
    f64.store
  )
  (data (i64.const 0) "\00\00\c0\3f\00\00\00\00\00\00\00\00\00\00\04\40")
)

