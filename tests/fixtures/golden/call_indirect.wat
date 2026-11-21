(module
  (type (;0;) (func (param i32) (result i32)))
  (type (;1;) (func (param i32 i32) (result i32)))
  (func (;0;) (type 0) (param i32) (result i32)
    i32.const 42
  )
  (func (;1;) (type 0) (param i32) (result i32)
    i32.const 99
  )
  (func (;2;) (type 1) (param i32 i32) (result i32)
    local.get 1
    local.get 0
    call_indirect (type 0)
  )
  (table (;0;) i32 2 funcref)
  (export "apply" (func 2))
  (elem (;0;) (i32.const 0) func 0 1)
)
