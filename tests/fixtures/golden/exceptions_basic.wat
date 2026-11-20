(module
  (type (;0;) (func (param i32)))
  (type (;1;) (func))
  (type (;2;) (func (result i32)))
  (func (;0;) (type 1)
    i32.const 42
    throw 0
  )
  (func (;1;) (type 2) (result i32)
    block (result i32)
    try_table (result i32) (catch 0 0)
    i32.const 0
    end
    end
  )
  (export "throw_it" (func 0))
  (export "try_catch" (func 1))
  (tag (;0;) (type 0))
)
