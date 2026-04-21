(module
  (memory 1)
  (data (i32.const 0) "Hello, π, 世界, 🚀")

  (func (export "加算") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add)
)

