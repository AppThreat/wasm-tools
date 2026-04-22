(module
  (memory (export "mem") 1)
  (func (export "store_lane") (param i32 v128)
    local.get 0
    local.get 1
    v128.store64_lane offset=1 align=4 1
  )
)

