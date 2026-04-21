(module
  (memory 1)
  (data (i32.const 0) "Hello, WebAssembly!")
  (func (export "read_byte") (param i32) (result i32)
    local.get 0
    ;; Load an unsigned byte with offset=2 and alignment=0
    i32.load8_u offset=2 align=1
  )
)