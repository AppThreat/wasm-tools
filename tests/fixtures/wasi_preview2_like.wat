(module
  (import "wasi:cli/run@0.2.0" "run" (func))
  (func (export "main")
    call 0
  )
)

