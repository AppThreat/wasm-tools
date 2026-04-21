;; Exceptions fixture – uses throw and try_table (new exception handling)
(module
  (tag $exn (param i32))

  (func (export "throw_it")
    i32.const 42
    throw $exn
  )

  (func (export "try_catch") (result i32)
    (block $label (result i32)
      (try_table (result i32) (catch $exn $label)
        i32.const 0
      )
    )
  )
)
