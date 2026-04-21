(module
  (func (export "adversarial_ops") (param $x i32) (result i32)
    (local $tmp i32)

    block $outer
      loop $inner
        local.get $x
        br_table $inner $outer
      end
    end

    i32.const -2147483648
    local.set $tmp
    local.get $tmp
  )
)

