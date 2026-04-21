(module
  (func $countdown (param $n i32) (result i32)
    (block $done
      (loop $loop
        local.get $n
        i32.eqz
        br_if $done
        local.get $n
        i32.const 1
        i32.sub
        local.set $n
        br $loop
      )
    )
    local.get $n
  )
)