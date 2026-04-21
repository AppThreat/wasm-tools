(module
  (type $binop (func (param i32 i32) (result i32)))
  (memory 1)
  (table 1 funcref)
  (global $counter (mut i32) (i32.const 7))

  (func $adder (type $binop) (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add)

  (elem (i32.const 0) $adder)
  (data (i32.const 16) "WASM\00payload")

  (func (export "complex_flow") (param $x i32) (param $y i32) (result i32)
    (local $tmp i32)

    local.get $x
    local.get $y
    call $adder
    local.set $tmp

    block $done
      loop $loop
        local.get $tmp
        i32.eqz
        br_if $done
        local.get $tmp
        i32.const 1
        i32.sub
        local.set $tmp
        br $loop
      end
    end

    i32.const 0
    local.get $tmp
    i32.store align=2

    i32.const 0
    i32.load align=2
    i32.const 1
    i32.const 0
    call_indirect (type $binop)
  )
)

