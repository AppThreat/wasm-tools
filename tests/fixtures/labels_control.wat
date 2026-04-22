(module
  (type (;0;) (func (result i32)))
  (type (;1;) (func (param i32) (result i32)))

  (export "block" (func 0))
  (export "loop" (func 1))
  (export "switch" (func 2))
  (export "shadowing" (func 3))
  (export "redefinition" (func 4))

  (func (;0;) (type 0) (result i32)
    block $exit (result i32)
      i32.const 1
      br $exit
      i32.const 0
    end
  )

  (func (;1;) (type 0) (result i32)
    (local $i i32)
    i32.const 0
    local.set $i
    block $exit (result i32)
      loop $cont (result i32)
        local.get $i
        i32.const 1
        i32.add
        local.set $i
        local.get $i
        i32.const 5
        i32.eq
        if
          local.get $i
          br $exit
        end
        br $cont
      end
    end
  )

  (func (;2;) (type 1) (param i32) (result i32)
    block $ret (result i32)
      i32.const 10
      block $exit (result i32)
        block $0
          block $default
            block $3
              block $2
                block $1
                  local.get 0
                  br_table $0 $1 $2 $3 $default
                end
              end
              i32.const 2
              br $exit
            end
            i32.const 3
            br $ret
          end
        end
        i32.const 5
      end
      i32.mul
    end
  )

  (func (;3;) (type 0) (result i32)
    block $l1 (result i32)
      i32.const 1
      br $l1
      i32.const 2
      i32.xor
    end
  )

  (func (;4;) (type 0) (result i32)
    block $l1 (result i32)
      block $l1 (result i32)
        i32.const 2
      end
      block $l1 (result i32)
        i32.const 3
        br $l1
      end
      i32.add
    end
  )
)

