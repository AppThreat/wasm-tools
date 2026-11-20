;; Control-flow-flattened shape: a dispatch loop switching over a wide
;; br_table threading through nested case blocks (the shape WASMixer-style
;; restructuring and classic CFF leave behind).
(module
  (func (export "flattened") (param i32) (result i32)
    (local $acc i32)
    (block $exit
      (loop $dispatch
        (block $c0
          (block $c1
            (block $c2
              (block $c3
                (block $c4
                  (block $c5
                    (block $c6
                      local.get 0
                      br_table $dispatch $c6 $c5 $c4 $c3 $c2 $c1 $c0
                    )
                    ;; case 6
                    local.get $acc
                    i32.const 6
                    i32.add
                    local.set $acc
                    br $dispatch
                  )
                  ;; case 5
                  local.get $acc
                  i32.const 5
                  i32.add
                  local.set $acc
                  br $dispatch
                )
                ;; case 4
                local.get $acc
                i32.const 4
                i32.add
                local.set $acc
                br $dispatch
              )
              ;; case 3
              local.get $acc
              i32.const 3
              i32.add
              local.set $acc
              br $dispatch
            )
            ;; case 2
            local.get $acc
            i32.const 2
            i32.add
            local.set $acc
            br $dispatch
          )
          ;; case 1
          local.get $acc
          i32.const 1
          i32.add
          local.set $acc
          br $dispatch
        )
        ;; case 0 completed the state machine
        br $exit
      )
    )
    local.get $acc
  )
  (func (result i32) i32.const 1)
  (func (result i32) i32.const 2)
  (func (result i32) i32.const 3)
  (func (result i32) i32.const 4)
  (func (result i32) i32.const 5)
  (func (result i32) i32.const 6)
  (func (result i32) i32.const 7)
  (func (result i32) i32.const 8)
  (func (result i32) i32.const 9)
)
