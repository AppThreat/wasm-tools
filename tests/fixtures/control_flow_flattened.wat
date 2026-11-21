;; Control-flow-flattened shape: an FNV-1a checksum rewritten the way
;; OLLVM-style flattening and binary-level rewriters such as WASMixer leave
;; it. The function becomes one loop that dispatches on a state local; the
;; state starts at a constant, and every case block is a straight-line run
;; that writes the next state's constant (a select of two constants for a
;; conditional successor) and branches straight back to the loop.
;;
;; $dense dispatches through a br_table on case numbers 0..8; $sparse uses
;; random 32-bit case values, which compile to a tree of i32.eq / i32.ne
;; tests instead of a br_table. Both mirror what clang 23 emits for a
;; flattened switch when jump threading has not undone the flattening.
(module
  (memory 1)
  (func $dense (export "dense") (param $p i32) (param $n i32) (result i32)
    (local $h i32) (local $state i32) (local $i i32) (local $t i32)
    i32.const -2128831035
    local.set $h
    i32.const 0
    local.set $state
    (block $done
      (loop $dispatch
        (block $c7
          (block $c6
            (block $c5
              (block $c4
                (block $c3
                  (block $c2
                    (block $c1
                      (block $c0
                        local.get $state
                        br_table $c0 $c1 $c2 $c3 $c4 $c5 $c6 $c7 $done $dispatch
                      )
                      ;; case 0: i = 0
                      i32.const 0
                      local.set $i
                      i32.const 1
                      local.set $state
                      br $dispatch
                    )
                    ;; case 1: i < n ? 2 : 6
                    i32.const 2
                    i32.const 6
                    local.get $i
                    local.get $n
                    i32.lt_u
                    select
                    local.set $state
                    br $dispatch
                  )
                  ;; case 2: t = p[i]
                  local.get $p
                  local.get $i
                  i32.add
                  i32.load8_u
                  local.set $t
                  i32.const 3
                  local.set $state
                  br $dispatch
                )
                ;; case 3: h ^= t
                local.get $h
                local.get $t
                i32.xor
                local.set $h
                i32.const 4
                local.set $state
                br $dispatch
              )
              ;; case 4: h *= prime
              local.get $h
              i32.const 16777619
              i32.mul
              local.set $h
              i32.const 5
              local.set $state
              br $dispatch
            )
            ;; case 5: i++
            local.get $i
            i32.const 1
            i32.add
            local.set $i
            i32.const 1
            local.set $state
            br $dispatch
          )
          ;; case 6: h ^= h >> 15
          local.get $h
          local.get $h
          i32.const 15
          i32.shr_u
          i32.xor
          local.set $h
          i32.const 7
          local.set $state
          br $dispatch
        )
        ;; case 7: final mix, then case 8 leaves through $done
        local.get $h
        i32.const 739982445
        i32.mul
        local.set $h
        i32.const 8
        local.set $state
        br $dispatch
      )
    )
    local.get $h
  )

  (func $sparse (export "sparse") (param $p i32) (param $n i32) (result i32)
    (local $h i32) (local $i i32) (local $state i32) (local $t i32)
    i32.const -2128831035
    local.set $h
    i32.const -1707336153
    local.set $state
    (loop $dispatch (result i32)
      (block $set_i
        (block $test
          (block $load
            (block $xor
              (block $mul
                (block $inc
                  (block $fold
                    (block $mix
                      local.get $state
                      i32.const -1707336153
                      i32.eq
                      br_if $set_i
                      local.get $state
                      i32.const 461308066
                      i32.eq
                      br_if $test
                      local.get $state
                      i32.const 1847708116
                      i32.eq
                      br_if $load
                      local.get $state
                      i32.const -1005879661
                      i32.eq
                      br_if $xor
                      local.get $state
                      i32.const 1474472432
                      i32.eq
                      br_if $mul
                      local.get $state
                      i32.const -388942997
                      i32.eq
                      br_if $inc
                      local.get $state
                      i32.const 61693713
                      i32.eq
                      br_if $fold
                      local.get $state
                      i32.const 2084837806
                      i32.eq
                      br_if $mix
                      local.get $state
                      i32.const -1299161540
                      i32.ne
                      br_if $dispatch
                      local.get $h
                      return
                    )
                    ;; mix
                    local.get $h
                    i32.const 739982445
                    i32.mul
                    local.set $h
                    i32.const -1299161540
                    local.set $state
                    br $dispatch
                  )
                  ;; fold
                  local.get $h
                  local.get $h
                  i32.const 15
                  i32.shr_u
                  i32.xor
                  local.set $h
                  i32.const 2084837806
                  local.set $state
                  br $dispatch
                )
                ;; inc
                local.get $i
                i32.const 1
                i32.add
                local.set $i
                i32.const 461308066
                local.set $state
                br $dispatch
              )
              ;; mul
              local.get $h
              i32.const 16777619
              i32.mul
              local.set $h
              i32.const -388942997
              local.set $state
              br $dispatch
            )
            ;; xor
            local.get $h
            local.get $t
            i32.xor
            local.set $h
            i32.const 1474472432
            local.set $state
            br $dispatch
          )
          ;; load
          local.get $p
          local.get $i
          i32.add
          i32.load8_u
          local.set $t
          i32.const -1005879661
          local.set $state
          br $dispatch
        )
        ;; test: i < n ? load : fold
        i32.const 1847708116
        i32.const 61693713
        local.get $i
        local.get $n
        i32.lt_u
        select
        local.set $state
        br $dispatch
      )
      ;; set_i
      i32.const 0
      local.set $i
      i32.const 461308066
      local.set $state
      br $dispatch
    )
  )
)
