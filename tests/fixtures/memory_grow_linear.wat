;; Memory.grow OUTSIDE any loop while memory ops run inside a loop.
;;
;; This is the shape the old WASM-DOS-003 rule falsely flagged: one startup
;; growth plus routine loop memory traffic. The tightened rule requires the
;; memory.grow itself to execute inside a loop body, so this module must NOT
;; fire the finding.
(module
  (memory 1)

  (func (export "spin") (result i32)
    (local $i i32)
    (loop $l
      (i32.store (i32.const 0) (i32.const 1))
      (i32.load (i32.const 0))
      drop
      local.get $i
      i32.const 1
      i32.add
      local.tee $i
      i32.const 16
      i32.lt_u
      br_if $l
    )
    (memory.grow (i32.const 1))
  )
)
