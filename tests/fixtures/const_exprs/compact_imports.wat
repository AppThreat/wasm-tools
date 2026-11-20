;; Compact import groups: one with a type per item (0x7F) and one where
;; all items share a type (0x7E), followed by an ordinary import.
(module
  (import "env" (item "f1" (func)) (item "f2" (func (param i32))))
  (import "env" (item "g1") (item "g2") (global i32))
  (import "host" "mem" (memory 1))
  (func (export "run") (call 1 (global.get 1))))
