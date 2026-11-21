;; A function calling imported WASI functions (fd_write, proc_exit) so the
;; per-function features block can exercise calls_imported_functions and
;; imported_callees against the imported-function index space.
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (func (export "emit") (param i32) (result i32)
    local.get 0
    local.get 0
    local.get 0
    local.get 0
    call $fd_write
  )
  (func (export "bail") (param i32)
    local.get 0
    call $proc_exit
    local.get 0
    local.get 0
    local.get 0
    local.get 0
    call $fd_write
    drop
  )
)
