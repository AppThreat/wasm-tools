(module
  (type $t0 (func (param i32 i32 i32 i32) (result i32)))
  (type $t1 (func (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (type $t2 (func (param i32 i32) (result i32)))
  (type $t3 (func (param i32)))

  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (type $t0)))
  (import "wasi_snapshot_preview1" "path_open" (func $path_open (type $t1)))
  (import "wasi_snapshot_preview1" "sock_send" (func $sock_send (type $t0)))
  (import "wasi_snapshot_preview1" "random_get" (func $random_get (type $t2)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (type $t3)))

  (func (export "noop"))
)

