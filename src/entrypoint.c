// We need to forward routine registration from C to Rust
// to avoid the linker removing the static library.

void R_init_tapLock_extendr(void *dll);

void R_init_tapLock(void *dll) {
    R_init_tapLock_extendr(dll);
}
