    .text
    .global toggleSmap
    .type toggleSmap, @function
toggleSmap:
    pushfq
    xorq    $0x40000,(%rsp)
    popfq
    ret
