    .text
    .global toggleSmap
    .type toggleSmap, @function
toggleSmap:
    pushfd
    pop     eax
    xor     eax, 0x40000
    push    eax
    popfd
    ret
