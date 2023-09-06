[bits 32]

  xor ecx, ecx
loop:
  mov dl, byte [0x100 + ecx]
  crc32 eax, dl
  inc ecx
  cmp ecx, ebx
  jnz loop

