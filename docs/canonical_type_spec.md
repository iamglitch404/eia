# EIA Canonical Type System Specification (Version 1.0)
## Frozen Cryptographic Type Contract Representation

### 1. Overview
The Eternal Interface Architecture (EIA) guarantees application binary compatibility across decades and hardware architectures without recompilation. To achieve deterministic, collision-resistant type identity between independent compilers (e.g., `spark0` stage-0 and `core1` self-hosted stage-1), EIA mandates a **Canonical Type Representation** hashed via BLAKE3.

---

### 2. Primitive Type Identifiers (BLAKE3-64 / FNV-1a Seeds)

Every primitive type in the EIA type universe has a 64-bit canonical type hash:

| Primitive Type | Size (Bytes) | Alignment | Canonical Hash (u64 Hex) | Description |
|---|---|---|---|---|
| `void` | 0 | 1 | `0x31726f5344494f5f` (`3563412735833858527`) | Void / unit return type |
| `i64` | 8 | 8 | `0x2adc0e86b971a8e6` (`3089943341986682694`) | Signed 64-bit integer |
| `u64` | 8 | 8 | `0x4d32f5209ea9b3d2` (`5563585020063213298`) | Unsigned 64-bit integer |
| `i32` | 4 | 4 | `0x2adc5186b9721c05` (`3090684413159346501`) | Signed 32-bit integer |
| `u32` | 4 | 4 | `0x4d2917209ea0be11` (`5560783464435099345`) | Unsigned 32-bit integer |
| `i16` | 2 | 2 | `0x2adc4f86b972189f` (`3090649228787259551`) | Signed 16-bit integer |
| `u16` | 2 | 2 | `0x4d2915209ea0baa7` (`5560779066388593319`) | Unsigned 16-bit integer |
| `i8` | 1 | 1 | `0x08c4e40285970c38` (`631889365574323256`) | Signed 8-bit integer |
| `u8` | 1 | 1 | `0x08c4e00285970568` (`631772817358541784`) | Unsigned 8-bit integer |
| `f64` | 8 | 8 | `0x3b1c90538a791a20` (`4259419517112007200`) | IEEE 754 double precision float |
| `f32` | 4 | 4 | `0x3b1c94538a7920f0` (`4259423915159789808`) | IEEE 754 single precision float |
| `bool` | 1 | 1 | `0x71a4f0289b52a781` (`8188924513697195905`) | Boolean logical type |

---

### 3. Pointer & Indirection Representation
Pointers wrap a base pointee type and encode depth and mutability:
- `is_ptr = 0`: Direct value
- `is_ptr = (depth << 2) | mut_flag`
  - `mut_flag = 1`: `*const` (immutable pointer)
  - `mut_flag = 2`: `*mut` (mutable pointer)
  - Example: `*const T` -> `depth=1, mut=1` -> `0x05`
  - Example: `*mut T` -> `depth=1, mut=2` -> `0x06`
  - Example: `**mut T` -> `depth=2, mut=2` -> `0x0A`

---

### 4. Fixed-Size Arrays (`[T; N]`)
Array types are canonically encoded as a 24-byte payload:
```
[kind: u32 LE (0x0A = TYPE_ARRAY)] [elem_type_hash: u64 LE] [element_count: u64 LE] [pad: u32 (0)]
```
Hashed via `blake3_hash64`, producing a unique structural identifier for any `[T; N]`.

---

### 5. Struct Representation: Structural Layout vs Nominal Contract
EIA distinguishes two levels of struct typing:
1. **Nominal Contract ID** (`type_sig_hash` in type graph):
   - Defined as `blake3_hash64(struct_name)`.
   - Allows schemas to evolve over time (fields added, reordered, widened) without breaking field lookups.
2. **Structural Layout Hash** (`layout_digest`):
   - Computed over the sorted sequence of field definitions:
   ```
   [field_count: u32 LE] [total_size: u32 LE] [alignment: u32 LE] [flags: u32 LE]
   followed by N field records:
   [field_name_hash: u64 LE] [field_type_hash: u64 LE] [byte_offset: u32 LE] [field_size: u32 LE]
   ```
   - Two structs with different names but identical field types and physical layout share an identical `layout_digest`.

---

### 6. Canonical Function Signature Encoding
Function signatures are encoded into a continuous Little-Endian binary record:
- **Bytes 0..3**: `param_count` (`u32` LE)
- **Bytes 4..7**: `calling_conv` (`u32` LE)
  - `0`: `EIA_CCONV_SYSV` (System V AMD64 / Standard AAPCS64 / RISC-V LP64D)
  - `1`: `EIA_CCONV_WIN64` (Microsoft x64 / Win64 ABI)
  - `2`: `EIA_CCONV_EIA` (EIA Sovereign Canonical Cross-ISA ABI)
  - `3`: `EIA_CCONV_AAPCS` (ARM64 AAPCS Explicit)
  - `4`: `EIA_CCONV_RISCV` (RISC-V LP64D Explicit)
- **Bytes 8..15**: `ret_type_hash` (`u64` LE)
- **Bytes 16 + i*16 .. 16 + i*16 + 15**: Parameter `i` (`0 <= i < param_count`)
  - `+0..+7`: `param_type_hash` (`u64` LE)
  - `+8..+15`: `is_ptr` / indirection descriptor (`u64` LE)

Total buffer size: `16 + (param_count * 16)` bytes.
The cryptographic hash: `sig_hash = blake3_hash64(sig_buf, total_len)`.

---

### 7. ABI Calling Convention Compatibility Matrix
When `caller_conv != callee_conv`, the dynamic loader injects a bridge thunk:

| Caller ABI | Callee ABI | Target Architecture | Action |
|---|---|---|---|
| SysV AMD64 | SysV AMD64 | x86-64 | Direct `call rel32` |
| SysV AMD64 | Win64 x64 | x86-64 | Inject SysV->Win64 Bridge Thunk (`RDI,RSI,RDX,RCX` -> `RCX,RDX,R8,R9` + 32-byte shadow) |
| Win64 x64 | SysV AMD64 | x86-64 | Inject Win64->SysV Bridge Thunk (`RCX,RDX,R8,R9` -> `RDI,RSI,RDX,RCX`) |
| AAPCS64 | AAPCS64 | ARM64 | Direct `BL imm26` |
| RISC-V Standard | RISC-V Standard | RISC-V 64 | Direct `JAL ra, imm20` |

---

### 8. Schema Evolution & Widening Rules
1. **Extension**: Provider may add new fields at any offset. Client ignores unreferenced fields.
2. **Reordering**: Provider may reorder fields. Client holes are patched with provider's exact byte offsets.
3. **Missing Fields**: If client references a field not present in provider type graph, loader rejects fail-closed (`EIA_ERR_FIELD_NOT_FOUND`).
4. **Field Widening**:
   - Provider `u32` -> Client `u64`: Loader patches load instruction to zero-extending load (`mov eax, [rdi]; nop` on x86, `ldr w0, [x1]` on ARM64, `lwu a0, 0(a1)` on RISC-V).
   - Provider `i32` -> Client `i64`: Loader patches load to sign-extending load (`movsxd rax, [rdi]` on x86, `ldrsw x0, [x1]` on ARM64, `lw a0, 0(a1)` on RISC-V).
   - Unadapted field narrowing fails closed (`EIA_ERR_NARROWING_UNSUPPORTED`).
