// SPDX-License-Identifier: GPL-2.0
//use kernel::bit;

//control registers
/*
    Cr0: usize {
        const CR0_ENABLE_PAGING = 1 << 31;
        const CR0_CACHE_DISABLE = 1 << 30;
        const CR0_NOT_WRITE_THROUGH = 1 << 29;
        const CR0_ALIGNMENT_MASK = 1 << 18;
        const CR0_WRITE_PROTECT = 1 << 16;
        const CR0_NUMERIC_ERROR = 1 << 5;
        const CR0_EXTENSION_TYPE = 1 << 4;
        const CR0_TASK_SWITCHED = 1 << 3;
        const CR0_EMULATE_COPROCESSOR = 1 << 2;
        const CR0_MONITOR_COPROCESSOR = 1 << 1;
        const CR0_PROTECTED_MODE = 1 << 0;
    }
*/

pub(crate) struct Cr0 {
    pub(crate) value: usize,
}

impl Cr0 {
    pub(crate) const CR0_ENABLE_PAGING: usize = 31;
}
/*
    Cr4: usize {
        /// Enables use of Protection Keys (MPK).
        const CR4_ENABLE_PROTECTION_KEY = 1 << 22;
        /// Enable Supervisor Mode Access Prevention.
        const CR4_ENABLE_SMAP = 1 << 21;
        /// Enable Supervisor Mode Execution Protection.
        const CR4_ENABLE_SMEP = 1 << 20;
        /// Enable XSAVE and Processor Extended States.
        const CR4_ENABLE_OS_XSAVE = 1 << 18;
        /// Enables process-context identifiers (PCIDs).
        const CR4_ENABLE_PCID = 1 << 17;
        /// Enables the instructions RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE.
        const CR4_ENABLE_FSGSBASE = 1 << 16;
        /// Enables Safer Mode Extensions (Trusted Execution Technology (TXT)).
        const CR4_ENABLE_SMX = 1 << 14;
        /// Enables Virtual Machine Extensions.
        const CR4_ENABLE_VMX = 1 << 13;
        /// Enables 5-Level Paging.
        const CR4_ENABLE_LA57 = 1 << 12;
        /// Enable User-Mode Instruction Prevention (the SGDT, SIDT, SLDT, SMSW and STR instructions
        /// cannot be executed if CPL > 0).
        const CR4_ENABLE_UMIP = 1 << 11;
        /// Enables unmasked SSE exceptions.
        const CR4_UNMASKED_SSE = 1 << 10;
        /// Enables Streaming SIMD Extensions (SSE) instructions and fast FPU
        /// save & restore FXSAVE and FXRSTOR instructions.
        const CR4_ENABLE_SSE = 1 << 9;
        /// Enable Performance-Monitoring Counters
        const CR4_ENABLE_PPMC = 1 << 8;
        /// Enable shared (PDE or PTE) address translation between address spaces.
        const CR4_ENABLE_GLOBAL_PAGES = 1 << 7;
        /// Enable machine check interrupts.
        const CR4_ENABLE_MACHINE_CHECK = 1 << 6;
        /// Enable: Physical Address Extension (allows to address physical
        /// memory larger than 4 GiB).
        const CR4_ENABLE_PAE = 1 << 5;
        /// Enable Page Size Extensions (allows for pages larger than the traditional 4 KiB size)
        /// Note: If Physical Address Extension (PAE) is used, the size of large pages is reduced
        /// from 4 MiB down to 2 MiB, and PSE is always enabled, regardless of the PSE bit in CR4.
        const CR4_ENABLE_PSE = 1 << 4;
        /// If set, enables debug register based breaks on I/O space access.
        const CR4_DEBUGGING_EXTENSIONS = 1 << 3;
        /// If set, disables ability to take time-stamps.
        const CR4_TIME_STAMP_DISABLE = 1 << 2;
        /// If set, enables support for the virtual interrupt flag (VIF) in protected mode.
        const CR4_VIRTUAL_INTERRUPTS = 1 << 1;
        /// If set, enables support for the virtual interrupt flag (VIF) in virtual-8086 mode.
        const CR4_ENABLE_VME = 1 << 0;
    }
*/

pub(crate) struct Cr4 {
    pub(crate) value: usize,
}

impl Cr4 {
    pub(crate) const CR4_ENABLE_VMX: usize = 13;
}
/*
bitflags! {
    pub struct Xcr0: u64 {
        const XCR0_PKRU_STATE = 1 << 9;
        const XCR0_HI16_ZMM_STATE = 1 << 7;
        const XCR0_ZMM_HI256_STATE = 1 << 6;
        const XCR0_OPMASK_STATE = 1 << 5;
        const XCR0_BNDCSR_STATE = 1 << 4;
        const XCR0_BNDREG_STATE = 1 << 3;
        const XCR0_AVX_STATE = 1 << 2;
        const XCR0_SSE_STATE = 1 << 1;
        const XCR0_FPU_MMX_STATE = 1 << 0;
    }
}
*/

/*
    /// The RFLAGS register.
    /// This is duplicated code from bits32 eflags.rs.
    pub struct RFlags: u64 {
        /// ID Flag (ID)
        const FLAGS_ID = 1 << 21;
        /// Virtual Interrupt Pending (VIP)
        const FLAGS_VIP = 1 << 20;
        /// Virtual Interrupt Flag (VIF)
        const FLAGS_VIF = 1 << 19;
        /// Alignment Check (AC)
        const FLAGS_AC = 1 << 18;
        /// Virtual-8086 Mode (VM)
        const FLAGS_VM = 1 << 17;
        /// Resume Flag (RF)
        const FLAGS_RF = 1 << 16;
        /// Nested Task (NT)
        const FLAGS_NT = 1 << 14;
        /// I/O Privilege Level (IOPL) 0
        const FLAGS_IOPL0 = 0b00 << 12;
        /// I/O Privilege Level (IOPL) 1
        const FLAGS_IOPL1 = 0b01 << 12;
        /// I/O Privilege Level (IOPL) 2
        const FLAGS_IOPL2 = 0b10 << 12;
        /// I/O Privilege Level (IOPL) 3
        const FLAGS_IOPL3 = 0b11 << 12;
        /// Overflow Flag (OF)
                const FLAGS_OF = 1 << 11;
        /// Direction Flag (DF)
        const FLAGS_DF = 1 << 10;
        /// Interrupt Enable Flag (IF)
        const FLAGS_IF = 1 << 9;
        /// Trap Flag (TF)
        const FLAGS_TF = 1 << 8;
        /// Sign Flag (SF)
        const FLAGS_SF = 1 << 7;
        /// Zero Flag (ZF)
        const FLAGS_ZF = 1 << 6;
        /// Auxiliary Carry Flag (AF)
        const FLAGS_AF = 1 << 4;
        /// Parity Flag (PF)
        const FLAGS_PF = 1 << 2;
        /// Bit 1 is always 1.
        const FLAGS_A1 = 1 << 1;
        /// Carry Flag (CF)
        const FLAGS_CF = 1 << 0;
    }
*/

pub(crate) struct RFlags {
    pub(crate) value: u64,
}

#[allow(dead_code)]
impl RFlags {
    pub(crate) const FLAGS_IF: u64 = 9;
    pub(crate) const FLAGS_ZF: u64 = 6;
    pub(crate) const FLAGS_AF: u64 = 4;
    pub(crate) const FLAGS_A1: u64 = 1;
    pub(crate) const FLAGS_CF: u64 = 0;
    // Creates a new Flags entry. Ensures bit 1 is set.
    /*  pub const fn new() -> RFlags {
          RFlags{value:bit(RFlags::FLAGS_A1).into()}
      }

      /// Creates a new Flags with the given I/O privilege level.
      pub const fn from_priv(iopl: Ring) -> RFlags {
          RFlags {
              bits: (iopl as u64) << 12,
          }
      }

      pub const fn from_raw(bits: u64) -> RFlags {
          RFlags { value: bits }
      }
    */
}

/*
pub fn rflags_read() -> RFlags {
    let r: u64;
    unsafe { asm!("pushfq; popq {0}", out(reg) r, options(att_syntax)) };
    RFlags{value: r}
}

pub fn rflags_set(val: RFlags) {
    unsafe {
        asm!("pushq {0}; popfq", in(reg) val.value, options(att_syntax));
    }
}

pub fn rip() -> u64 {
    let rip: u64;
    unsafe {
        asm!("leaq 0(%rip), {0}", out(reg) rip, options(att_syntax));
    }
    rip
}

pub fn rbp() -> u64 {
    let rbp: u64;
    unsafe {
        asm!("mov %rbp, {0}", out(reg) rbp, options(att_syntax));
    }
    rbp
}
*/
