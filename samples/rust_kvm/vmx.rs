// SPDX-License-Identifier: GPL-2.0
#![feature(asm)]
#[feature(llvm_asm)]
//VMX instruction
use kernel::bit;
use crate::x86reg::{self,RFlags};
//#[cfg(target_arch="x86_64")]
//use core::llvm_asm;

pub type Result<T> = core::result::Result<T, VmFail>;
#[derive(Debug)]
pub enum VmFail {
    /// VMCS pointer is valid, but some other error was encountered. Read
    /// VM-instruction error field of VMCS for more details.
    VmFailValid,
    /// VMCS pointer is not valid.
    VmFailInvalid,
}

fn vmx_status() -> Result<()> {
    let flags = x86reg::rflags_read();

    if (flags.value & bit(x86reg::RFlags::FLAGS_ZF)) > 0 {
        Err(VmFail::VmFailValid)
    } else if (flags.value & bit(x86reg::RFlags::FLAGS_CF)) > 0 {
        Err(VmFail::VmFailInvalid)
    } else {
        Ok(())
    }
}


pub unsafe fn vmxon(addr: u64) -> Result<()> {
    asm!("vmxon ({0})", in(reg) &addr, options(att_syntax));
    vmx_status()
}


pub unsafe fn vmxoff() -> Result<()> {
    asm!("vmxoff");
    vmx_status()
}


pub unsafe fn vmclear(addr: u64) -> Result<()> {
    asm!("vmclear ({0})", in(reg) &addr, options(att_syntax));
    vmx_status()
}


pub unsafe fn vmptrst() -> Result<u64> {
    let value: u64 = 0;
    asm!("vmptrst ({0})", in(reg) &value, options(att_syntax));
    vmx_status().and(Ok(value))
}

pub unsafe fn vmread(field: u32) -> Result<u64> {
    let field: u64 = field.into();
    let value: u64;
    asm!("vmread {0}, {1}", in(reg) field, out(reg) value, options(att_syntax));
    vmx_status().and(Ok(value))
}

pub unsafe fn vmlaunch() -> Result<()> {
    asm!("vmlaunch");
    vmx_status()
}

pub unsafe fn vmresume() -> Result<()> {
    asm!("vmresume");
    vmx_status()
}

