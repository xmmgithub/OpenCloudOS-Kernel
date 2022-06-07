// SPDX-License-Identifier: GPL-2.0
use kernel::bindings;
use kernel::pages::Pages;
#[feature(global_asm)]
use kernel::prelude::*;
use kernel::sync::{Mutex, Ref, UniqueRef};
use kernel::Result;
//use alloc::alloc::{AllocError};
use super::{Guest, GuestWrapper};
use crate::exit::*;
use crate::mmu::*;
use crate::vmcs::*;
use crate::vmstat::*;
use core::ptr::NonNull;

#[repr(C)]
#[allow(dead_code)]
pub(crate) struct RkvmRegs {
        /* out (KVM_GET_REGS) / in (KVM_SET_REGS) */
        pub(crate) rax: u64, 
        pub(crate) rbx: u64, 
        pub(crate) rcx: u64,
        pub(crate) rdx: u64,
        pub(crate) rsi: u64, 
        pub(crate) rdi: u64,
        pub(crate) rsp: u64,
        pub(crate) rbp: u64,
        pub(crate) r8:  u64,
        pub(crate) r9: u64,
        pub(crate) r10: u64,
        pub(crate) r11: u64,
        pub(crate) r12: u64,
        pub(crate) r13: u64,
        pub(crate) r14: u64,
        pub(crate) r15: u64,
        pub(crate) rip: u64,
        pub(crate) rflags: u64,
}

#[repr(C)]
#[allow(dead_code)]
pub(crate) struct RkvmRun {
    /* in */
    pub(crate) request_interrupt_window: u8,
    pub(crate) immediate_exit: u8,
    pub(crate) padding1: u32,
    pub(crate) padding2: u16,
    /* out */
    pub(crate) exit_reason: u32,
    pub(crate) ready_for_interrupt_injection: u8,
    pub(crate) if_flag: u8,
    pub(crate) flags: u16,
}

#[repr(C)]
#[allow(dead_code)]
struct VmxInfo {
    revision_id: u32,
    region_size: u16,
    write_back: bool,
    io_exit_info: bool,
    vmx_controls: bool,
}

#[allow(dead_code)]
pub(crate) struct Vcpu {
    pub(crate) guest: Ref<GuestWrapper>,
    pub(crate) vmx_state: Box<VmxState>,
    // DefMut trait for UniqueRef, List use it
    pub(crate) mmu: UniqueRef<RkvmMmu>,
    pub(crate) va_run: u64,
    pub(crate) run: *mut RkvmRun,
    pub(crate) va_vmcs: u64,
    //pub(crate) vmcs:
    pub(crate) vcpu_id: u32,
    pub(crate) launched: bool,
}
pub(crate) fn alloc_vmcs(revision_id: u32, size: u16) -> Result<u64> {
    let page = Pages::<0>::new();
    let page = match page {
            Ok(page) => page,
            Err(err) => return Err(err),
        };
    let vmxinfo = VmxInfo {
        revision_id: revision_id,
        region_size: size,
        write_back: false,
        io_exit_info: false,
        vmx_controls: true,
    };

    let mut vmcs: u64 = 0;
    unsafe {
        vmcs = bindings::rkvm_page_address(page.pages);
        let len = core::mem::size_of::<VmxInfo>();
        let p = &vmxinfo;
        pr_info!(
            "Rust kvm: vmcs={:x}, size={:?},revision={:?} \n",
            vmcs,
            size,
            vmxinfo.revision_id,
        );
        let ptr = core::slice::from_raw_parts((p as *const VmxInfo) as *mut u8, len);

        page.write(ptr.as_ptr(), 0, len);
    }
    Ok(vmcs)
}

fn vmcs_load(va: u64) {
   unsafe {
      let phy = bindings::rkvm_phy_address(va);
      bindings::rkvm_vmcs_load(phy);
   }
}

fn vmcs_clear(va: u64) {
   unsafe {
       let phy = bindings::rkvm_phy_address(va);
       bindings::rkvm_vmcs_clear(phy);
   }
}


pub(crate) struct VcpuWrapper {
    pub(crate) vcpuinner: Mutex<Vcpu>,
}
impl VcpuWrapper {
    pub(crate) fn new(guest: Ref<GuestWrapper>, revision_id: u32, size: u16) -> Result<Ref<Self>> {
        let state = Box::try_new(VmxState::new()?);
        let state = match state {
            Ok(state) => state,
            Err(_) => return Err(Error::ENOMEM),
        };
        // kvm_run
        let page = Pages::<0>::new();
        let run = match page {
            Ok(page) => page,
            Err(err) => return Err(err),
        };
        let mut va_run = unsafe { bindings::rkvm_page_address(run.pages) };
        // alloc vmcs and init 
        let va_vmcs = alloc_vmcs(revision_id, size);
        let va_vmcs = match va_vmcs {
            Ok(va) => va,
            Err(err) => return Err(/*Error::ENOMEM*/ err),
        };
        vmcs_clear(va_vmcs);

        let mmu = RkvmMmu::new();

        let mut mmu = match mmu {
            Ok(mmu) => mmu,
            Err(err) => return Err(err),
        };
        let ptr = NonNull::new(va_run as *mut RkvmRun).unwrap().as_ptr();
        mmu.init_mmu_root();
        let mut v = Pin::from(UniqueRef::try_new(Self {
            vcpuinner: unsafe {
                Mutex::new(Vcpu {
                    guest: guest,
                    vmx_state: state,
                    mmu: mmu,
                    va_run: va_run,
                    va_vmcs: va_vmcs,
                    run: ptr,
                    vcpu_id: 0,
                    launched: false,
                })
            },
        })?);
        let pinned = unsafe { v.as_mut().map_unchecked_mut(|s| &mut s.vcpuinner) };
        kernel::mutex_init!(pinned, "VcpuWrapper::vcpuinner");
        // vmcs load
        vmcs_load(va_vmcs);
        Ok(v.into())
    }

    pub(crate) fn init(&self, vmcsconf: &VmcsConfig) {
        vmcsconf.vcpu_vmcs_init();
    }

    pub(crate) fn get_run(&self) -> u64 {
        self.vcpuinner.lock().va_run
    }

    pub(crate) fn vcpu_exit_handler(&self) -> Result<u64> {
        let exit_info = ExitInfo::from_vmcs();
        let mut vcpuinner = self.vcpuinner.lock();
        unsafe {
            (*vcpuinner.run).exit_reason = exit_info.exit_reason as u32;
        }

        match exit_info.exit_reason {
            ExitReason::HLT => return handle_hlt(&exit_info, self),
            //ExitReason::IO_INSTRUCTION => handle_io_instruction(&exit_info),
            ExitReason::EPT_VIOLATION => return handle_ept_violation(&exit_info, self),
            _ => return Err(Error::EINVAL),
        };
    }

    pub(crate) fn vcpu_run(&self) -> i64 {
        let mut vcpuinner = self.vcpuinner.lock();
        vmcs_load(vcpuinner.va_vmcs);
        loop {
            unsafe {
                bindings::rkvm_irq_disable();
            }
            
            //let mut vcpuinner = self.vcpuinner.lock();
            let launched = vcpuinner.launched;
            let has_err_ = unsafe { _vmx_vcpu_run(&mut vcpuinner.vmx_state, launched) };

            if has_err_ == 1 {
                unsafe {
                    bindings::rkvm_irq_enable();
                }
                return -1;
            }
            unsafe {
                bindings::rkvm_irq_enable();
            }
            vcpuinner.launched = true;
            //match vmexit_handler
            let ret = self.vcpu_exit_handler();
            // TODO: according to ret, update run
            match ret {
                Ok(r) => {
                    if r == 0 {
                        return r.try_into().unwrap();
                    }
                }
                Err(err) => return -1,
            }
        } // loop
    }
   pub(crate) fn set_regs(&self, regs: &RkvmRegs)  {
       let mut vcpuinner = self.vcpuinner.lock();
       vmcs_load(vcpuinner.va_vmcs);
       let mut guest_state = vcpuinner.vmx_state.guest_state;
       guest_state.rax = regs.rax;
       guest_state.rbx = regs.rbx;
       guest_state.rcx = regs.rcx;
       guest_state.rdx = regs.rdx;
       guest_state.rsi = regs.rsi;
       guest_state.rdi = regs.rdi;
       guest_state.rsp = regs.rsp;
       guest_state.rbp = regs.rbp;
       guest_state.r8  = regs.r8;
       guest_state.r9  = regs.r9;
       guest_state.r10 = regs.r10;
       guest_state.r11 = regs.r11;
       guest_state.r12 = regs.r12;
       guest_state.r13 = regs.r13;
       guest_state.r14 = regs.r14;
       guest_state.r15 = regs.r15;
       guest_state.rip = regs.rip;
       vmcs_write64(VmcsField::GUEST_RFLAGS, regs.rflags);
   }
   
   pub(crate) fn get_regs(&self, regs: &mut RkvmRegs)  {
       let mut vcpuinner = self.vcpuinner.lock();
       vmcs_load(vcpuinner.va_vmcs);
       let guest_state = vcpuinner.vmx_state.guest_state;
       regs.rax = guest_state.rax;
       regs.rbx = guest_state.rbx;
       regs.rcx = guest_state.rcx;
       regs.rdx = guest_state.rdx;
       regs.rsi = guest_state.rsi;
       regs.rdi = guest_state.rdi;
       regs.rsp = guest_state.rsp;
       regs.rbp = guest_state.rbp;
       regs.r8  = guest_state.r8;
       regs.r9  = guest_state.r9;
       regs.r10 = guest_state.r10;
       regs.r11 = guest_state.r11;
       regs.r12 = guest_state.r12;
       regs.r13 = guest_state.r13;
       regs.r14 = guest_state.r14;
       regs.r15 = guest_state.r15;
       regs.rip = guest_state.rip;
       regs.rflags = vmcs_read64(VmcsField::GUEST_RFLAGS);       
   }
}
/*
fn vmx_update_host(vmx_state: &mut VmxState, host_rsp: u64) {
    vmx_state.host_state.rsp = host_rsp;
    vmcs_write64(VmcsField::HOST_RSP, host_rsp);
}
*/
extern "C" {
    fn _vmx_vcpu_run(vmx_state: &mut VmxState, launched: bool) -> u64;
}

global_asm!(
    "
.global _vmx_vcpu_run
_vmx_vcpu_run:
    push   rbp
    mov    rbp,rsp
    push   r15
    push   r14
    push   r13
    push   r12
    push   rbx
    push   rdi
    mov    rsi,rbx
//    lea    rsi, -0x8[rsp]

    mov    rax,[rsp]
    test   bl,bl
    mov    rcx,0x8[rax]
    mov    rdx,0x10[rax]
    mov    rbx,0x18[rax]
    mov    rbp,0x28[rax]
    mov    rsi,0x30[rax]
    mov    rdi,0x38[rax]
    mov    r8,0x40[rax]
    mov    r9,0x48[rax]
    mov    r10,0x50[rax]
    mov    r11,0x58[rax]
    mov    r12,0x60[rax]
    mov    r13,0x68[rax]
    mov    r14,0x70[rax]
    mov    r15,0x78[rax]
    mov    rax,[rax]

    je 3f
   vmresume
    jmp 4f
3: vmlaunch
4:
    jbe    2f
    push   rax
    mov    rax,0x8[rsp]
//  pop   [rax]
    pop    rcx
    mov    [rax],rcx
    mov    0x8[rax],rcx
    mov    0x10[rax],rdx
    mov    0x18[rax],rbx
    mov    0x28[rax],rbp
    mov    0x30[rax],rsi
    mov    0x38[rax],rdi
    mov    0x40[rax],r8
    mov    0x48[rax],r9
    mov    0x50[rax],r10
    mov    0x58[rax],r11
    mov    0x60[rax],r12
    mov    0x68[rax],r13
    mov    0x70[rax],r14
    mov    0x78[rax],r15
    xor    eax,eax
1:  xor    ecx,ecx
    xor    edx,edx
    xor    ebx,ebx
    xor    ebp,ebp
    xor    esi,esi
    xor    edi,edi
    xor    r8d,r8d
    xor    r9d,r9d
    xor    r10d,r10d
    xor    r11d,r11d
    xor    r12d,r12d
    xor    r13d,r13d
    xor    r14d,r14d
    xor    r15d,r15d
    add    rsp, 0x8
    pop    rbx
    pop    r12
    pop    r13
    pop    r14
    pop    r15
    pop    rbp
    ret
2:  mov    eax, 0x1
    jmp    1b
"
);
