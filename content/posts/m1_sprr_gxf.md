---
title: "Apple Silicon Hardware Secrets: SPRR and Guarded Exception Levels (GXF)"
date: 2021-05-06T07:48:41+02:00
draft: false
summary: "Apple's new M1 SoC contains interesting and undocumented new hardware features. SPRR allows redefining the
meaning of pagetable permission bits and GXF introduces lateral execution levels. This post explores these new features
and documents how Apple uses them to protect macOS against attacks."

---


# Introduction

Over a year ago [siguza](https://twitter.com/s1guza) published a [write-up about Apple's
APRR](https://siguza.github.io/APRR/) - a custom ARM extension that redefines pagetable permissions and protects certain parts of
the kernel from itself. Since then Apple has released their M1 chip
which not only features an updated version of APRR but also easily allows to run bare-metal code shortly after boot.
There have been [some](https://twitter.com/s1guza/status/1355929535699681284) [rumors](https://threedots.ovh/blog/2021/02/notes-on-the-new-xnu-source-release/)
about the new version but nothing specific has been (publicly) documented yet.

Time to change that!


The first part of this post is a very brief introduction to memory management, pagetables, and user/kernel mode on
aarch64. It'll also summarize APRR which is the equivalent feature on previous Apple SoCs. You'll be bored if
you are already aware of these and should probably just skip the beginning.

Then we can finally get to the major part: Reverse engineering how SPRR and GXF work and what they do. This part will be
interesting to you if you want to learn *how* I approached this challenge. If you on the other hand only want to
understand *what* SPRR and GXF are feel free to head over to the [Asahi Linux wiki](https://github.com/AsahiLinux/docs/wiki/HW:-SPRR-and-GXF) directly!


## MMUs, pagetables, and kernels

On ARM the CPU runs in what is called [exception levels](https://developer.arm.com/documentation/102412/0100/Privilege-and-Exception-levels).
If you're familiar with x86 these are called rings instead.
EL0 is userspace where applications run, EL1 is (usually) where the kernel itself runs and EL2 is where a hypervisor runs.
(There is also EL3 for firmware or Trust Zone but the M1 doesn't have that level)

On ARM64 CPUs with [Virtualization Host Extensions](https://developer.arm.com/documentation/102142/latest/Virtualization-Host-Extensions)
there's also a way to make EL2 look like EL1 such that a kernel can easily run there as well.

One of the kernel's tasks is to lie to each application running in userland and to tell them that they're the only
one in the address space. It does that by using the memory management unit. The MMU allows creating an alias from a virtual address to a
real physical address in e.g. RAM. The smallest granularity of this mapping is called a page which is usually 4KiB large.
Each page has a virtual address and a physical address. When an instruction
of an application or the kernel itself now tries to access memory at location `x` the MMU looks up the page in its pagetable
and instead returns memory from another address `y`. And that's how the kernel can give each userland application its
own separate address space: It just creates a different set of pagetables for each process.

In addition to this mapping, each page also contains four bits that encode certain access flags. These flags determine
if it's possible to read from a page, write to a page or execute code from a page for a userland application or the kernel
itself. The following four bits can be found in each pagetable entry on [ARMv8-A CPUs](https://developer.arm.com/documentation/100940/0101):

* *UXN*, Unprivileged Execute never: Never allow userland (EL0) code to execute from this page
* *PXN*, Privileged execute never: Never allow kernel (EL1) code to execute from this page
* *AP0* and *AP1*: These are just a slightly confusing way to encode four different write and read access settings for kernel and userland `rw/--`, `rw/rw`, `r-/--` and `r-/r-`.

There's also some additional complexity related to determining the final access flags (PAN, hierarchical control) which
I'll ignore for this blog post. One thing to note here is that userland and kernel permissions are tightly coupled.
It's impossible to create a page that's `rw-` in userland but `r-` for the kernel.


## APRR

As mentioned, there are four flags for each page that control the access permissions (read/write/execute) for EL0/1
(user/kernel mode). APRR changes this behavior completely: Instead of storing the four flags as bits inside the page
table entry, the four bits are repurposed as an index to a separate table (i.e. instead of encoding access permissions directly
the bits are merged into a 4 bit index as [AP1][AP0][PXN][UXN]). This separate table then encodes the actual
permissions of the pages. Additionally, some registers allow to further restrict these permissions for
userspace. These registers are also separate for kernel and userland and allow much flexibility when creating page
permissions.

APRR introduces a layer of indirection to pagetable permissions this way which allows to very efficiently flip the access
permissions of *many* pages at once with a single register write. Usually, this would require a rather expensive page walk
to modify all individual entries.

More details are available in [siguza's excellent write-up](https://siguza.github.io/APRR/).


## Just-In-Time Compilers

Usually, applications are compiled from a higher language to machine code which is then distributed. The code can easily
be mapped as `r-x` since it's fixed and usually won't be modified during runtime anymore.

A JIT compiler on the other hand dynamically generates machine code. Traditionally, this requires mapping a memory region
as `rwx` such that new code can first be written and then executed.

Apple really doesn't want to allow such mappings though since they ideally want to sign every single instruction
that the CPU executes on their iPhones. If any application could just request an `rwx` mapping that whole exercise would be pointless: That application
could just run any instructions it wants. Even if only some applications were entitled to such mapping those would become targets
for exploits: Once an `rwx` mapping exists somewhere all that's required is to write the shellcode there and jump to it. (Locating such
regions and getting an arbitrary write and jump gadget will still be challenging of course).


Apple wants to have a JIT compiler though. Or, well, they really have no choice. They *need* a JIT compiler because [Javascript](https://en.wikipedia.org/wiki/JavaScript_engine) exists.

How can this be solved? By using APRR of course. Certain userland applications (Safari on iOS, every application on macOS) are
capable of requesting a special memory region (using [`mmap` with `MAP_JIT` and `pthread_jit_write_protect_np`](https://developer.apple.com/documentation/apple-silicon/porting-just-in-time-compilers-to-apple-silicon)[^1]) that can be quickly switched between `rw-` and `r-x`.
Behind the scenes, this switch flips two bits inside an APRR register to strip `x` instead of `w` from the JIT pages
which immediately changes *all* those pages from `rw-` to `r-x` or vice versa.



[^1]: According to [saagarjha](https://twitter.com/_saagarjha/status/1390273346072240134) Safari actually uses `os_thread_self_restrict_rwx_to_r{w,x}` which likely has the same effect though



## Page Protection Layer

As previously mentioned, Apple wants to enforce code signing on all executable pages if possible. On iOS, these
signatures must come from Apple itself while on macOS ad-hoc signatures that can be created locally are enough.
Code signing is usually enforced by the kernel. The kernel also has a *lot* of unrelated code though like device
drivers, making for a huge attack surface. Any bug in any driver is enough to bypass code signing (This is not
entirely true since you probably need an infoleak to then ROP your way to writing pagetables). This issue has already
been solved by video game consoles a long time ago: [Microsoft's Xbox 360 hypervisor](https://free60project.github.io/wiki/Hypervisor/) was a tiny piece of code that
essentially only enforced code signatures and equally important tasks. Instead of ensuring that no exploitable
bugs are present in *all* kernel code, it's enough to ensure that no critical bugs are present in the hypervisor itself.
Only [one critical bug](https://seclists.org/fulldisclosure/2007/Feb/613) was ever found in that hypervisor.

Similarly, Apple uses APRR to effectively create a very low-overhead hypervisor inside the kernel itself. First, the pagetables (and other
memory with important data structures) are remapped as read-only to the kernel itself. Additionally, a small section of
privileged code, called PPL, is also mapped as read-only. A small trampoline function then uses APRR to remap the pagetables as
`rw-` and the PPL code as `r-x` before jumping there. As this small trampoline is the only entry point to PPL code it
behaves like a hypercall instruction while PPL itself acts like a very low-overhead hypervisor.

More details about this can be found in [Jonathan's Casa De P(a)P(e)L
write up](http://newosxbook.com/articles/CasaDePPL.html).

# SPRR

## Userland JIT

As previously explained, JITs on Apple Silicon can allocate a special region whose permissions can be quickly switched
between `rw-` and `r-x`. In previous SoCs, this was enforced using APRR and should provide a good starting point for
looking into SPRR. 

[Apple's official documentation regarding Just-in-Time
Compilers](https://developer.apple.com/documentation/apple-silicon/porting-just-in-time-compilers-to-apple-silicon)
leads to the `_pthread_jit_write_protect_np` function which still performs this switch on the M1. 
Let's first use ` otool -xv /usr/lib/system/libsystem_pthread.dylib` to figure out what happens behind the scenes.
The relevant instructions from this function

```
_pthread_jit_write_protect_np:
[...]
0000000000007fdc        movk    x0, #0xc118
0000000000007fe0        movk    x0, #0xffff, lsl #16
0000000000007fe4        movk    x0, #0xf, lsl #32
0000000000007fe8        movk    x0, #0x0, lsl #48
0000000000007fec        ldr     x0, [x0]                ; Latency: 4
0000000000007ff0        msr     S3_6_C15_C1_5, x0
0000000000007ff4        isb
[...]
```

load a 64bit integer from the constant address `0xfffffc118` and then write it to the system register
identified as `S3_6_C15_C1_5`. There is similar code further down that instead loads the new system register value
from `0xfffffc110`. These addresses belong to a region known as commpage. This page is mapped into every userland
process and contains various variables exposed by the kernel to userland. 

Unsurprisingly, the code that sets up these variables inside the commpage is missing from the [open source XNU
code](https://github.com/apple/darwin-xnu/blob/main/osfmk/arm/commpage/commpage.c#L86). However, there are references to
`cp_aprr_shadow_jit_rw` used by the previous generation APRR code left in the [XNU 
code](https://github.com/apple/darwin-xnu/blob/main/osfmk/arm/cpu_x86_64_capabilities.h#L146).

Dumping these with a small c program
```c
#include <stdio.h>
#include <stdint.h>

int main(int argc, char *argv[])
{
  uint64_t *sprr = (uint64_t *)0xfffffc110;
  printf("%llx %llx\n", sprr[0], sprr[1]);
}
```
yields the values `0x2010000030300000` and `0x2010000030100000` which switch between `r-x` and `rw-` permissions of
JIT pages. So far so good. This is similar to how APRR used to work but these are different registers and they contain
different magic numbers that we will have to demystify.

With this rough idea about SPRR, we could now disassemble the kernel and look for functions that use these or
nearby registers. I don't quite enjoy staring at disassembly as much as I used to though. (But then again I do enjoy
low-level hardware reverse engineering so maybe you shouldn't trust me when it comes to fun).  It's also unlikely that the
kernel will lead us to the meaning of the individual bits: The registers are probably just initialized once with a magic constant and never touched again.

Luckily there's another alternative: ~~Un~~educated Guesswork! 
Try to flip bits in the register we found and see how it behaves. And we can even start that from a regular userspace program
running on the M1!

The first thing we can do is to try and set every bit to 0 and 1:

```c
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>


void write_sprr(uint64_t v)
{
    __asm__ __volatile__("msr S3_6_c15_c1_5, %0\n"
                         "isb sy\n" ::"r"(v)
                         :);
}

uint64_t read_sprr(void)
{
    uint64_t v;
    __asm__ __volatile__("isb sy\n"
                         "mrs %0, S3_6_c15_c1_5\n"
                         : "=r"(v)::"memory");
    return v;
}


int main(int argc, char *argv[])
{
    for (int i = 0; i < 64; ++i) {
        write_sprr(1ULL<<i);
        printf("bit %02d: %016llx\n", i, read_sprr());
    }
}
```

We quickly observe that almost all bits are locked to their initial value except for the two that are different in the
two values we found in the commpage. We also know that these are somehow related to JIT page permissions. We can map such
pages using `mmap`. Reading from or writing to a read- or write-protected page generates a `SIGBUS`. Jumping to a
non-executable page results in a `SIGSEV`. We can catch signals in userland applications by setting up signal handlers. These tools are
all we need to understand how these bits map to page permissions!

In order to recover from accessing a protected page, we set up the following signal handler which will set `x0` to a magic
constant and then increment the program counter before returning:

```c
void bus_handler(int signo, siginfo_t *info, void *cx_)
{
    ucontext_t *cx = cx_;
    cx->uc_mcontext->__ss.__x[0] = 0xdeadbeef;
    cx->uc_mcontext->__ss.__pc += 4;
}
```

Recovering from executing a non-executable page works similarly: Set the program counter to the link register to return
to the callee and store a magic value in `x0`:

```c
void sev_handler(int signo, siginfo_t *info, void *cx_)
{
    ucontext_t *cx = cx_;
    cx->uc_mcontext->__ss.__x[0] = 0xdeadbeef;
    cx->uc_mcontext->__ss.__pc = cx->uc_mcontext->__ss.__lr;
}
```

All that's left to do is map a page with `MAP_JIT` and try to read, write or execute that memory for all four possible
values in the system register.

<aside>
<details>
<summary>
SPRR JIT test code
</summary>

```c
#define _XOPEN_SOURCE
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <ucontext.h>

static void sev_handler(int signo, siginfo_t *info, void *cx_)
{
    (void)signo;
    (void)info;
    ucontext_t *cx = cx_;
    cx->uc_mcontext->__ss.__x[0] = 0xdeadbeef;
    cx->uc_mcontext->__ss.__pc = cx->uc_mcontext->__ss.__lr;
}

static void bus_handler(int signo, siginfo_t *info, void *cx_)
{
    (void)signo;
    (void)info;
    ucontext_t *cx = cx_;
    cx->uc_mcontext->__ss.__x[0] = 0xdeadbeef;
    cx->uc_mcontext->__ss.__pc += 4;
}

static void write_sprr_perm(uint64_t v)
{
    __asm__ __volatile__("msr S3_6_c15_c1_5, %0\n"
                         "isb sy\n" ::"r"(v)
                         :);
}

static uint64_t read_sprr_perm(void)
{
    uint64_t v;
    __asm__ __volatile__("isb sy\n"
                         "mrs %0, S3_6_c15_c1_5\n"
                         : "=r"(v)::"memory");
    return v;
}

static bool can_read(void *ptr)
{
    uint64_t v = 0;

    __asm__ __volatile__("ldr x0, [%0]\n"
                         "mov %0, x0\n"
                         : "=r"(v)
                         : "r"(ptr)
                         : "memory", "x0");

    if (v == 0xdeadbeef)
        return false;
    return true;
}

static bool can_write(void *ptr)
{
    uint64_t v = 0;

    __asm__ __volatile__("str x0, [%0]\n"
                         "mov %0, x0\n"
                         : "=r"(v)
                         : "r"(ptr + 8)
                         : "memory", "x0");

    if (v == 0xdeadbeef)
        return false;
    return true;
}

static bool can_exec(void *ptr)
{
    uint64_t (*fun_ptr)(uint64_t) = ptr;
    uint64_t res = fun_ptr(0);
    if (res == 0xdeadbeef)
        return false;
    return true;
}

static void sprr_test(void *ptr, uint64_t v)
{
    uint64_t a, b;
    a = read_sprr_perm();
    write_sprr_perm(v);
    b = read_sprr_perm();

    printf("%llx: %c%c%c\n", b, can_read(ptr) ? 'r' : '-', can_write(ptr) ? 'w' : '-',
           can_exec(ptr) ? 'x' : '-');
}

static uint64_t make_sprr_val(uint8_t nibble)
{
    uint64_t res = 0;
    for (int i = 0; i < 16; ++i)
        res |= ((uint64_t)nibble) << (4 * i);
    return res;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    struct sigaction sa;
    sigfillset(&sa.sa_mask);
    sa.sa_sigaction = bus_handler;
    sa.sa_flags = SA_RESTART | SA_SIGINFO;
    sigaction(SIGBUS, &sa, 0);
    sa.sa_sigaction = sev_handler;
    sigaction(SIGSEGV, &sa, 0);

    uint32_t *ptr = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
    write_sprr_perm(0x3333333333333333);
    ptr[0] = 0xd65f03c0; // ret

    for (int i = 0; i < 4; ++i)
        sprr_test(ptr, make_sprr_val(i));
}
```

</aside>

This gives us the following table

| register value | page permissions |
|----------------|------------------|
| 00 | `---` |
| 01 | `r-x` |
| 10 | `r--` |
| 11 | `rw-`  |

This is much simpler than how APRR works: Instead of using two registers to first set permissions and then masking others,
we can now only change them to one of these four values. APRR also allowed a [clever hack](https://gist.github.com/saagarjha/d1ddd98537150e4a09520ed3ede54f5e) to create `rwx` mappings in userspace which is no longer possible
since there's just no way to encode that. Presumably, the different bytes in the system register correspond to the 16
different possible permissions encoded in the page table entries. That leaves the meaning of half of the system register
completely unknown!

We've probably figured out all we could from macOS userspace now though and it's time to bring out some heavier tools to
really understand how this new hardware feature works.

I was hoping that I could just use Apple's Hypervisor.framework to run my code in EL1 and investigate how SPRR
behaves from there. But, unfortunately, every access to registers probably related to SPRR always faulted. Oh
well. Luckily we have more powerful tools at our disposal to run code in EL2 on the "bare metal" instead.

## m1n1

Previously iPhone hackers had to either statically reverse engineer XNU or exploit their way up to EL1 to then run their
experiments to understand new hardware. This makes all their achievements even more impressive. These days, however, our
lives are much more straightforward: Apple has released the M1 which shares many of these new hardware additions and also allows
anyone to run unsigned code very early on in the boot process.

As part of the [Asahi Linux project](https://asahilinux.org), which aims to introduce upstream Linux support for the M1, marcan had led the
development of a small bootloader / hardware experimentation platform called [m1n1](https://github.com/AsahiLinux/m1n1).
m1n1 gets control at the same time as XNU usually does with all hardware left in a pristine state. While all of the
following work could also be done by manually writing shellcode to be run in EL2 m1n1 actually makes this fun (if you
trust my definition of fun, anyway).


## Discovering unknown system registers from Python

The best aspect of m1n1 is that we can directly manipulate the hardware from a python shell instead of recompiling and reloading shellcode and handling data extractions and all of these annoying little details. marcan has also
recently merged my USB gadget code such that all you need to repeat these experiments is a M1 Mac and a normal USB
cable.

Let's start by running `proxyclient/shell.py`. 
Unfortunately accessing the userland SPRR register just triggers an exception though. (but notice how m1n1 quickly recovers
from this exception in EL2. There's no need to reboot afterwards!)

```python
>>> u.mrs((3, 6, 15, 1, 5))
TTY> Exception: SYNC
TTY> Exception taken from EL2h
TTY> Running in EL2
TTY> MPIDR: 0x80000000
TTY> Registers: (@0x8046b3db0)
TTY>   x0-x3: 0000000000000000 0000000000000000 0000000000000000 0000000000000000
TTY>   x4-x7: 0000000810cb8000 0000000000007a69 0000000804630004 0000000804630000
TTY>  x8-x11: 0000000000000000 00000000ffffffc8 00000008046b3eb0 000000000000002c
TTY> x12-x15: 0000000000000003 0000000000000001 0000000000000000 00000008046b3b20
TTY> x16-x19: 00000008045caa80 0000000000000000 0000000000000000 000000080462b000
TTY> x20-x23: 00000008046b3f78 00000008046b3fa0 0000000000000002 00000008046b3f98
TTY> x24-x27: 00000008046b3f70 0000000000000000 0000000000000001 0000000000000001
TTY> x28-x30: 00000008046b3fa0 00000008046b3eb0 00000008045bad90
TTY> PC:       0x810cb8000 (rel: 0xc70c000)
TTY> SP:       0x8046b3eb0
TTY> SPSR_EL1: 0x60000009
TTY> FAR_EL1:  0x0
TTY> ESR_EL1:  0x2000000 (unknown)
TTY> L2C_ERR_STS: 0x11000ffc00000000
TTY> L2C_ERR_ADR: 0x0
TTY> L2C_ERR_INF: 0x0
TTY> SYS_APL_E_LSU_ERR_STS: 0x0
TTY> SYS_APL_E_FED_ERR_STS: 0x0
TTY> SYS_APL_E_MMU_ERR_STS: 0x0
TTY> Recovering from exception (ELR=0x810cb8004)
Traceback (most recent call last):
  File "/opt/homebrew/Cellar/python@3.9/3.9.4/Frameworks/Python.framework/Versions/3.9/lib/python3.9/code.py", line 90, in runcode
    exec(code, self.locals)
  File "<console>", line 1, in <module>
  File "/Users/speter/asahi/git/m1n1/proxyclient/utils.py", line 80, in mrs
    raise ProxyError("Exception occurred")
proxy.ProxyError: Exception occurred
>>>
```

The kernel must be able to modify this register during context switches though. This likely means that there is some enable bit.
Luckily there's already a [python tool in the m1n1 repository which
allows to find all available system
registers](https://github.com/AsahiLinux/m1n1/blob/main/proxyclient/find_all_regs.py). Internally it just generates `mrs` instructions for all of them and
recovers from exceptions caused by undefined registers. We just run it and look for any nearby registers:


```bash
$ python3 proxyclient/find_all_regs.py | grep s3_6_c15_c1_
s3_6_c15_c1_0 (3, 6, 15, 1, 0) = 0x0
s3_6_c15_c1_2 (3, 6, 15, 1, 2) = 0x0
s3_6_c15_c1_4 (3, 6, 15, 1, 4) = 0x0
```

This gives us three candidates. ~~Writing 0x1 to the first one seems to stop m1n1 from working. Now this should've been
obvious to me:  m1n1 runs from pages with `rwx` permissions. The SPRR registers start out at `0x0` which means
`---` or no access at all. What happens if SPRR suddenly kicks in and makes the CPU believe `rwx` actually is `---`?
Everything breaks because there's no memory it can read or execute left. Finding that issue totally didn't take the 
better part of my weekend...~~

Anyway.

We disable the MMU, write all ones to each of those (and quickly notice that the third one seems to
just fault and ignore it), find all registers again, and finally identify new ones. This can all be done in a few lines of python code:

```python
with u.mmu_disabled():
    for reg in [(3, 6, 15, 1, 0), (3, 6, 15, 1, 2)]:
        old_regs = find_regs()
        u.msr(reg, 1)
        new_regs = find_regs()

        diff_regs = new_regs - old_regs

        print(reg)
        for r in sorted(diff_regs):
            print("  %s" % list(r))

    u.msr((3, 6, 15, 1, 2), 0)
    u.msr((3, 6, 15, 1, 0), 0)
```

And oh boy, are there a lot of new register we've just enabled this way:

<aside>
<details>
<summary>
Enabled system registers
</summary>

```
(3, 6, 15, 1, 0)
  [3, 4, 15, 5, 1]
  [3, 4, 15, 5, 2]
  [3, 4, 15, 7, 0]
  [3, 4, 15, 7, 1]
  [3, 4, 15, 7, 2]
  [3, 4, 15, 7, 3]
  [3, 4, 15, 7, 4]
  [3, 4, 15, 7, 5]
  [3, 4, 15, 7, 6]
  [3, 4, 15, 7, 7]
  [3, 4, 15, 8, 0]
  [3, 4, 15, 8, 1]
  [3, 4, 15, 8, 2]
  [3, 4, 15, 8, 3]
  [3, 4, 15, 8, 4]
  [3, 4, 15, 8, 5]
  [3, 4, 15, 8, 6]
  [3, 4, 15, 8, 7]
  [3, 6, 15, 1, 3]
  [3, 6, 15, 1, 5]
  [3, 6, 15, 1, 6]
  [3, 6, 15, 1, 7]
  [3, 6, 15, 3, 0]
  [3, 6, 15, 3, 1]
  [3, 6, 15, 3, 2]
  [3, 6, 15, 3, 3]
  [3, 6, 15, 3, 4]
  [3, 6, 15, 3, 5]
  [3, 6, 15, 3, 6]
  [3, 6, 15, 3, 7]
  [3, 6, 15, 4, 0]
  [3, 6, 15, 4, 1]
  [3, 6, 15, 4, 2]
  [3, 6, 15, 4, 3]
  [3, 6, 15, 4, 4]
  [3, 6, 15, 4, 5]
  [3, 6, 15, 4, 6]
  [3, 6, 15, 4, 7]
  [3, 6, 15, 5, 0]
  [3, 6, 15, 5, 1]
  [3, 6, 15, 5, 2]
  [3, 6, 15, 5, 3]
  [3, 6, 15, 5, 4]
  [3, 6, 15, 5, 5]
  [3, 6, 15, 5, 6]
  [3, 6, 15, 5, 7]
  [3, 6, 15, 6, 0]
  [3, 6, 15, 6, 1]
  [3, 6, 15, 6, 2]
  [3, 6, 15, 6, 3]
  [3, 6, 15, 6, 4]
  [3, 6, 15, 6, 5]
  [3, 6, 15, 6, 6]
  [3, 6, 15, 6, 7]
  [3, 6, 15, 14, 3]
  [3, 6, 15, 15, 5]
  [3, 6, 15, 15, 7]
(3, 6, 15, 1, 2)
  [3, 1, 15, 8, 2]
  [3, 6, 15, 0, 3]
  [3, 6, 15, 8, 1]
  [3, 6, 15, 8, 2]
  [3, 6, 15, 9, 2]
  [3, 6, 15, 9, 3]
  [3, 6, 15, 9, 4]
  [3, 6, 15, 9, 5]
  [3, 6, 15, 9, 6]
  [3, 6, 15, 9, 7]
  [3, 6, 15, 10, 0]
  [3, 6, 15, 10, 1]
  [3, 6, 15, 12, 0]
  [3, 6, 15, 12, 1]
  [3, 6, 15, 15, 2]
  [3, 6, 15, 15, 3]
```

</details>
</aside>


Let's rename `S3_6_C15_C1_0` to `SPRR_CONFIG_EL1`. Bit 1 in there enables SPRR and setting all bits seems to lock
down all SPRR registers for further changes. `S3_6_C15_1_2` and the registers it enables will be important for part 2.


And we can now indeed flip all bits in `S3_6_C15_C1_5`:

```python
>>> p.mmu_shutdown()
TTY> MMU: shutting down...
TTY> MMU: shutdown successful, clearing cache
>>> u.msr((3, 6, 15, 1, 0), 1)
>>> u.mrs((3, 6, 15, 1, 5))
0x0
>>> u.msr((3, 6, 15, 1, 5), 0xffffffffffffffff)
>>> u.mrs((3, 6, 15, 1, 5))
0xffffffffffffffff
>>>
```

This register likely applies to EL0 though but we're running in EL2 here. We can make an educated guess and assume
that the newly enabled register `S3_6_C15_C1_6` is probably for EL1 and `S3_6_C15_C1_7` for EL2. The M1 always runs with
``HCR_EL2.E2H`` which (among other things) redirects access to EL1 registers to their EL2 counterparts. We can use this to verify
our guess:

```python
>>> u.msr((3, 6, 15, 1, 6), 0xdead0000)
>>> u.mrs((3, 6, 15, 1, 7))
0xdead0000
>>>
```

Looks good so far. SPRR can be enabled now and there's a suspicious register likely used for EL2 permissions. Time to repeat
the same experiments done from userland to understand more than just four bits of these registers. 


## Reverse engineering SPRR 

We can write some code in python to set up a simple pagetable for us and then essentially repeat the same experiment
we did in userland: Map a page for which we presumably know the permission byte in `S3_6_C15_C1_6` and then try to
read/write/execute memory from it.

Doing this entirely from Python would've only been possible with some invasive changes to m1n1 itself to make it run from
a `r-x` page and keep its stack in a `rw-` page.
It's much easier just to do as much setup work as possible in Python and then write some shellcode and run that on one of the other
cores. If one of them hangs there are still a few more left before a reboot is required.

```python
pagetable = ARMPageTable(heap.memalign, heap.free)
pagetable.map(0x800000000, 0x800000000, 0xc00000000, 0)   # normal memory, we run from here
pagetable.map(0xf800000000, 0x800000000, 0xc00000000, 1)  # probe memory, we'll try to read/write/execute this
# ...
code_page = build_and_write_code(heap, """
    // [...]
                // prepare and enable MMU
                ldr x0, =0x0400ff
                msr MAIR_EL1, x0
                ldr x0, =0x27510b510 // borrowed from m1n1's MMU code
                msr TCR_EL1, x0
                ldr x0, =0x{ttbr:x}
                msr TTBR0_EL1, x0
                mrs x0, SCTLR_EL1
                orr x1, x0, #5
                msr SCTLR_EL1, x1
                isb
    // [...]
""".format(ttbr=pagetable.l0)
# ...
ret = p.smp_call_sync(1, code_page, sprr_val)
# ...
```

What used to be a signal handler now becomes a small exception vector.  All we do in
there is modify a single register to indicate failure and then move the program counter two instructions further
before returning. The first instruction is the one that faulted which we don't want to run again. The second one would
be a `mov x10, 0x80` to indicate that the access was successful, which it wasn't if we hit an exception.

```asm
_fault_handler:
# store that we failed
mov x10, 0xf1

mrs x12, ELR_GL2  # get the PC that faulted
add x12, x12, 8   # skip two instructions
msr ELR_GL2, x12  # store the updated PC

isb
# eret restores the state from before the exception was taken
eret


_sprr_test:
# ...

# test read access, x1 contains an address to a page for which we modify the SPRR register values
mov x10, 0    # x10 is our success/failure indicator
ldr x1, [x1]  # this instruction will fault if we can't read from [x1]
mov x10, 0x80 # this instruction will be skipped if the previous one faulted
```


With all that we finally get the meaning of all 16 possible configurations:

| register value |page permissions |
|-|-|
| `0000` | `---` | 
| `0001` | `r-x` |
| `0010` | `r--` |
| `0011` | `rw-` |
| `0100` | `---` |
| `0101` | `r-x` |
| `0110` | `r--` |
| `0111` | `---` |
| `1000` | `---` |
| `1001` | `--x` |
| `1010` | `r--` |
| `1011` | `rw-` |
| `1100` | `---` |
| `1101` | `r-x` |
| `1110` | `r--` |
| `1111` | `rw-` |

Clearly, something is strange here: For the most part the lower two bits specify the permissions. But there are two
exceptions where the higher bits somehow change the permissions as well. `0111` seems to disallow access to a page that
should otherwise be `rw-` and `1001` should usually be readable and executable but is only executable.

There's no need to waste two more bits to encode this. At first this looks like it might be user vs. kernel permissions
with a strict enforcement of write-or-execute. But we know that EL0 uses an entirely different register. So what else could this be?


# Guarded Exception Levels / GXF

We know from the previous section that something strange is encoded in the PPR registers. There have been [some](https://twitter.com/qwertyoruiopz/status/1174787964100075521) [mentions](https://twitter.com/s1guza/status/1355929535699681284)
about [guarded exception levels](https://twitter.com/s1guza/status/1353749746951839748) which are lateral to the normal exception levels. Apparently, these are triggered by the
custom instructions `0x00201420` and `0x00201400` which are called `genter` and `gexit`.


Let's take XNU to a disassembler and see if we can find something suspicious using `otool -xv
/System/Library/Kernels/kernel.release.t8101`.
Looking for these instructions there's the following candidate which also happens to be called
early on during initialization:

```
fffffe00071f80f0        mov     x0, #0x1
fffffe00071f80f4        msr     S3_6_C15_C1_2, x0
fffffe00071f80f8        adrp    x0, 2025 ; 0xfffffe00079e1000
fffffe00071f80fc        add     x0, x0, #0x9d8
fffffe00071f8100        msr     S3_6_C15_C8_2, x0
fffffe00071f8104        adrp    x0, 2025 ; 0xfffffe00079e1000
fffffe00071f8108        add     x0, x0, #0x9dc
fffffe00071f810c        msr     S3_6_C15_C8_1, x0
fffffe00071f8110        isb
fffffe00071f8114        mov     x0, #0x0
fffffe00071f8118        msr     ELR_EL1, x0
fffffe00071f811c        isb
fffffe00071f8120        .long   0x00201420
fffffe00071f8124        ret
```

Remember `S3_6_C15_C1_2`? (Consider me impressed then because to me all these numbers just look the same.) That's the second enable register we found earlier and it's the first thing this snippet uses.
It then writes two pointers to unknown system registers and finally executes the undefined instruction `0x00201420`.
The first pointer is just an infinite loop but the second one points to a function which seems to also use the SPRR
register we have previously identified.

So probably `S3_6_C15_C8_1` contains a pointer to which the processor jumps once `0x00201420` is executed. The second
unknown instruction `0x00201420` seems to resume execution then. All this sounds very similar to how hypervisor calls work:
`0x00201420` corresponds to `smc` to trap to EL3 and `0x00201400` is `eret` which takes us back to EL2.
What's different is that there are no different pagetables for this new execution mode. Remember the unknown two
bits in the SPRR registers? What if these correspond to page permissions in GL2?

We can quickly verify this again with m1n1 by using the same approach as before: We setup exception vectors in guarded
execution mode and repeat the same experiments.

Uh. But how do we setup exception vectors in this new mode? Usually there is a register called `VBAR` for this. Let's just
take a quick look at the code pointed to by `S3_6_C15_C10_2`, which is one of the first registers XNU sets up after genter:

```
fffffe00079e0000        b       0xfffffe00079e15d0
fffffe00079e0004        nop
fffffe00079e0008        nop
fffffe00079e000c        nop
[...]
fffffe00079e007c        nop
fffffe00079e0080        b       0xfffffe00079e1000
fffffe00079e0084        nop
[...]
fffffe00079e00fc        nop
fffffe00079e0100        b       0xfffffe00079e11f0
fffffe00079e0104        nop
[...]
```

Phew, this suspiciously looks like an [exception vector table](https://developer.arm.com/documentation/100933/0100/AArch64-exception-vector-table)
which means `S3_6_C15_C10_2` is `VBAR_GL1`


~~All this then finally leads to the full permission table with all bits of the SPRR register demystified:~~

This almost works to find the full permission table. When jumping to code from EL2 while the SPRR register has
a value of `0100`, `0110` or `1111` the core seems to just crash. All these values represent a page that's clearly not
executable from EL2 but possibly executable from GL2. What if these faults vector to a different address for some
reason? To stop beating around the bush that's precisely what happens. These three particular faults use the system
register which XNU pointed to an infinite loop, i.e.

* Aborts where EL2 tries to jump to code that's only executable in GL2 go to `S3_6_C15_C8_2` (which I've called `GXF_ABORT_EL2`)
* Any other aborts from EL2 go to `VBAR_EL2`
* Any other aborts from GL2 go to `VBAR_GL2`

All this then finally leads to the full permission table with all bits of the SPRR register demystified:


| register value | EL page permissions | GL page permissions |
|-|-|-|
| `0000` | `---` | `---` | 
| `0001` | `r-x` | `---` |
| `0010` | `r--` | `---` |
| `0011` | `rw-` | `---` |
| `0100` | `---` | `r-x` |
| `0101` | `r-x` | `r-x` |
| `0110` | `r--` | `r-x` |
| `0111` | `---` | `r-x` |
| `1000` | `---` | `r--` | 
| `1001` | `--x` | `r--` | 
| `1010` | `r--` | `r--` | 
| `1011` | `rw-` | `r--` | 
| `1100` | `---` | `rw-` | 
| `1101` | `r-x` | `rw-` | 
| `1110` | `r--` | `rw-` | 
| `1111` | `rw-` | `rw-` | 

Let's also take a detailed look at the two special cases where the GL permissions bits modify the meaning of the EL
permission bits:

* The first one (0111) ensures that it is impossible to create a page that is executable in GL and writable from EL.
  This provides an additional hardware layer protection against software mistakes. Being able to change code running in
  GL from EL would render the whole lateral level pointless.
* The second one (1001) replaces `r-x` EL permissions with `--x` permissions if the page is only readable from GL. I'm
  not sure why this is enforced. Maybe to be able to hide some secret code from EL or as some additional mitigation
  against an exploit that I'm not familiar with? I'd love to hear if anyone has a good reason for why such a
  mapping would be helpful.  

## Probing GL2 with Python 

Equipped with this knowledge we can now easily add support for running custom payloads in GL2 to m1n1.
All we need to do is leverage the framework that already exists to drop to EL1/EL0. We just need to disable the MMU
(because m1n1 assumes it's running from `rwx` pages that we can't do with SPRR enabled), jump to the payload, and finally
enable the MMU again before returning.

This allows to easily probe GL2 to figure out e.g. that `S3_6_C15_C10_3` probably is `SPSR_GL2`:
```
>>> u.mrs((3, 6, 15, 10, 3), call=p.gl_call)
0x60000009
>>> u.mrs(SPSR_EL2)
0x60000009
```

Or we can just rerun the MSR finder but this time in GL2:


```python
gxf_regs = find_regs(call=p.gl_call)

print("GXF")
for r in sorted(gxf_regs - all_regs):
    print("  %s" % list(r))
```

and discover a whole bunch of mysterious new system registers only available from that context:

```
GXF
  [3, 6, 15, 0, 1]
  [3, 6, 15, 0, 2]
  [3, 6, 15, 1, 1]
  [3, 6, 15, 2, 6]
  [3, 6, 15, 8, 5]
  [3, 6, 15, 8, 7]
  [3, 6, 15, 10, 2]
  [3, 6, 15, 10, 3]
  [3, 6, 15, 10, 4]
  [3, 6, 15, 10, 5]
  [3, 6, 15, 10, 6]
  [3, 6, 15, 10, 7]
  [3, 6, 15, 11, 1]
  [3, 6, 15, 11, 2]
  [3, 6, 15, 11, 3]
  [3, 6, 15, 11, 4]
  [3, 6, 15, 11, 5]
  [3, 6, 15, 11, 6]
  [3, 6, 15, 11, 7]
```

Maybe the ones starting with `3, 6, 15, 10` are for GL1 and those starting with `3, 6, 15, 11` for GL2 or vice versa?
That's easy to figure out. Just drop to EL1 after enabling SPRR and GXF in EL2 and rerun the same experiment.
This time we only get the following new registers:

```
  [3, 6, 15, 0, 1]
  [3, 6, 15, 8, 7]
  [3, 6, 15, 10, 1]
  [3, 6, 15, 10, 2]
  [3, 6, 15, 10, 3]
  [3, 6, 15, 10, 4]
  [3, 6, 15, 10, 5]
  [3, 6, 15, 10, 6]
  [3, 6, 15, 10, 7]
```

which means that the `3, 6, 15, 10` group indeed represents the EL1 registers.  Not that this matters much: The M1 is
always running with `HCR_EL2.E2H` which means that `_EL1` registers are redirected to `_EL2` when running in EL2. The
same seems to apply for `GL1` and `GL2` registers as well.

Can we figure out what they exactly mean as well? Luckily an older [open source XNU
release](https://github.com/apple/darwin-xnu/blob/62e8fb1273a17d605112cc7db62e847e399a7c66/osfmk/arm64/exception_asm.h#L40) contained some names:

```c
#define KERNEL_MODE_ELR      ELR_GL11
#define KERNEL_MODE_FAR      FAR_GL11
#define KERNEL_MODE_ESR      ESR_GL11
#define KERNEL_MODE_SPSR     SPSR_GL11
#define KERNEL_MODE_ASPSR    ASPSR_GL11
#define KERNEL_MODE_VBAR     VBAR_GL11
#define KERNEL_MODE_TPIDR    TPIDR_GL11
 ```

It's unclear to me why these registers have the `GL11` suffix but they otherwise can be easily matched up with the
unknown registers found above. ASPSR contains at least a bit that determines if gexit should return to guarded execution
or normal execution.

There are still a lot of unknown registers and mysteries left even for just these two extensions. If you want to play
along grab the latest m1n1 and see what you can figure out :-)

# SPRR & GXF inside XNU

And finally it's time to take a brief look at how XNU uses these new features. There's actually not much to look at since,
thanks to the great write up by Jonathan, it's already pretty obvious how SPRR and GXF are used: SPRR just replaces what
used to be APRR's task: Disallow the kernel from writing to pagetables and disallow execution of the PPL code.

The significant difference will be GXF: Instead of carefully crafting a small trampoline function that changes the APRR registers all
that's required is to setup the GXF entry vector. Then, the pagetable permissions will be flipped automatically and genter
can directly point into PPL. 


Let's confirm this by looking at how XNU initialized SPRR: 
The start function briefly enables SPRR to initialize the EL1 SPRR permission register to `0x2020A505F020F0F0`. This
code sequence is entangled with all the CPU chicken bits and even originally made its way into [the first experiments
inside  m1n1](https://github.com/AsahiLinux/m1n1/blob/main/proxyclient/chickens.py#L60). marcan even correctly
guessed what those writes are and stripped them from the actual chicken bits sequence.

A little bit later the initial GL bootstrap code then updates EL1 permissions to `0x2020A506F020F0E0` before locking everything
down to prevent further changes.


The guarded execution mode entry point is then set to a function from the normal kernel text region which quickly jumps
to the beginning of `PPLTEXT`. The PPL entry function verifies that the SPRR permissions are
set up correctly and then behaves as described in Jonathan's write up.

Let's also take a final look at the various SPRR page permissions that are used by XNU (entries not shown here are no
access for all levels. the original value set during the chicken bits sequence gives the GL permissions to EL as well):

  <table>
    <thead>
      <th>index</th>
      <th colspan="2">normal permissions</th>
      <th colspan="3">SPRR permissions</th>
      <th>usage</th>
    </thead>
    <thead>
      <th></th>
      <th>EL0</th>
      <th>EL2</th>
      <th>EL0</th>
      <th>EL2</th>
      <th>GL2</th>
      <th></th>
    </thead>



<tr><td>1</td><td><code>--x</code></td><td><code>rw-</code></td><td><code>---</code></td><td><code>r--</td><td><code>rw-</code></td><td>pagetables</tr>
<tr><td>3</td><td><code>---</code></td><td><code>rw-</code></td><td><code>---</code></td><td><code>rw-</td><td><code>rw-</code></td><td>kernel data</td></tr>
<tr><td>5</td><td><code>rw-</code></td><td><code>rwx</code></td><td><code>rw-</code><br><code>r-x</code></td><td><code>r--</td><td><code>---</code></td><td>userland MAP_JIT</td></tr>
<tr><td>7</td><td><code>rw-</code></td><td><code>rw-</code></td><td><code>rw-</code></td><td><code>rw-</td><td><code>rw-</code></td><td>userland data</td></tr>
<tr><td>8</td><td><code>--x</code></td><td><code>r-x</code></td><td><code>---</code></td><td><code>r--</td><td><code>r-x</code></td><td>PPL code</td></tr>
<tr><td>10</td><td><code>---</code></td><td><code>r-x</code></td><td><code>---</code></td><td><code>r-x</td><td><code>r-x</code></td><td>kernel code</td></tr>
<tr><td>11</td><td><code>---</code></td><td><code>r--</code></td><td><code>---</code></td><td><code>r--</td><td><code>r--</code></td><td>kernel readonly data</td></tr>
<tr><td>13</td><td><code>r-x</code></td><td><code>r--</code></td><td><code>r-x</code></td><td><code>r--</td><td><code>---</code></td><td>userland code</td></tr>
<tr><td>15</td><td><code>r--</code></td><td><code>r--</code></td><td><code>r--</code></td><td><code>r--</td><td><code>---</code></td><td>userland readonly data</td></tr>

  </table>


This all looks pretty reasonable. The GL permissions could probably be further locked down by e.g. disallowing GL to
execute regular kernel code (entry 10) and disallowing it access to any user data (entry 7).

Other than that this feels like a neat increment of the previous APRR hardware: The changes not only make the whole
system less prone to errors (the registers can be locked down, the kernel->PPL transition happens entirely in hardware
and the kernel and PPL exception vectors are clearly separated now) but also more flexible. APRR used to only strip
permissions but SPRR now allows to arbitrarily remap permissions as long as no `rwx` pages are desired. It's almost a
pity that there's no good use for this in Linux :-)


# tl;dr

Apple Silicon has two "secret" features that work hand-in-hand as an additional mitigation against attacks.
GXF introduces lateral exception levels, called GL1 and GL2, which use the same pagetables as the corresponding EL but
with different page permissions. SPRR allows to redefine what the permissions bits in pagetable entries mean for EL and
GL. Apple uses this to hide all pagetable manipulation code in GL and to disallow EL to modify any pagetables. This
effectively introduces a low-overhead hypervisor with a small attack surface which protects the pagetables even from
code running in kernel mode. Most of this can be reverse engineered using Python and m1n1.

This isn't useful for porting Linux to the M1 but we might run into this once we virtualize XNU in order to trace its
MMIO access.

If you enjoyed this post consider checking out [Asahi Linux](https://asahilinux.org) or follow me on
 [Twitter](https://twitter.com/svenpeter42). 

## Open questions

* Is it possible to enable SPRR and GXF in EL1 when using Hypervisor.framework?
    * Yes! [Longhorn](https://twitter.com/never_released) pointed out that there is a `com.apple.private.hypervisor.vmapple` entitlement which allows EL1 guests under macOS to use these system registers as well.
* What do the other bits in `SPRR_CONFIG` and `GXF_CONFIG` do? 
* What other effects does enabling SPRR and GXF have? At least HCR_EL2 is no longer writable from EL2 but requires GL2
  now and I'm quite sure that's not the only difference.
* Where are interrupts routed when we are in guarded execution mode? I'd assume they go to `VBAR_GLx` but I haven't
  confirmed this.
* When running in EL2 there should be a different register for EL0 permissions for `HCR_EL2.TGE = 0` and `HCR_EL2.TGE = 1`. There should also be a way to access the EL1 registers from EL2 (similar to the common `.._EL12` ones). Which registers do just that?
    * marcan figured them all out during [one of his streams](https://www.youtube.com/watch?v=iw_FvXnb_WQ) and they're [documented in m1n1](https://github.com/AsahiLinux/m1n1/blob/main/tools/apple_regs.json) now.
* siguza found some obscure hardware ~~bug~~undefined behavior involving PAN and WXN - is that one still present or are there similar issues with SPRR as well?
* What do SPRR and GXF stand for? :-)
    * Possibly ["shadow permission remap register" and "guarded execution feature"](https://twitter.com/_saagarjha/status/1390271837771165703)

 