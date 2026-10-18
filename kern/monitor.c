// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>

#include <kern/pmap.h>     // kern_pgdir, KADDR
#include <inc/mmu.h>       // PTE_P, PTE_W, PTE_U, PTE_PS, PTE_ADDR

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Stack backtrace", mon_backtrace },
	{ "showmappings", "Show page mappings for a VA range", mon_showmappings },
	{ "setperm", "Set/Clear page permissions", mon_setperm },
	{ "dumpva", "Dump virtual address range", mon_dumpva },
	{ "dumppa", "Dump physical address range", mon_dumppa },
};

static uint32_t
parse_hex(const char *s)
{
    uint32_t v = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    while (*s) {
        int d;
        if (*s >= '0' && *s <= '9')       d = *s - '0';
        else if (*s >= 'a' && *s <= 'f')  d = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'F')  d = *s - 'A' + 10;
        else break;
        v = v * 16 + d;
        s++;
    }
    return v;
}

static int
query_mapping(pde_t *pgdir, uintptr_t va, physaddr_t *pa, pte_t *perm)
{
    pte_t *pte = pgdir_walk(pgdir, (void *)va, 0);
    if (!pte || !(*pte & PTE_P))
        return -1;

    *pa   = PTE_ADDR(*pte) | (va & 0xFFF);
    *perm = *pte & 0xFFF;
    return 0;
}

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	int* ebp = (int*) read_ebp();
	struct Eipdebuginfo info;
	while(ebp){
		int eip = ebp[1];
		int* args = ebp + 2;  
		cprintf("  ebp %08x  eip %08x  args %08x %08x %08x %08x %08x\n", 
			ebp, eip, args[0], args[1], args[2], args[3], args[4]);
		
		debuginfo_eip(eip, &info);
		cprintf("         %s:%d: %.*s+%d\n", info.eip_file, info.eip_line, 
				info.eip_fn_namelen, info.eip_fn_name, eip - info.eip_fn_addr);

		ebp = (int*) *ebp;
	}
	return 0;
}

int
mon_showmappings(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 3) {
        cprintf("Usage: showmappings <va_start> <va_end>\n");
        return 0;
    }
	uintptr_t va_start = parse_hex(argv[1]);
	uintptr_t va_end = parse_hex(argv[2]);
	if (va_start > va_end) {
        uintptr_t t = va_start; va_start = va_end; va_end = t;
    }
	pde_t *pgdir = kern_pgdir;
	cprintf("VA         -> PA         perm:P W U\n");
	for(uintptr_t va = ROUNDDOWN(va_start, PGSIZE); va <= va_end; va += PGSIZE){
		physaddr_t pa;
		pte_t perm;
		if(query_mapping(pgdir, va, &pa, &perm) < 0){
			cprintf("0x%08x -> not mapped\n", va);
		}else{
			cprintf("0x%08x -> 0x%08x  %c%c%c\n",
                va, pa,
                (perm & PTE_P) ? 'P' : '-',
                (perm & PTE_W) ? 'W' : '-',
                (perm & PTE_U) ? 'U' : '-');
		}
	}
    return 0;
}

int
mon_setperm(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 3) {
        cprintf("Usage: setperm <va> +w|-w|+u|-u\n");
        return 0;
    }
	uintptr_t va = parse_hex(argv[1]);
	char op    = argv[2][0];
    char which = argv[2][1];

	pde_t *pgdir = kern_pgdir;
	pte_t *pte = pgdir_walk(pgdir, (void *)va, 0);
	if(!pte || !(*pte & PTE_P)){
		cprintf("VA 0x%08x not mapped\n", va);
		return 0;
	}

	if(op == '+'){
		if(which == 'w') 		*pte = *pte | PTE_W;
		else if(which == 'U')	*pte = *pte | PTE_U;
		else goto bad;
	}
	else if(op == '-'){
		if(which == 'w')		*pte = *pte & (~PTE_W);
		else if(which == 'U')	*pte = *pte & (~PTE_U);
		else goto bad;
	}
	else{
		goto bad;
	}

	tlb_invalidate(pgdir, (void *) va);

	cprintf("VA 0x%08x perm updated: %c%c%c\n",
        va,
        (*pte & PTE_P) ? 'P' : '-',
        (*pte & PTE_W) ? 'W' : '-',
        (*pte & PTE_U) ? 'U' : '-');
    return 0;

bad:
	cprintf("Usage: setperm <va> +w|-w|+u|-u\n");
	return 0;
}

int
mon_dumpva(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 3) {
        cprintf("Usage: dumpva <va_start> <va_end>\n");
        return 0;
    }

	uintptr_t start = parse_hex(argv[1]);
	uintptr_t end = parse_hex(argv[2]);
	if (start > end) {
        uintptr_t t = start; start = end; end = t;
    }

	pde_t *pgdir = kern_pgdir;

	for(uintptr_t va = ROUNDDOWN(start, PGSIZE); va <= end; va += PGSIZE){
		pte_t *pte = pgdir_walk(pgdir,(void *) va, 0);
		if(!pte || !(*pte & PTE_P)){
			cprintf("0x%08x: <not mapped>\n", va);
			continue;
		}
		physaddr_t pa_base = PTE_ADDR(*pte);

		uintptr_t va1 = (va < start) ? start : va;
		uintptr_t va2 = (va + PGSIZE -1 < end)? va + PGSIZE -1 : end;

		uintptr_t line_start = ROUNDDOWN(va1, 16);

		for (uintptr_t line = line_start; line <= va2; line += 16) {
            cprintf("0x%08x: ", line);

            uint8_t buf[16];
			int valid[16];

            for (int j = 0; j < 16; j++) {
                uintptr_t cur = line + j;
                if (cur >= va1 && cur <= va2) {
                    buf[j]   = *(uint8_t *)KADDR(pa_base + (cur & 0xFFF));
                    valid[j] = 1;
                } else {
                    valid[j] = 0;
                }
            }

            for (int j = 0; j < 16; j++) {
                if (valid[j]) cprintf("%02x ", buf[j]);
                else       cprintf("   ");
                if (j == 7) cprintf(" ");
            }

            cprintf(" |");

            for (int j = 0; j < 16; j++) {
                if (!valid[j])
                    cprintf(" ");
                else
                    cprintf("%c", (buf[j] >= 32 && buf[j] < 127) ? buf[j] : '.');
            }
            cprintf("|\n");
        }
	}
	return 0;
}

int
mon_dumppa(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 3) {
        cprintf("Usage: dumppa <pa_start> <pa_end>\n");
        return 0;
    }

	uintptr_t start = parse_hex(argv[1]);
    uintptr_t end   = parse_hex(argv[2]);
    if (start > end) {
        uintptr_t t = start; start = end; end = t;
    }

	if (end >= 0x10000000) {
        cprintf("physical range exceeds 256MB mapped window\n");
        return 0;
    }

	uintptr_t line_start = ROUNDDOWN(start, 16);

	for (uintptr_t line = line_start; line <= end; line += 16) {
        cprintf("0x%08x: ", line);

        uint8_t buf[16];
        int valid[16];

        for (int j = 0; j < 16; j++) {
            uintptr_t cur = line + j;
            if (cur >= start && cur <= end) {
                buf[j]   = *(uint8_t *)KADDR(cur);
                valid[j] = 1;
            } else {
                valid[j] = 0;
            }
        }

        for (int j = 0; j < 16; j++) {
            if (valid[j]) cprintf("%02x ", buf[j]);
            else          cprintf("   ");
            if (j == 7) cprintf(" ");
        }

        cprintf(" |");
        for (int j = 0; j < 16; j++) {
            if (!valid[j])
                cprintf(" ");
            else
                cprintf("%c", (buf[j] >= 32 && buf[j] < 127) ? buf[j] : '.');
        }
        cprintf("|\n");
    }
	return 0;
}
/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
