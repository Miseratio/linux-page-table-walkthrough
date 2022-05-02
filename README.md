# Linux page table walkthrough kenrel module

enviroment :
- unbuntu 16.04 LTS
- kernel 4.15.0
## Question 1 demo 

code : test1.c

實驗設計: 取出每個process的pgd，再丟入0xc0000000進去查表驗證是否每個process是否都相同的physical addr

![](https://i.imgur.com/V8fv6fS.png)

test1_1.c

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/init_task.h>
#include <asm/highmem.h>

MODULE_DESCRIPTION("Hello_world");
MODULE_LICENSE("GPL");

static unsigned long vaddr2paddr(unsigned long vaddr, struct task_struct *task)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    p4d_t *p4d;
    unsigned long paddr = 0;
    unsigned long page_addr = 0;
    unsigned long page_offset = 0;
    unsigned long pg, pm, pt;

    pgd = pgd_offset(task->mm, vaddr);
    pg = pgd_val(*pgd);
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        return -1;
    }

    p4d = p4d_offset(pgd, vaddr);
    if(p4d_none(*p4d)){
        printk("not mapped in p4d\n");
        return -1;

    }

    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud)) {
        printk("not mapped in pud\n");
        return -1;
    }

    pmd = pmd_offset(pud, vaddr);
    pm = pmd_val(*pmd);
    if (pmd_none(*pmd)) {
        printk("not mapped in pmd\n");
        return -1;
    }

    pte = pte_offset_kernel(pmd, vaddr);
    pt = pte_val(*pte);
    if (pte_none(*pte)) {
        printk("not mapped in pte\n");
        return -1;
    }

    /* Page frame physical address mechanism | offset */
    page_addr = pte_val(*pte) & PAGE_MASK;
    page_offset = vaddr & ~PAGE_MASK;
    paddr = page_addr | page_offset;
    printk("   va   ->   pgd  ->   pmd  ->   pte  ->   pa \n");
    printk("%8lx  %8lx  %8lx  %8lx  %8lx \n", vaddr, pg, pm, pt, paddr);
    return paddr;
}

/*
virtual kernel memory layout:
                   fixmap  : 0xfff14000 - 0xfffff000   ( 940 kB)
                 cpu_entry : 0xffa00000 - 0xffb39000   (1252 kB)
                   pkmap   : 0xff600000 - 0xff800000   (2048 kB)
                   vmalloc : 0xf7dfe000 - 0xff5fe000   ( 120 MB)
                   lowmem  : 0xc0000000 - 0xf75fe000   ( 885 MB)

*/
static void print_memory_layout(void){

    printk(KERN_INFO "virtual kernel memory layout:\n"
		"    fixmap  : 0x%08lx - 0x%08lx   (%4ld kB)\n"
		"  cpu_entry : 0x%08lx - 0x%08lx   (%4ld kB)\n"
#ifdef CONFIG_HIGHMEM
		"    pkmap   : 0x%08lx - 0x%08lx   (%4ld kB)\n"
#endif
		"    vmalloc : 0x%08lx - 0x%08lx   (%4ld MB)\n"
		"    lowmem  : 0x%08lx - 0x%08lx   (%4ld MB)\n"
,
		FIXADDR_START, FIXADDR_TOP,
		(FIXADDR_TOP - FIXADDR_START) >> 10,

		CPU_ENTRY_AREA_BASE,
		CPU_ENTRY_AREA_BASE + CPU_ENTRY_AREA_MAP_SIZE,
		CPU_ENTRY_AREA_MAP_SIZE >> 10,

#ifdef CONFIG_HIGHMEM
		PKMAP_BASE, PKMAP_BASE+LAST_PKMAP*PAGE_SIZE,
		(LAST_PKMAP*PAGE_SIZE) >> 10,
#endif

		VMALLOC_START, VMALLOC_END,
		(VMALLOC_END - VMALLOC_START) >> 20,

		(unsigned long)__va(0), (unsigned long)high_memory,
		((unsigned long)high_memory - (unsigned long)__va(0)) >> 20);

}

static int init(void)
{	
    print_memory_layout();
    struct task_struct *tmp; 
    tmp = &init_task;
      
    int count = 10;    
    // try to access kernel space addr
    for_each_process(tmp){
        if(tmp -> mm == NULL){
            continue;
        }
        count--;
        printk("========== pid: %d ===========\n", tmp->pid);
        printk("---------- lowmem  -----------\n");
        vaddr2paddr(0xc0000000, tmp);
        printk("---------- vmalloc -----------\n");
        vaddr2paddr(VMALLOC_START, tmp);
        if(!count)
            break;

    }
    return 0;
}

static void exit(void)
{

    printk(KERN_INFO "Bye !\n");
}

module_init(init);
module_exit(exit);
```

test1_2.c

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/init_task.h>
#include <asm/highmem.h>

MODULE_DESCRIPTION("Hello_world");
MODULE_LICENSE("GPL");

static unsigned long vaddr2paddr(unsigned long vaddr, struct task_struct *task)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    p4d_t *p4d;
    unsigned long paddr = 0;
    unsigned long page_addr = 0;
    unsigned long page_offset = 0;
    
    unsigned long pg,pm,pt;

    pgd = pgd_offset(task->mm, vaddr);
    pg = pgd_val(*pgd);
    //unsigned long index = pgd_index(vaddr);
    //printk("index = %lx", index);
    if (pgd_none(*pgd)) {
        //printk("not mapped in pgd\n");
        return -1;
    }

    p4d = p4d_offset(pgd, vaddr);
    if(p4d_none(*p4d)){
        //printk("not mapped in p4d\n");
        return -1;

    }

    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud)) {
        //printk("not mapped in pud\n");
        return -1;
    }

    pmd = pmd_offset(pud, vaddr);
    pm = pmd_val(*pmd);
    if (pmd_none(*pmd)) {
        //printk("not mapped in pmd\n");
        return -1;
    }

    pte = pte_offset_kernel(pmd, vaddr);
    pt = pte_val(*pte);
    if (pte_none(*pte)) {
        //printk("not mapped in pte\n");
        return -1;
    }

    /* Page frame physical address mechanism | offset */
    page_addr = pte_val(*pte) & PAGE_MASK;
    page_offset = vaddr & ~PAGE_MASK;
    paddr = page_addr | page_offset;

    //printk("   va   ->   pgd  ->   pmd  ->   pte  ->   pa \n");
    //printk("%8lx  %8lx  %8lx  %8lx  %8lx \n", vaddr, pg, pm, pt, paddr);
    return paddr;
}

/*
virtual kernel memory layout:
                   fixmap  : 0xfff14000 - 0xfffff000   ( 940 kB)
                 cpu_entry : 0xffa00000 - 0xffb39000   (1252 kB)
                   pkmap   : 0xff600000 - 0xff800000   (2048 kB)
                   vmalloc : 0xf7dfe000 - 0xff5fe000   ( 120 MB)
                   lowmem  : 0xc0000000 - 0xf75fe000   ( 885 MB)

*/
static void print_memory_layout(void){

    printk(KERN_INFO "virtual kernel memory layout:\n"
		"    fixmap  : 0x%08lx - 0x%08lx   (%4ld kB)\n"
		"  cpu_entry : 0x%08lx - 0x%08lx   (%4ld kB)\n"
#ifdef CONFIG_HIGHMEM
		"    pkmap   : 0x%08lx - 0x%08lx   (%4ld kB)\n"
#endif
		"    vmalloc : 0x%08lx - 0x%08lx   (%4ld MB)\n"
		"    lowmem  : 0x%08lx - 0x%08lx   (%4ld MB)\n"
,
		FIXADDR_START, FIXADDR_TOP,
		(FIXADDR_TOP - FIXADDR_START) >> 10,

		CPU_ENTRY_AREA_BASE,
		CPU_ENTRY_AREA_BASE + CPU_ENTRY_AREA_MAP_SIZE,
		CPU_ENTRY_AREA_MAP_SIZE >> 10,

#ifdef CONFIG_HIGHMEM
		PKMAP_BASE, PKMAP_BASE+LAST_PKMAP*PAGE_SIZE,
		(LAST_PKMAP*PAGE_SIZE) >> 10,
#endif

		VMALLOC_START, VMALLOC_END,
		(VMALLOC_END - VMALLOC_START) >> 20,

		(unsigned long)__va(0), (unsigned long)high_memory,
		((unsigned long)high_memory - (unsigned long)__va(0)) >> 20);

}

static int init(void)
{	
    print_memory_layout();
    struct task_struct *tmp; 
    tmp = &init_task;
    struct task_struct *cur = current;
    int flag = 0;  
    unsigned long i;

    for(i =0xc0000000; i <=  0xf75fe000; i += 0x1000)
    {

        //printk("%lx\n",i);
        unsigned long old;
        unsigned long new;

        old = vaddr2paddr(i, cur);

        for_each_process(tmp){

            if(tmp -> mm == NULL){
                continue;
            }

            new = vaddr2paddr(i, tmp);

            if(new != old){
                flag = 1;
                goto f;
            }
            
        }

    }

    f:
    if(flag){
        printk("False!!\n");
    }
    else{
        printk("True!!\n");
    }

    return 0;
}

static void exit(void)
{

    printk(KERN_INFO "Bye !\n");
}

module_init(init);
module_exit(exit);

```

## Question 2 demo

code: test2.c

實驗設計: 先丟一段在fixmap的位置在其中一個process的轉換表轉換，之後在allocate 一段 fixmap 的記憶體取得該virtual addr，再讓其他process用該virtual addr去各自的pgd查表驗證是否得到相同的physical addr

![](https://i.imgur.com/uh3VZaa.png)

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/init_task.h>
#include <asm/highmem.h>


MODULE_DESCRIPTION("Hello_world");
MODULE_LICENSE("GPL");

static unsigned long vaddr2paddr(unsigned long vaddr, struct task_struct *task)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    p4d_t *p4d;
    unsigned long paddr = 0;
    unsigned long page_addr = 0;
    unsigned long page_offset = 0;
    unsigned long pg, pm, pt;

    pgd = pgd_offset(task->mm, vaddr);
    pg = pgd_val(*pgd);
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        return -1;
    }

    p4d = p4d_offset(pgd, vaddr);
    if(p4d_none(*p4d)){
        printk("not mapped in p4d\n");
        return -1;

    }

    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud)) {
        printk("not mapped in pud\n");
        return -1;
    }

    pmd = pmd_offset(pud, vaddr);
    pm = pmd_val(*pmd);
    if (pmd_none(*pmd)) {
        printk("not mapped in pmd\n");
        return -1;
    }

    pte = pte_offset_kernel(pmd, vaddr);
    pt = pte_val(*pte);
    if (pte_none(*pte)) {
        printk("not mapped in pte\n");
        return -1;
    }

    /* Page frame physical address mechanism | offset */
    page_addr = pte_val(*pte) & PAGE_MASK;
    page_offset = vaddr & ~PAGE_MASK;
    paddr = page_addr | page_offset;
    printk("   va   ->   pgd  ->   pmd  ->   pte  ->   pa \n");
    printk("%8lx  %8lx  %8lx  %8lx  %8lx \n", vaddr, pg, pm, pt, paddr);
    return paddr;
}


/*
virtual kernel memory layout:
                   fixmap  : 0xfff14000 - 0xfffff000   ( 940 kB)
                 cpu_entry : 0xffa00000 - 0xffb39000   (1252 kB)
                   pkmap   : 0xff600000 - 0xff800000   (2048 kB)
                   vmalloc : 0xf7dfe000 - 0xff5fe000   ( 120 MB)
                   lowmem  : 0xc0000000 - 0xf75fe000   ( 885 MB)

*/
static void print_memory_layout(void){

    printk(KERN_INFO "virtual kernel memory layout:\n"
		"    fixmap  : 0x%08lx - 0x%08lx   (%4ld kB)\n"
		"  cpu_entry : 0x%08lx - 0x%08lx   (%4ld kB)\n"
#ifdef CONFIG_HIGHMEM
		"    pkmap   : 0x%08lx - 0x%08lx   (%4ld kB)\n"
#endif
		"    vmalloc : 0x%08lx - 0x%08lx   (%4ld MB)\n"
		"    lowmem  : 0x%08lx - 0x%08lx   (%4ld MB)\n"
,
		FIXADDR_START, FIXADDR_TOP,
		(FIXADDR_TOP - FIXADDR_START) >> 10,

		CPU_ENTRY_AREA_BASE,
		CPU_ENTRY_AREA_BASE + CPU_ENTRY_AREA_MAP_SIZE,
		CPU_ENTRY_AREA_MAP_SIZE >> 10,

#ifdef CONFIG_HIGHMEM
		PKMAP_BASE, PKMAP_BASE+LAST_PKMAP*PAGE_SIZE,
		(LAST_PKMAP*PAGE_SIZE) >> 10,
#endif

		VMALLOC_START, VMALLOC_END,
		(VMALLOC_END - VMALLOC_START) >> 20,

		(unsigned long)__va(0), (unsigned long)high_memory,
		((unsigned long)high_memory - (unsigned long)__va(0)) >> 20);

}

static int init(void)
{	
    print_memory_layout();
    struct task_struct *tmp;
    struct task_struct *cur = current;
    tmp = &init_task;


    struct page *cur_page1, *cur_page2 = NULL;
    unsigned int *pkmap_cur_int = NULL;
    // allocate a page on pkmap
    cur_page1 = alloc_pages(__GFP_HIGHMEM, 0);
    pkmap_cur_int = kmap(cur_page1);
    printk("---------- cur_pkmap -----------");
    vaddr2paddr(pkmap_cur_int,cur);   
    
    // allocate a page on fixmap
    cur_page2 = alloc_pages(__GFP_HIGHMEM, 0);
    unsigned long fixmap_vaddr = kmap_atomic(cur_page2);
    printk("---------- cur_fixmap ----------");
    vaddr2paddr(fixmap_vaddr,cur);
      
    // others try to access current task's allocated page
    int count = 10;    
    for_each_process(tmp){
        if(tmp -> mm == NULL){
            continue;
        }
        count--;
        printk("========== pid: %d ===========\n", tmp->pid);
        printk("----------- pkmap  ------------\n");
        vaddr2paddr(pkmap_cur_int,tmp);
        
        printk("---------- fixkmap  -----------\n");
        vaddr2paddr(fixmap_vaddr,tmp);
        
        printk("\n");

        if(!count)
            break;
    }
    // free page
    if(pkmap_cur_int)
        kunmap(cur_page1);
    __free_pages(cur_page1, 0);
    

    return 0;
}

static void exit(void)
{

    printk(KERN_INFO "Bye !\n");
}

module_init(init);
module_exit(exit);

```
