/*
 * Copyright (C) 1999-2018 Parallels International GmbH. All Rights Reserved.
 */

#ifndef __PRL_TG_COMMON_H__
#define __PRL_TG_COMNON_H__

#include <linux/version.h>
#include <linux/pm.h>
#include <linux/compat.h>
#include <video/vga.h>

#define PRLVTG_MMAP
#include <linux/mm.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
#include <linux/uaccess.h>
#else
#include <asm/uaccess.h>
#endif

#include "../Interfaces/prltg.h"
#include "../../Interfaces/tgreq.h"
#include "../../../Interfaces/Tg.h"
#include "prltg_compat.h"

/* define to 1 to enable copious debugging info */
#undef DRV_DEBUG

/* define to 1 to disable lightweight runtime debugging checks */
#undef DRV_NDEBUG

#ifdef DRV_DEBUG
/* note: prints function name for you */
#	define DPRINTK(fmt, args...) printk(KERN_DEBUG "%s: " fmt, __FUNCTION__ , ## args)
#else
#	define DPRINTK(fmt, args...)
#endif

#ifdef DRV_NDEBUG
#	define assert(expr) do {} while (0)
#else
#	define assert(expr) \
	if(!(expr)) {\
		printk( "Assertion failed! %s,%s,%s,line=%d\n",\
		#expr,__FILE__,__FUNCTION__,__LINE__);\
	}
#endif

#define DRV_LOAD_MSG	DRV_LONG_NAME " driver " DRV_VERSION " loaded"
#define PFX				DRV_SHORT_NAME ": "

#define INLINE_SIZE(a)	(((a)->InlineByteCount + sizeof(u64) - 1) & ~(sizeof(u64) - 1))

#define VTG_HASH_BITS	4
#define VTG_HASH_SIZE	(1UL << VTG_HASH_BITS)
#define VTG_HASH_MASK	(VTG_HASH_SIZE-1)

// For rejecting of anomalous large requests we should set internal TG request
// size limit according to some assumptions about TG request sturcture limits:
// - 16 TG buffers max
// - 1024 * 1024 Pages buffer length max
// - 8 byte page address
#define TG_REQUEST_INTERNAL_LIMIT (16 * 1024 * 1024 * 8)

typedef enum {
	TOOLGATE = 0,
	VIDEO_TOOLGATE = 1,
	VIDEO_DRM_TOOLGATE = 2
} board_t;

#define TG_DEV_FLAG_MSI		(1 << 0)
#define TG_DEV_FLAG_OUTS	(1 << 1)

struct tg_dev {
	board_t board;
	unsigned int irq;
	void __iomem *base_addr;
	spinlock_t queue_lock; /* protects queue of submitted requests */
	struct list_head pr_list; /* pending requests list */
	struct work_struct work;
	struct pci_dev *pci_dev;
	spinlock_t lock;	/* protects device's port IO operations */
	unsigned int flags;
#ifdef PRLVTG_MMAP
	unsigned int capabilities;
	resource_size_t mem_phys, mem_size;
#endif
};

struct TG_PENDING_REQUEST
{
	struct tg_dev *dev;
	TG_REQ_DESC *sdesc;
	TG_PAGED_REQUEST *dst;

	struct list_head pr_list;
	struct list_head up_list;

	struct completion waiting;
	int processed;				/* Protected by queue_lock */
	dma_addr_t phys;			/* Physical address of first page of request */
	struct page *pg;			/* First page of request descriptor */
};

/*
 * Build request pin vmalloced pages in memory to prevent swapping.
 * Also, pages got from userspace pinned too. Those pages must be
 * released at completion. As all request structures are shared between
 * lot of places - the list to store pages is good enough.
 */
struct up_list_entry {
	struct list_head up_list;
	int count;
	/* user pages must be marked dirty if device touched them */
	unsigned writable;
	struct page *p[0];
};

struct vtg_filp_private {
	struct list_head	hash_list;
	struct list_head	glctx_list;
	spinlock_t			lock;
	struct file			*filp;
	struct tg_dev		*dev;
};

/* The rest of these values should never change. */

/* Symbolic offsets to registers. */
enum TgRegisters {
	TG_PORT_STATUS	= 0,
	TG_PORT_MASK	= 0,
	TG_PORT_CAPS	= 0x4,
	TG_PORT_SUBMIT	= 0x8,
	TG_PORT_CANCEL	= 0x10,
	TG_MAX_PORT		= 0x18,
	TG_MAX_MEM	= 0x1000,
};

/* Port IO primitives */
static __inline u32
tg_in32(struct tg_dev *dev, unsigned long port)
{
	u32 x;
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
#if defined(__aarch64__)
	x = ioread32(dev->base_addr + port);
#else
	x = inl((unsigned long)dev->base_addr + port);
#endif
	spin_unlock_irqrestore(&dev->lock, flags);
	return (x);
}

static __inline void
tg_out32(struct tg_dev *dev, unsigned long port, u32 val)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
#if defined(__aarch64__)
	iowrite32(val, dev->base_addr + port);
#else
	outl(val, (unsigned long)dev->base_addr + port);
#endif
	spin_unlock_irqrestore(&dev->lock, flags);
}

static __inline void
tg_out(struct tg_dev *dev, unsigned long port, unsigned long long val)
{
	unsigned long flags;

	port += (unsigned long)dev->base_addr;
	spin_lock_irqsave(&dev->lock, flags);

#if defined(__aarch64__)
	iowrite64(val, port);
#else
	if (dev->flags & TG_DEV_FLAG_OUTS) {
		unsigned long len = (sizeof(unsigned long long) >> 2);
		void *ptr = &val;

#ifdef CONFIG_AMD_MEM_ENCRYPT
		asm volatile("rep; outsl" : "+S"(ptr), "+c"(len) : "d"(port) : "memory");
#else
		outsl(port, ptr, len);
#endif
	} else {
		u32 val_h = (u32)(val >> 32);
		u32 val_l = (u32)val;

		if (val_h)
			outl(val_h, port + 4);

		outl(val_l, port);
	}
#endif // __aarch64__
	spin_unlock_irqrestore(&dev->lock, flags);
}

struct pci_dev;
struct file_operations;
// Exported functions
int prl_tg_probe_common(struct tg_dev *pdev, board_t board,
                        struct proc_ops *proc_ops);
void prl_tg_remove_common(struct tg_dev *dev);
#ifdef CONFIG_PM
int prl_tg_suspend_common(struct tg_dev *dev, pm_message_t state);
int prl_tg_resume_common(struct tg_dev *dev);
#endif

int prl_tg_user_to_host_request_prepare(void *ureq, TG_REQ_DESC *sdesc, TG_REQUEST *src);
int prl_tg_user_to_host_request_complete(char *u, TG_REQ_DESC *sdesc, int ret);

static inline bool prl_tg_req_ptr_size_check(size_t nbytes)
{
#if defined(CONFIG_X86_64) && defined(CONFIG_COMPAT)
	if (prl_in_compat_syscall())
		return nbytes == sizeof(compat_uptr_t);
#endif
	return nbytes == sizeof(void *);
}

#endif /* __PRL_TG_COMNON_H__ */
