/*
 * Copyright (C) 1999-2021 Parallels International GmbH. All Rights Reserved.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/interrupt.h>
#include <linux/proc_fs.h>
#include <linux/hash.h>
#include <linux/delay.h>
#include <linux/version.h>
#if defined(CONFIG_CRASH_CORE) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
#	include <linux/crash_core.h>
#	define REPORT_VMCOREINFO
#endif
#include <asm-generic/pci_iomap.h>
#include "prltg_common.h"
#include "prltg_compat.h"
#include "prltg_call.h"

#define PRLVID_CAPABILITY_APERTURE_ONLY 0x02

// iobar: 0 - for parallels vid, 2 - for virtio vid
// membar: 1 - for parallels vid, 0 - for virtio vid
#define PRL_IO_BAR(dev) ((dev->vendor == 0x1ab8) ? 0 : 2)
#define PRL_MM_BAR(dev) ((dev->vendor == 0x1ab8) ? 1 : 0)

#define FOURCC(a, b, c, d) ((u32)(d) | ((u32)(c) << 8) | ((u32)(b) << 16) | ((u32)(a) << 24))

static char version[] = KERN_INFO DRV_LOAD_MSG "\n";

/* indexed by board_t, above */
static struct {
	const char *name;
	char *nick;
} board_info[] = {
	{ "Parallels ToolGate", TOOLGATE_NICK_NAME },
	{ "Parallels Video ToolGate", VIDEO_TOOLGATE_NICK_NAME },
	{ "Parallels Video DRM ToolGate", VIDEO_DRM_TOOLGATE_NICK_NAME }
};

static struct pci_device_id prl_tg_pci_tbl[] = {
	{ 0x1ab8, 0x4000, PCI_ANY_ID, PCI_ANY_ID, 0, 0, TOOLGATE },
	{ 0, }
};
MODULE_DEVICE_TABLE (pci, prl_tg_pci_tbl);

/* Interrupt's bottom half */
static void tg_do_work(struct work_struct *work)
{
	struct list_head completed;
	struct list_head *tmp, *n;
	struct TG_PENDING_REQUEST *req;
	struct tg_dev *dev = container_of(work, struct tg_dev, work);
	unsigned long flags;

	DPRINTK("ENTER\n");

	INIT_LIST_HEAD(&completed);
	spin_lock_irqsave(&dev->queue_lock, flags);
	list_for_each_safe(tmp, n, &dev->pr_list) {
		req = list_entry(tmp, struct TG_PENDING_REQUEST, pr_list);
		if (req->dst->Status == TG_STATUS_PENDING)
			continue;

		if (req->dst->Status == TG_STATUS_SUCCESS &&
			(req->sdesc->flags & TG_REQ_RESTART_ON_SUCCESS)) {
			req->dst->Status = TG_STATUS_PENDING;
			tg_out(dev, TG_PORT_SUBMIT, req->phys);
			continue;
		}

		list_move(&req->pr_list, &completed);
		req->processed = 1;
	}
	spin_unlock_irqrestore(&dev->queue_lock, flags);

	/* enable Toolgate's interrupt */
	if (!(dev->flags & TG_DEV_FLAG_MSI))
		tg_out32(dev, TG_PORT_MASK, TG_MASK_COMPLETE);

	list_for_each_safe(tmp, n, &completed) {
		req = list_entry(tmp, struct TG_PENDING_REQUEST, pr_list);
		complete(&req->waiting);
	}

	DPRINTK("EXIT\n");
}

static void tg_req_cancel_all(struct tg_dev *dev)
{
	struct list_head cancelled;
	struct list_head *tmp, *n;
	struct TG_PENDING_REQUEST *req;
	unsigned long flags;

	DPRINTK("ENTER\n");

	INIT_LIST_HEAD(&cancelled);
	spin_lock_irqsave(&dev->queue_lock, flags);
	list_for_each_safe(tmp, n, &dev->pr_list) {
		req = list_entry(tmp, struct TG_PENDING_REQUEST, pr_list);
		if (req->dst->Status == TG_STATUS_PENDING) {
			list_move(&req->pr_list, &cancelled);
			req->processed = 1;
		}
	}
	spin_unlock_irqrestore(&dev->queue_lock, flags);

	list_for_each(tmp, &cancelled) {
		req = list_entry(tmp, struct TG_PENDING_REQUEST, pr_list);
		tg_out(dev, TG_PORT_CANCEL, req->phys);
	}
	/* waiting host's confirmation up to several seconds */
	list_for_each_safe(tmp, n, &cancelled) {
		int timeout = 1;

		req = list_entry(tmp, struct TG_PENDING_REQUEST, pr_list);
		while ((req->dst->Status == TG_STATUS_PENDING) &&
							(timeout < 4*HZ)) {
			msleep(timeout);
			timeout *= 2;
		}
		if (req->dst->Status == TG_STATUS_PENDING)
			/* Host don't cancel request. If we free it we can get
			 * the memory corruption if host will handle it later.
			 * If we don't free it, we'll leak the memory if host
			 * forget about this request. I think memory leak is
			 * better than memory corruption */
			 printk(KERN_ERR PFX "Host don't handle "
					"request's cancel %p\n", req);
		else
		complete(&req->waiting);
	}
	DPRINTK("EXIT\n");
}

int prl_tg_user_to_host_request_complete(char *u, TG_REQ_DESC *sdesc, int ret)
{
	DPRINTK("ENTER\n");

	if (!ret) {
		int i;
		TG_BUFFER *sbuf;
		TG_REQUEST *src = sdesc->src;
		/* copy request status back to userspace */
		if (copy_to_user(u, src, sizeof(TG_REQUEST)))
			ret = -EFAULT;

		u += sizeof(TG_REQUEST);
		/* copy inline data back to userspace */
		if ((src->InlineByteCount != 0) && (src->Status == TG_STATUS_SUCCESS) &&
			(copy_to_user(u, sdesc->idata, src->InlineByteCount)))
			ret = -EFAULT;

		sbuf = sdesc->sbuf;
		u += INLINE_SIZE(src) + offsetof(TG_BUFFER, ByteCount);
		for (i = 0; i < src->BufferCount; i++) {
			/* copy buffer's ButeCounts back to userspace */
			if ((src->Status != TG_STATUS_CANCELLED) &&
				copy_to_user(u, &sbuf->ByteCount, sizeof(sbuf->ByteCount)))
				ret = -EFAULT;
			sbuf++;
			u += sizeof(TG_BUFFER);
		}
	}

	if (sdesc->sbuf)
		vfree(sdesc->sbuf);

	if (sdesc->idata)
		vfree(sdesc->idata);

	DPRINTK("EXIT, returning %d\n", ret);
	return ret;
}
EXPORT_SYMBOL(prl_tg_user_to_host_request_complete);

int prl_tg_user_to_host_request_prepare(void *ureq, TG_REQ_DESC *sdesc, TG_REQUEST *src)
{
	int ret = 0;
	void *u;

	/* read request header from userspace */
	if (copy_from_user(src, ureq, sizeof(TG_REQUEST)))
		return -EFAULT;

	/*
	 * requests up to TG_REQUEST_SECURED_MAX are for drivers only and are
	 * denied by guest driver if come from user space to maintain guest
	 * kernel integrity (prevent malicious code from sending FS requests)
	 * dynamically assigned requests start from TG_REQUEST_MIN_DYNAMIC
	 */
	if (src->Request <= TG_REQUEST_SECURED_MAX)
		return -EINVAL;

	memset(sdesc, 0, sizeof(TG_REQ_DESC));
	sdesc->src = src;

	u = ureq + sizeof(TG_REQUEST);
	if (src->InlineByteCount) {
		sdesc->idata = vmalloc(src->InlineByteCount);
		if (sdesc->idata == NULL) {
			ret = -ENOMEM;
			goto err_vm;
		}

		if (copy_from_user(sdesc->idata, u, src->InlineByteCount)) {
			ret = -EFAULT;
			goto err_vm;
		}
	}
	u += INLINE_SIZE(src);

	if (src->BufferCount) {
		/* allocate memory for request's buffers */
		int ssize = src->BufferCount * sizeof(TG_BUFFER);
		sdesc->sbuf = vmalloc(ssize);
		if (!sdesc->sbuf) {
			ret = -ENOMEM;
			goto err_vm;
		}
		/* copy buffer descriptors from userspace */
		if (copy_from_user(sdesc->sbuf, u, ssize)) {
			ret = -EFAULT;
			goto err_vm;
		}
		/* leaving sdesc.kernel_bufs set to 0 to indicate that
		all the buffers are Userspace */
	}

	return 0;

err_vm:
	if (sdesc->sbuf)
		vfree(sdesc->sbuf);
	if (sdesc->idata)
		vfree(sdesc->idata);
	return ret;
}
EXPORT_SYMBOL(prl_tg_user_to_host_request_prepare);

static ssize_t prl_tg_write(struct file *filp, const char __user *buf,
	size_t nbytes, loff_t *ppos)
{
	int ret = 0;
	struct tg_dev *dev = prl_pde_data(FILE_DENTRY(filp)->d_inode);
	void *ureq = NULL;
	TG_REQ_DESC sdesc;
	TG_REQUEST src;

	if (!prl_tg_req_ptr_size_check(nbytes))
		return -EINVAL;

	if (copy_from_user(&ureq, buf, nbytes))
		return -EFAULT;

	ret = prl_tg_user_to_host_request_prepare(ureq, &sdesc, &src);
	if (ret)
		return ret;

	ret = call_tg_sync(dev, &sdesc);

	return prl_tg_user_to_host_request_complete(ureq, &sdesc, ret);
}

static int prl_tg_open(struct inode *inode, struct file *filp)
{
	(void)inode;
	(void)filp;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

#ifdef FMODE_ATOMIC_POS
	filp->f_mode &= ~FMODE_ATOMIC_POS;
#endif
	return 0;
}

static int prl_tg_release(struct inode *inode, struct file *filp)
{
	(void)inode;
	(void)filp;
	module_put(THIS_MODULE);
	return 0;
}


/* The interrupt handler */
static irqreturn_t prl_tg_interrupt(int irq, void *dev_instance)
{
	struct tg_dev *dev = (struct tg_dev *) dev_instance;
	int status = TG_MASK_COMPLETE;
	int ret = 0;

	if (!(dev->flags & TG_DEV_FLAG_MSI))
		status = tg_in32(dev, TG_PORT_STATUS);

	if (status) {
		/* if it is toolgate's interrupt schedule bottom half */
		ret = 1;
		schedule_work(&dev->work);
	}
	DPRINTK("prl_tg exiting interrupt, ret %d\n", ret);
	return IRQ_RETVAL(ret);
}

/* Initialize PCI device */
static int prl_tg_initialize(struct tg_dev *dev)
{
	int rc, io_bar;
	struct pci_dev *pdev = dev->pci_dev;
	DPRINTK ("ENTER\n");

	/* enable device (incl. PCI PM wakeup), and bus-mastering */
	rc = pci_enable_device(pdev);
	if (rc) {
		printk(KERN_ERR PFX "could not enable device\n");
		goto out;
	}

	io_bar = PRL_IO_BAR(pdev);
	rc = -ENODEV;
	/* make sure PCI base addr 0 is PIO */
#if defined(__aarch64__)
	/* For ARM Toolgate we use MMIO as control region */
	if (!(pci_resource_flags(pdev, io_bar) & IORESOURCE_MEM)) {
#else
	if (!(pci_resource_flags(pdev, io_bar) & IORESOURCE_IO)) {
#endif
		printk(KERN_ERR PFX "region #%d not a PIO resource\n", io_bar);
		goto err_out;
	}

	/* check for weird/broken PCI region reporting */
#if defined(__aarch64__)
	if (pci_resource_len(pdev, io_bar) < TG_MAX_MEM) {
#else
	if (pci_resource_len(pdev, io_bar) < TG_MAX_PORT) {
#endif
		printk(KERN_ERR PFX "Invalid PCI region size(s)\n");
		goto err_out;
	}

#ifdef PRLVTG_MMAP
	if (dev->board != TOOLGATE) {
		int mm_bar = PRL_MM_BAR(pdev);
		const unsigned int capabilities =
			((dev->board == VIDEO_DRM_TOOLGATE ? PRLVID_CAPABILITY_APERTURE_ONLY : 0) << 16);

		if (!(pci_resource_flags(pdev, mm_bar) & IORESOURCE_MEM)) {
			printk(KERN_ERR PFX "region #%d not a MEM resource\n", mm_bar);
			goto err_out;
		}
		dev->mem_phys = pci_resource_start(pdev, mm_bar);

		// read VESA regs for CAPABILITIES
		outb(0xae, VGA_SEQ_I);
		dev->capabilities = inl(VGA_SEQ_D);

		outb(0xae, VGA_SEQ_I);
		outl((dev->capabilities & 0xffff) | capabilities, VGA_SEQ_D);

		// read VESA regs for MEMSIZE
		outb(0xa0, VGA_SEQ_I);
		dev->mem_size = inl(VGA_SEQ_D);
		printk(KERN_INFO
			"%s: memory physaddr %llx, size %lldMb, capabilities %x\n",
			board_info[dev->board].name,
			dev->mem_phys, dev->mem_size, dev->capabilities);
		dev->mem_size *= 1024 * 1024;
	}
#endif
	/* Set DMA ability. Only lower 4G is possible to address */
	rc = prl_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (rc) {
		printk(KERN_ERR "no usable DMA configuration\n");
		goto err_out;
	}

	rc = pci_request_region(pdev, io_bar, board_info[dev->board].nick);
	if (rc) {
		printk(KERN_ERR PFX "could not reserve PCI I/O and memory resources\n");
		goto err_out;
	}

	dev->base_addr = pci_iomap(pdev, io_bar, 0);

	tg_out32(dev, TG_PORT_CAPS, 0);
	if (tg_in32(dev, TG_PORT_CAPS) != FOURCC('O', 'U', 'T', 'D'))
		dev->flags |= TG_DEV_FLAG_OUTS;

	rc = pci_enable_msi(pdev);
	if (rc == 0)
		dev->flags |= TG_DEV_FLAG_MSI;
	dev->irq = pdev->irq;

	rc = request_irq(dev->irq, prl_tg_interrupt,
		(dev->flags & TG_DEV_FLAG_MSI) ? 0 : IRQF_SHARED, board_info[dev->board].nick, dev);
	if (rc) {
		pci_release_region(pdev, io_bar);
err_out:
		if (dev->board == TOOLGATE)
			pci_disable_device(pdev);
	}

out:
	DPRINTK("EXIT, returning %d\n", rc);
	return rc;
}

static void send_vmcoreinfo(struct tg_dev *dev)
{
#ifdef REPORT_VMCOREINFO
	struct {
		TG_REQUEST req;
		struct dbg_vmcoreinfo_desc vmcore;
		TG_UINT64 align;
	} src = {{
			.Request = TG_REQUEST_DBG_VMCOREINFO,
			.Status	= TG_STATUS_PENDING,
			.InlineByteCount = sizeof(struct dbg_vmcoreinfo_desc),
			.BufferCount = 0,
			.Reserved = 0
		},
		{
			.note_paddr = paddr_vmcoreinfo_note()
		}
	};

	TG_REQ_DESC sdesc = {
		.src = &src.req,
		.idata = &src.vmcore,
		.sbuf = 0,
		.flags = 0
	};
	call_tg_sync(dev, &sdesc);
#else
	(void)dev;
#endif
}

int prl_tg_probe_common(struct tg_dev *dev, board_t board,
                        struct proc_ops *proc_ops)
{
	int rc = -ENOMEM;
	dev->flags = 0;
#ifdef PRLVTG_MMAP
	dev->mem_phys = 0;
	dev->mem_size = 0;
#endif
	spin_lock_init(&dev->lock);
	spin_lock_init(&dev->queue_lock);
	INIT_LIST_HEAD(&dev->pr_list);
	dev->board = board;

	/* masks interrupts on the device probing */
	/* ayegorov@:
	 * Masking of interrupt at this step is illegal, i.e. first we have to
	 * initialize 'base_addr' variable in 'dev' data structure. Also I have
	 * commented this line, because we should know exactly should this function
	 * call be here or not!
	tg_out32(dev, TG_PORT_MASK, 0); */

	rc = prl_tg_initialize(dev);
	if (rc) {
		kfree(dev);
		goto out;
	}

	INIT_WORK(&dev->work, tg_do_work);

	/* enable interrupt */
	tg_out32(dev, TG_PORT_MASK, TG_MASK_COMPLETE);

	if (board == TOOLGATE) {
		send_vmcoreinfo(dev);
	}
	if (board != VIDEO_DRM_TOOLGATE) {
		struct proc_dir_entry *p;
		char proc_file[16];
		snprintf(proc_file, 16, "driver/%s", board_info[board].nick);

		p = proc_create_data(proc_file,
			S_IWUGO | ((dev->board == VIDEO_TOOLGATE) ? S_IRUGO : 0), NULL,
			proc_ops, dev);
		if (!p)
			printk(KERN_WARNING "cannot create %s proc entry\n", proc_file);
	}

	printk(KERN_INFO "Detected %s device, IRQ %d\n",
		board_info[board].name, dev->irq);

out:
	DPRINTK("EXIT, returning %d\n", rc);
	return rc;
}
EXPORT_SYMBOL(prl_tg_probe_common);

/* Deinitialize PCI device */
static void prl_tg_deinitialize(struct tg_dev *dev)
{
	DPRINTK("ENTER\n");

	tg_out32(dev, TG_PORT_MASK, 0);

	synchronize_irq(dev->irq);
	free_irq(dev->irq, dev);
	if (dev->flags & TG_DEV_FLAG_MSI) {
		dev->flags &= ~TG_DEV_FLAG_MSI;
		pci_disable_msi(dev->pci_dev);
	}
	flush_scheduled_work();

	pci_release_region(dev->pci_dev, PRL_IO_BAR(dev->pci_dev));
	if (dev->board == TOOLGATE)
		pci_disable_device(dev->pci_dev);

	DPRINTK("EXIT\n");
}

void prl_tg_remove_common(struct tg_dev *dev)
{
	assert(dev != NULL);

	if (dev->board != VIDEO_DRM_TOOLGATE) {
		char proc_file[16];
		snprintf(proc_file, 15, "driver/%s", board_info[dev->board].nick);
		remove_proc_entry(proc_file, NULL);
	}

	prl_tg_deinitialize(dev);
}
EXPORT_SYMBOL(prl_tg_remove_common);

static struct proc_ops prl_tg_ops = PRLTG_PROC_OPS_INIT(
		prl_tg_open,
		prl_tg_write,
		NULL, NULL,
		prl_tg_release);

#ifdef CONFIG_PM
int prl_tg_suspend_common(struct tg_dev *dev, pm_message_t state)
{
	/* VvS: I don't found a way to detect hibernate on all linuxes,
	 * therore we'll cancel all request on each suspend */
	tg_req_cancel_all(dev);
	prl_tg_deinitialize(dev);
	return 0;
}
EXPORT_SYMBOL(prl_tg_suspend_common);

int prl_tg_resume_common(struct tg_dev *dev)
{
	int rc = prl_tg_initialize(dev);
	if (!rc)
		tg_out32(dev, TG_PORT_MASK, TG_MASK_COMPLETE);

	return rc;
}
EXPORT_SYMBOL(prl_tg_resume_common);
#endif /* CONFIG_PM */

static int prl_tg_probe(
		struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct tg_dev *dev = NULL;
/* when built into the kernel, we only print version if device is found */
#ifndef MODULE
	static int printed_version;
	if (!printed_version++)
		printk(version);
#endif
	assert(pdev != NULL);
	assert(ent != NULL);

	dev = kmalloc(sizeof(struct tg_dev), GFP_KERNEL);
	assert(dev != NULL);
	dev->pci_dev = pdev;
	pci_set_drvdata(pdev, dev);

	return prl_tg_probe_common(dev, TOOLGATE, &prl_tg_ops);
}

static void prl_tg_remove(struct pci_dev *pdev)
{
	prl_tg_remove_common(pci_get_drvdata(pdev));
	kfree(pci_get_drvdata(pdev));
	pci_set_drvdata(pdev, NULL);
}

#ifdef CONFIG_PM
static int prl_tg_suspend(struct pci_dev *pdev, pm_message_t state)
{
	return prl_tg_suspend_common(pci_get_drvdata(pdev), state);
}

static int prl_tg_resume(struct pci_dev *pdev)
{
	return prl_tg_resume_common(pci_get_drvdata(pdev));
}
#endif /* CONFIG_PM */

static struct pci_driver prl_tg_pci_driver = {
	.name		= DRV_SHORT_NAME,
	.id_table	= prl_tg_pci_tbl,
	.probe		= prl_tg_probe,
	.remove		= prl_tg_remove,
#ifdef CONFIG_PM
	.suspend	= prl_tg_suspend,
	.resume		= prl_tg_resume,
#endif /* CONFIG_PM */
};

static int __init prl_tg_init_module(void)
{
/* when a module, this is printed whether or not devices are found in probe */
#ifdef MODULE
	printk(version);
#endif

	/* we don't return error when devices probing fails,
	 * it's required for proper supporting hot-pluggable device */
	return pci_register_driver(&prl_tg_pci_driver);
}

static void __exit prl_tg_cleanup_module(void)
{
	pci_unregister_driver(&prl_tg_pci_driver);
}

module_init(prl_tg_init_module);
module_exit(prl_tg_cleanup_module);

MODULE_AUTHOR("Parallels International GmbH");
MODULE_DESCRIPTION("Parallels ToolGate driver");
MODULE_LICENSE("Parallels");
MODULE_VERSION(DRV_VERSION);
MODULE_INFO(supported, "external");
