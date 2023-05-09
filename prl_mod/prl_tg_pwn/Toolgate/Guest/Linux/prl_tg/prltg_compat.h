/*
 * Copyright (C) 1999-2018 Parallels International GmbH. All Rights Reserved.
 */

#ifndef __PRL_TG_COMPAT_H__
#define __PRL_TG_COMPAT_H__

#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>

#ifndef DEFINE_SPINLOCK
#define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED
#endif

#ifndef __user
#define __user
#endif

#ifndef IRQ_RETVAL
#define IRQ_RETVAL(x)
#define irqreturn_t void
#endif

#ifndef IRQF_SHARED
#define IRQF_SHARED SA_SHIRQ
#endif

#ifndef MODULE_LICENSE
#define MODULE_LICENSE(x)
#endif

#ifdef RHEL_RELEASE_CODE
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9, 0)
#define PRLTG_RHEL_9_0_GE 1
#endif
#endif

#undef dev_put
#define dev_put(x) __dev_put(x)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#define FILE_DENTRY(f) ((f)->f_path.dentry)
#else
#define FILE_DENTRY(f) ((f)->f_dentry)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
#define page_cache_get(x) get_page(x)
#define page_cache_release(x) put_page(x)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
		LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0) && \
		defined(FAULT_FLAG_REMOTE)
#define OPENSUSE_4_4_76
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0) || defined(OPENSUSE_4_4_76)
#define prl_get_user_pages(_1, _2, _3, _4, _5) \
		get_user_pages(_1, _2, (_3) ? FOLL_WRITE : 0, _4, _5)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
#define prl_get_user_pages(_1, _2, _3, _4, _5) \
		get_user_pages(_1, _2, _3, 0, _4, _5)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 168) && \
		LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
#define prl_get_user_pages(_1, _2, _3, _4, _5) \
		get_user_pages(current, current->mm, _1, _2, (_3) ? FOLL_WRITE : 0, _4, _5)
#else
#define prl_get_user_pages(_1, _2, _3, _4, _5) \
		get_user_pages(current, current->mm, _1, _2, _3, 0, _4, _5)
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)

#define PRLTG_PROC_OPS_INIT(_open, _write, _unlocked_ioctl, _mmap, _release) \
	{ \
		.proc_open = _open, \
		.proc_write = _write, \
		.proc_ioctl = _unlocked_ioctl, \
		.proc_mmap = _mmap, \
		.proc_release = _release, \
	}

#else

#define PRLTG_PROC_OPS_INIT(_open, _write, _unlocked_ioctl, _mmap, _release) \
	{ \
		.open = _open, \
		.write = _write, \
		.unlocked_ioctl = _unlocked_ioctl, \
		.mmap = _mmap, \
		.release = _release, \
	}

#define proc_ops file_operations

#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#define prl_mmap_read_lock(mm) mmap_read_lock(mm)
#define prl_mmap_read_unlock(mm) mmap_read_unlock(mm)
#else
#define prl_mmap_read_lock(mm) down_read(&(mm)->mmap_sem)
#define prl_mmap_read_unlock(mm) up_read(&(mm)->mmap_sem)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
#define prl_in_compat_syscall() in_compat_syscall()
#else
#define prl_in_compat_syscall() test_thread_flag(TIF_IA32)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
#define prl_set_dma_mask(pdev, mask) dma_set_mask(&(pdev)->dev, mask)
#else
#define prl_set_dma_mask(pdev, mask) pci_set_dma_mask(pdev, mask)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0) || defined(PRLTG_RHEL_9_0_GE)
#define prl_pde_data(inode) pde_data(inode)
#else
#define prl_pde_data(inode) PDE_DATA(inode)
#endif

#endif /* __PRL_TG_COMPAT_H__ */
