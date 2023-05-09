/*
 * Copyright (C) 1999-2018 Parallels International GmbH. All Rights Reserved.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/interrupt.h>
#include <linux/pagemap.h>
#include "prltg_common.h"
#include "prltg_compat.h"
#include "../Interfaces/prltg_call.h"

#define dma_addr_to_pfn(addr) ((addr) >> PAGE_SHIFT)
#define pfn_to_dma_addr(pfn) ((pfn) << PAGE_SHIFT)

static int tg_req_paged_size(TG_REQ_DESC *sdesc)
{
	TG_REQUEST *src;
	TG_BUFFER *sbuf;
	int dpages, dsize, nbuf;

	src = sdesc->src;
	sbuf = sdesc->sbuf;
	dsize = sizeof(TG_PAGED_REQUEST) + INLINE_SIZE(src);
	for (nbuf = 0; nbuf < src->BufferCount; ++nbuf, ++sbuf) {
		dsize += sizeof(TG_PAGED_BUFFER);
		if (sbuf->ByteCount) {
			int npages = ((sbuf->u.Va & ~PAGE_MASK) +
				sbuf->ByteCount + ~PAGE_MASK) >> PAGE_SHIFT;
			dsize += npages * sizeof(u64);
			if (dsize < 0)
				break;
		}
	}
	// If we have dsize overflow here, it's definitely corrupted request. Skip it.
	if ((dsize < 0) || (dsize > TG_REQUEST_INTERNAL_LIMIT)) {
		DPRINTK("tg_req_paged_size: dsize overflow\n");
		return -1;
	}
	/*
	 * If the request is large enough it needs its own page list
	 * note1: first page index is part of TG_PAGED_REQUEST
	 * note2: page indices are part of request, we may need more
	 * pages to fit all page indicies, so we iterate until all fit
	 */
	for (dpages = 1; ; ) {
		long delta = 1 + ((dsize - 1) >> PAGE_SHIFT) - dpages;

		if (!delta)
			break;
		dpages += delta;
		dsize += delta * sizeof(u64);
	}
	return dsize;
}

static int tg_req_map_internal(struct TG_PENDING_REQUEST *req)
{
	int i, count;
	struct up_list_entry *uple;
	TG_PAGED_REQUEST *dst = req->dst;
	char* mem = (char*)dst;
	struct pci_dev *pdev = req->dev->pci_dev;

	count = (((unsigned long)dst & ~PAGE_MASK) +
			dst->RequestSize + ~PAGE_MASK) >> PAGE_SHIFT;

	uple = (struct up_list_entry *)kmalloc(sizeof(struct up_list_entry) +
			sizeof(struct page *) * count, GFP_KERNEL);
	if (!uple)
		return -ENOMEM;

	uple->writable = 0;
	uple->count = 0;

	for (i = 0; i < count; i++, mem += PAGE_SIZE, uple->count++) {
		dma_addr_t addr;

		uple->p[i] = vmalloc_to_page(mem);
		page_cache_get(uple->p[i]);

		addr = dma_map_page(&pdev->dev, uple->p[i], 0, PAGE_SIZE,
		                    DMA_BIDIRECTIONAL);
		dst->RequestPages[i] = dma_addr_to_pfn(addr);
		if (!dst->RequestPages[i]) {
			page_cache_release(uple->p[i]);
			goto err;
		}
	}

	list_add(&uple->up_list, &req->up_list);
	return count;

err:
	for (i = 0; i < uple->count; i++) {
		dma_addr_t addr = pfn_to_dma_addr(dst->RequestPages[i]);
		dma_unmap_page(&pdev->dev, addr, PAGE_SIZE,
		               DMA_BIDIRECTIONAL);
		page_cache_release(uple->p[i]);
	}
	kfree(uple);
	return -ENOMEM;
}

static TG_PAGED_BUFFER *tg_req_map_user_pages(struct TG_PENDING_REQUEST *req,
	TG_PAGED_BUFFER *dbuf, TG_BUFFER *sbuf, int npages)
{
	struct pci_dev *pdev = req->dev->pci_dev;
	struct up_list_entry *uple;
	int i, got, mapped = 0;
	u64 *pfn;

	uple = (struct up_list_entry *)kmalloc(sizeof(struct up_list_entry) +
							sizeof(struct page *) * npages,
							GFP_KERNEL);
	if (!uple)
		goto err;

	uple->writable = sbuf->Writable;
	uple->count = npages;

	prl_mmap_read_lock(current->mm);
	/* lock userspace pages */
	got = prl_get_user_pages(
				 sbuf->u.Va, npages,
				 sbuf->Writable,
				 uple->p, NULL);
	prl_mmap_read_unlock(current->mm);

	if (got < npages) {
		DPRINTK("[2] %d < %d	\n", got, npages);
		goto err_put;
	}

	dbuf = (TG_PAGED_BUFFER *)((u64 *)dbuf + npages);
	pfn = (u64 *)dbuf - 1;

	for (; npages > 0; npages--, mapped++) {
		dma_addr_t addr = dma_map_page(&pdev->dev, uple->p[npages-1], 0,
		                               PAGE_SIZE, DMA_BIDIRECTIONAL);

		if (!addr) {
			DPRINTK("[3] %d < %d	\n", got, npages);
			goto err_unmap;
		}

		*(pfn--) = dma_addr_to_pfn(addr);
	}

	list_add(&uple->up_list, &req->up_list);
	return dbuf;

err_unmap:
	for (i = 0; i < mapped; i++, pfn++) {
		dma_unmap_page(&pdev->dev, pfn_to_dma_addr(*pfn), PAGE_SIZE,
		               DMA_BIDIRECTIONAL);
	}

err_put:
	for(i = 0; i < got; i++)
		page_cache_release(uple->p[i]);

	kfree(uple);
err:
	return ERR_PTR(-ENOMEM);
}

static TG_PAGED_BUFFER *tg_req_map_kernel_pages(struct TG_PENDING_REQUEST *req,
	TG_PAGED_BUFFER *dbuf, TG_BUFFER *sbuf, int npages)
{
	int i;
	u64 *pfn = (u64 *)dbuf;
	char *buffer = (char *)sbuf->u.Buffer;
	struct pci_dev *pdev = req->dev->pci_dev;

	for (i = 0; i < npages; i++, buffer += PAGE_SIZE) {
		dma_addr_t addr;
		struct page *page;

		if (virt_addr_valid(buffer))
			page = virt_to_page(buffer);
		else if (is_vmalloc_addr(buffer))
			page = vmalloc_to_page(buffer);
		else {
			DPRINTK("[0][%d] va:%p incorrect\n", i, buffer);
			goto err;
		}

		addr = dma_map_page(&pdev->dev, page, 0, PAGE_SIZE, DMA_BIDIRECTIONAL);
		if (!addr) {
			DPRINTK("[2] va:%p can't map\n", buffer);
			goto err;
		}

		*(pfn++) = dma_addr_to_pfn(addr);
	}

	return (TG_PAGED_BUFFER *)((u64 *)dbuf + npages);

err:
	for (; i > 0; i--, pfn--) {
		dma_unmap_page(&pdev->dev, pfn_to_dma_addr(*pfn), PAGE_SIZE,
                       DMA_BIDIRECTIONAL);
	}

	return ERR_PTR(-ENOMEM);
}

static inline int tg_req_unmap_internal(struct TG_PENDING_REQUEST *req)
{
	int i, count;
	TG_PAGED_REQUEST *dst = req->dst;

	count = (((unsigned long)dst & ~PAGE_MASK) +
			dst->RequestSize + ~PAGE_MASK) >> PAGE_SHIFT;

	for (i = 0; i < count; i++) {
		dma_addr_t addr = pfn_to_dma_addr(dst->RequestPages[i]);
		dma_unmap_page(&req->dev->pci_dev->dev, addr, PAGE_SIZE,
		               DMA_BIDIRECTIONAL);
	}

	return count;
}

static inline void tg_req_unmap_user_pages(struct TG_PENDING_REQUEST *req)
{
	struct up_list_entry *uple, *tmp;
	int i;

	list_for_each_entry_safe(uple, tmp, &req->up_list, up_list) {
		list_del_init(&uple->up_list);

		if (uple->writable)
			for(i = 0; i < uple->count; i++)
				SetPageDirty(uple->p[i]);

		for(i = 0; i < uple->count; i++)
			page_cache_release(uple->p[i]);

		kfree(uple);
	}
}

static void tg_req_unmap_pages(struct TG_PENDING_REQUEST *req, int nbuf)
{
	struct pci_dev *pdev = req->dev->pci_dev;
	TG_REQ_DESC *sdesc = req->sdesc;
	TG_PAGED_REQUEST *dst = req->dst;
	TG_REQUEST *src = sdesc->src;
	TG_BUFFER *sbuf = sdesc->sbuf;
	TG_PAGED_BUFFER *dbuf;
	int i, dpages;

	dpages = tg_req_unmap_internal(req);

	if (src->InlineByteCount != 0) {
		if (dst->Status == TG_STATUS_SUCCESS)
			memcpy(sdesc->idata, &dst->RequestPages[dpages], src->InlineByteCount);
	}

	dbuf = (TG_PAGED_BUFFER *)
		((char *)&dst->RequestPages[dpages] + INLINE_SIZE(src));

	for (i = 0 ; i < nbuf; i++, sbuf++) {
		int npages;
		u64 *pfn;

		if (!sbuf->ByteCount) {
			dbuf++;
			continue;
		}

		npages = ((sbuf->u.Va & ~PAGE_MASK) +
			sbuf->ByteCount + ~PAGE_MASK) >> PAGE_SHIFT;

		if (dst->Status == TG_STATUS_SUCCESS)
			sbuf->ByteCount = dbuf->ByteCount;

		pfn = (u64 *)(dbuf + 1);
		for (; npages > 0; npages--, pfn++) {
			dma_unmap_page(&pdev->dev, pfn_to_dma_addr(*pfn), PAGE_SIZE,
			               DMA_BIDIRECTIONAL);
		}

		dbuf = (TG_PAGED_BUFFER *)pfn;
	}

	tg_req_unmap_user_pages(req);
}

static struct TG_PENDING_REQUEST *tg_req_create(struct tg_dev *dev, TG_REQ_DESC *sdesc)
{
	struct TG_PENDING_REQUEST *req;
	TG_REQUEST *src = sdesc->src;
	TG_PAGED_REQUEST *dst;
	TG_BUFFER *sbuf;
	TG_PAGED_BUFFER *dbuf;
	int npages, dpages, dsize;
	int nbuf;

	DPRINTK("ENTER\n");

	req = vmalloc(sizeof(struct TG_PENDING_REQUEST));
	if (req == NULL)
		goto err0;

	dsize = tg_req_paged_size(sdesc);
	if ((dsize < 0) || ((dst = vmalloc(dsize)) == NULL)) {
		DPRINTK("ENTER-1: dsize:%d\n", dsize);
		goto err1;
	}

	dst->RequestSize = dsize;
	dst->Request = src->Request;
	dst->Status = TG_STATUS_PENDING;
	dst->InlineByteCount = src->InlineByteCount;
	dst->BufferCount = src->BufferCount;

	req->dev = dev;
	req->sdesc = sdesc;
	req->dst = dst;
	INIT_LIST_HEAD(&req->pr_list);
	INIT_LIST_HEAD(&req->up_list);

	dpages = tg_req_map_internal(req);
	if (dpages < 0) {
		DPRINTK("[2] dpages:%d\n", dsize);
		goto err2;
	}

	sbuf = sdesc->sbuf;
	if (src->InlineByteCount != 0)
		memcpy(&dst->RequestPages[dpages], sdesc->idata, src->InlineByteCount);

	dbuf = (TG_PAGED_BUFFER *)
		((char *)&dst->RequestPages[dpages] + INLINE_SIZE(src));

	for (nbuf = 0; nbuf < src->BufferCount; nbuf++, sbuf++) {
		if (!sbuf->ByteCount) {
			dbuf->Va = 0;
			dbuf->ByteCount = 0;
			dbuf->Writable = 0;
			dbuf->Reserved = 0;
			dbuf++;
			continue;
		}

		dbuf->Va = sbuf->u.Va;
		dbuf->ByteCount = sbuf->ByteCount;
		dbuf->Writable = sbuf->Writable;
		dbuf->Reserved = 0;

		npages = ((sbuf->u.Va & ~PAGE_MASK) + sbuf->ByteCount + ~PAGE_MASK) >> PAGE_SHIFT;

		if (!prltg_buf_is_kernelspace(sdesc, nbuf))
			dbuf = tg_req_map_user_pages(req, dbuf + 1, sbuf, npages);
		else
			dbuf = tg_req_map_kernel_pages(req, dbuf + 1, sbuf, npages);

		if (IS_ERR(dbuf)) {
			DPRINTK("[3] npages:%d\n", npages);
			goto err3;
		}
	}

	DPRINTK("EXIT (req:%p)\n", req);
	return req;

err3:
	tg_req_unmap_pages(req, nbuf);
err2:
	vfree(dst);
err1:
	vfree(req);
err0:
	DPRINTK("EXIT: can't alloc/map memory for request\n");
	return NULL;
}

static int tg_req_submit(struct TG_PENDING_REQUEST *req)
{
	TG_PAGED_REQUEST *dst = req->dst;
	struct tg_dev *dev = req->dev;
	unsigned long lock_flags;
	int ret = TG_STATUS_CANCELLED;
	DPRINTK("ENTER\n");

	/*
	 * Request memory allocated via vmalloc, so this conversion is possible and
	 * also no any offset inside page needed.
	 */
	req->pg = vmalloc_to_page(dst);
	req->phys = dma_map_page(&dev->pci_dev->dev, vmalloc_to_page(dst), 0,
	                         PAGE_SIZE, DMA_BIDIRECTIONAL);
	if (!req->phys) {
		DPRINTK("Can not allocate memory for DMA mapping\n");
		goto out;
	}

	/* First page must be pinned, others should be pinned by build_request */
	page_cache_get(req->pg);

	do {
		dst->Status = TG_STATUS_PENDING;
		tg_out(dev, TG_PORT_SUBMIT, req->phys);
		ret = dst->Status; // Is request already completed?
	} while(ret == TG_STATUS_SUCCESS && (req->sdesc->flags & TG_REQ_RESTART_ON_SUCCESS));

	if (ret != TG_STATUS_PENDING)
		goto out;

	init_completion(&req->waiting);
	req->processed = 0;

	spin_lock_irqsave(&dev->queue_lock, lock_flags);
	ret = dst->Status;
	/* we can miss interrupt */
	if (ret == TG_STATUS_PENDING)
		list_add_tail(&req->pr_list, &dev->pr_list);
	spin_unlock_irqrestore(&dev->queue_lock, lock_flags);

out:
	if (ret != TG_STATUS_PENDING) {
		page_cache_release(req->pg);
		dma_unmap_page(&dev->pci_dev->dev, req->phys, PAGE_SIZE,
		               DMA_BIDIRECTIONAL);
	}

	DPRINTK("EXIT\n");
	return ret;
}

static int tg_req_complete(struct TG_PENDING_REQUEST *req, int force_cancel)
{
	TG_PAGED_REQUEST *dst = req->dst;
	struct tg_dev *dev = req->dev;
	unsigned long lock_flags;
	int ret = 0, processed;
	DPRINTK("ENTER req:%p desc:%p src:%p dst:%p\n", req, req->sdesc, req->sdesc->src, dst);

	if (force_cancel == 0) {
		/* request can be handled by host, interrupted by signal
		 * or cancelled by suspend */
		if (req->sdesc->flags & TG_REQ_PF_CTX)
			ret = wait_for_completion_killable(&req->waiting);
		else
			ret = wait_for_completion_interruptible(&req->waiting);

		if (ret >= 0)
			goto out;
	}

	if (dst->Status != TG_STATUS_PENDING)
		goto out_wait;

	tg_out(dev, TG_PORT_CANCEL, req->phys);
	DPRINTK("CANCELED req:%p desc:%p src:%p dst:%p sts:%x\n", req, req->sdesc, req->sdesc->src, dst, dst->Status);

	if (dst->Status == TG_STATUS_PENDING)
		goto out_wait;

	spin_lock_irqsave(&dev->queue_lock, lock_flags);

	processed = req->processed;
	if (!processed)
		list_del(&req->pr_list);

	spin_unlock_irqrestore(&dev->queue_lock, lock_flags);

	if (!processed)
		/* Now we are sure that nobody will
		 * complete this request */
		goto out;

out_wait:
	/* we must wait for completion, it accessed rq struct*/
	DPRINTK("waiting for completion\n");
	wait_for_completion(&req->waiting);
out:
	page_cache_release(req->pg);
	dma_unmap_page(&dev->pci_dev->dev, req->phys, PAGE_SIZE, DMA_BIDIRECTIONAL);
	DPRINTK("EXIT\n");
	return ret;
}

static void tg_req_destroy(struct TG_PENDING_REQUEST *req)
{
	TG_REQ_DESC *sdesc = req->sdesc;
	TG_PAGED_REQUEST *dst = req->dst;
	TG_REQUEST *src = sdesc->src;
	DPRINTK("ENTER req:%p desc:%p src:%p dst:%p\n", req, sdesc, src, dst);

	src->Status = dst->Status;
	if (src->InlineByteCount != dst->InlineByteCount)
		printk(PFX "InlineByteCounts are not equal: src %d dst %d\n",
			src->InlineByteCount, dst->InlineByteCount);

	tg_req_unmap_pages(req, src->BufferCount);

	vfree(dst);
	vfree(req);

	DPRINTK("EXIT\n");
	return;
}

int call_tg_sync(struct tg_dev *dev, TG_REQ_DESC *sdesc)
{
	struct TG_PENDING_REQUEST *req;
	struct tg_dev *pdev = dev;

	req = tg_req_create(pdev, sdesc);
	if (req == NULL)
		return -ENOMEM;

	if (tg_req_submit(req) == TG_STATUS_PENDING)
		tg_req_complete(req, 0);

	tg_req_destroy(req);
	return 0;
}
EXPORT_SYMBOL(call_tg_sync);

struct TG_PENDING_REQUEST *call_tg_async_start(struct tg_dev *dev, TG_REQ_DESC *sdesc)
{
	struct TG_PENDING_REQUEST *req;

	req = tg_req_create(dev, sdesc);
	if (req == NULL)
		return NULL;

	if (tg_req_submit(req) == TG_STATUS_PENDING)
		return req;

	tg_req_destroy(req);
	return NULL;
}
EXPORT_SYMBOL(call_tg_async_start);

void call_tg_async_wait(struct TG_PENDING_REQUEST *req)
{
	if (req) {
		tg_req_complete(req, 0);
		tg_req_destroy(req);
	}
}
EXPORT_SYMBOL(call_tg_async_wait);

void call_tg_async_cancel(struct TG_PENDING_REQUEST *req)
{
	if (req) {
		tg_req_complete(req, 1);
		tg_req_destroy(req);
	}
}
EXPORT_SYMBOL(call_tg_async_cancel);
