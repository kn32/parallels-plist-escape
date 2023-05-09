/*
 * Copyright (C) 1999-2016 Parallels International GmbH. All Rights Reserved.
 * Linux guest specific PCI toolgate userspace interface definitions
 */

#ifndef __PRL_TG_H__
#define __PRL_TG_H__

typedef struct _TG_REQ_DESC {
	struct _TG_REQUEST *src;
	void *idata;
	struct _TG_BUFFER *sbuf;
	int flags; /* See TG_REQ_* definitions below. */

	/* Bitset that marks corresponding TG_BUFFERs as related to the
	 * kernelspace. There is an implicit limit of 32 bufs that allowed
	 * to be kernelspace
	 */
	unsigned kernel_bufs;
} TG_REQ_DESC;

#define prltg_buf_set_kernelspace(sdesc, num) \
	do {BUG_ON((num) >= 32); (sdesc)->kernel_bufs |= 1 << (num);} while(0)

#define prltg_buf_is_kernelspace(sdesc, num) \
	(((num) < 32) && (sdesc)->kernel_bufs & (1 << (num)))

#define TG_REQ_COMMON				0	/* Just common request made from syscall handler. */
#define TG_REQ_PF_CTX				1	/* Request is made from page fault handler. */
#define TG_REQ_RESTART_ON_SUCCESS	2	/* Restart request if it was completed successfully. */

#define PROC_PREFIX						"/proc/driver/"
#define TOOLGATE_NICK_NAME				"prl_tg"
#define VIDEO_TOOLGATE_NICK_NAME		"prl_vtg"
#define VIDEO_DRM_TOOLGATE_NICK_NAME	"prl_drm"

#define PRL_TG_FILE		PROC_PREFIX TOOLGATE_NICK_NAME
#define PRL_VTG_FILE	PROC_PREFIX VIDEO_TOOLGATE_NICK_NAME

struct draw_bdesc {
	union {
		void *pbuf;
		unsigned long long va;
	} u;
	unsigned int id;
	unsigned int bsize;
	unsigned int used;
	unsigned int pad; /* not used, only for structure alignment */
};

#define VIDTG_CREATE_DRAWABLE		_IO  ('|',0)
#define VIDTG_CLIP_DRAWABLE			_IOWR('|',1, struct draw_bdesc)
#define VIDTG_DESTROY_DRAWABLE		_IO  ('|',2)
#define VIDTG_GET_MEMSIZE			_IOR ('|',3, unsigned int)
#define VIDTG_ACTIVATE_SVGA			_IO  ('|',4)

/*
 * CREATE/CLIP/DESTROY/_DRAWABLE, GET_MEMSIZE, ACTIVATE_SVGA - equivalent for VTG ioctls
 * HOST_REQUEST - common replacement for write() in VTG
 * ENABLE_HEAD,.. - new ioctls
 *
 * Max code = DRM_COMMAND_END - DRM_COMMAND_BASE = 0x60
 */
#define PRL_DRM_CREATE_DRAWABLE		0
#define PRL_DRM_CLIP_DRAWABLE		1
#define PRL_DRM_DESTROY_DRAWABLE	2
#define PRL_DRM_GET_MEMSIZE			3
#define PRL_DRM_ACTIVATE_SVGA		4
#define PRL_DRM_HOST_REQUEST		5
#define PRL_DRM_ENABLE_HEADS		6
#define PRL_DRM_ADD_MODE_FOR_HEAD	7
// Find,bind,unbind,resize,export or create new image
#define PRL_DRM_IMAGE_CREATE		8
// Release image
#define PRL_DRM_IMAGE_RELEASE		9
#define PRL_DRM_GET_DUMB_PARAMS		10

#define IMAGE_DESC_FORMAT_MAX		60
struct image_desc {
	unsigned int handle;	// dumb buffer handle
	unsigned int width;		// image width
	unsigned int height;	// image height
	unsigned int offset;	// offset from start of dumb buffer
	unsigned int pbuffer;	// host pbuffer handle
	unsigned short pformat[IMAGE_DESC_FORMAT_MAX];
};

struct mode_desc {
	unsigned int index;		// head index
	unsigned int width;
	unsigned int height;
};

struct dumb_params_desc {
	unsigned int handle; // dumb buffer handle
	unsigned long long aperture_addr;
};

struct dbg_vmcoreinfo_desc {
	unsigned long long note_paddr;
};

#endif
