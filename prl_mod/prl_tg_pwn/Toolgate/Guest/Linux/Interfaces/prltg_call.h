/*
 * Copyright (C) 1999-2018 Parallels International GmbH. All Rights Reserved.
 */

#include "prltg.h"

struct tg_dev;
extern int call_tg_sync(struct tg_dev *dev, TG_REQ_DESC *sdesc);
extern struct TG_PENDING_REQUEST *call_tg_async_start(struct tg_dev *dev, TG_REQ_DESC *sdesc);
extern void call_tg_async_wait(struct TG_PENDING_REQUEST *req);
extern void call_tg_async_cancel(struct TG_PENDING_REQUEST *req);

#define TOOLGATE_DEV_DEFAULT (struct tg_dev *)0x1234
