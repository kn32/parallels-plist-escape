/*
 * Copyright (C) 2007-2017 Parallels International GmbH. All Rights Reserved.
 * http://www.parallels.com
 */

#ifndef __TGREQ_H__
#define __TGREQ_H__

enum {
	TG_BUFFER_READONLY = 0,
	TG_BUFFER_READWRITE = 1,
	TG_BUFFER_WRITEONLY = 3,
};

typedef struct _TG_BUFFER {
	union {
		void *Buffer;
#ifdef _MSC_VER
		unsigned __int64 Va;
#else
		unsigned long long __attribute__((aligned(8))) Va;
#endif
	} u;
	unsigned ByteCount;
	unsigned Writable:2;
	unsigned Reserved:30;
} TG_BUFFER;

// the compiler should align TG_BUFFER to 64-bit
// boundary regardless of pointer size
// alignment is important because buffers follow
// InlineBytes in request structure
struct _TEST_TG_BUFFER_ALIGNMENT {
	char unaligned;
	TG_BUFFER test;
};

struct _ASSERT_TG_BUFFER_ALIGNMENT {
	char test[2 * (sizeof(struct _TEST_TG_BUFFER_ALIGNMENT) == (sizeof(TG_BUFFER) + 8)) - 1];
};

typedef struct _TG_REQUEST {
	unsigned Request;
	unsigned Status;
	unsigned short InlineByteCount;
	unsigned short BufferCount;
	unsigned Reserved;
} TG_REQUEST;

#endif // __TGREQ_H__
