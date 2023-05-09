#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/types.h>

#include "../Interfaces/prltg.h"
#include "../../Interfaces/tgreq.h"

int
main(int argc, char *argv[])
{
	int fd, ret;
	char buf0[32];
	struct {
		TG_REQUEST req;
		TG_BUFFER buf[1];
	} req = {
		{ 0x8000, 0, 0, 1, 0 },
		{
			{ { buf0 }, sizeof(buf0), 1 }
	}
	};

	void *p = &req;

	fd = open(PRL_TG_FILE, O_WRONLY);
	if (fd < 0) {
		perror("opening PRL_TG_FILE");
		exit(-1);
	}
	if (write(fd, &p, 0) < 0)
		perror("write 0");
	if (write(fd, &p, 1) < 0)
		perror("write 1");
	if (write(fd, &p, 2) < 0)
		perror("write 2");
	if (write(fd, &p, 3) < 0)
		perror("write 3");

	if (write(fd, &p, sizeof(p)) < 0) {
		perror("write request");
		exit(-2);
	}
	printf("req.Status=%08x\n", req.req.Status);
	if (close(fd) < 0) {
		perror ("closing PRL_TG_FILE");
		exit(-3);
	}
	return 0;
}
