/********************************************************/
/*                                                      */
/*   FUZZ TEST for civetweb.c                           */
/*                                                      */
/*   Copyright (c) 2015-2020 the CivetWeb developers    */
/*                                                      */
/*   This file contains test code for fuzz tests.       */
/*   It should not be used in production code.          */
/*                                                      */
/********************************************************/

#include "civetweb.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>


#if defined(_WIN32)
#error "Currently not supported"
#else

#include <unistd.h>
#define test_sleep(x) (sleep(x))
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
typedef int SOCKET;
#define closesocket(a) (close(a))

#endif // not _WIN32


/* Port configuration */
unsigned short PORT_NUM_HTTP = 0; /* set dynamically */


#define TESTabort()                                                            \
	{                                                                          \
		fprintf(stderr, "!!! Precondition in test environment not met !!!\n"); \
		fprintf(stderr, "!!! aborting fuzz test in line %u !!!", __LINE__);    \
		abort();                                                               \
	}


static uint64_t call_count = 0;


/********************************************************/
/* Init CivetWeb server ... test with mock client       */
/********************************************************/
static struct mg_context *ctx = 0;
static const char *OPTIONS[] = {"listening_ports",
                                "0", /* port: auto */
                                "document_root",
                                "fuzztest/docroot",
                                NULL,
                                NULL};

static void
civetweb_exit(void)
{
	printf("CivetWeb server exit\n");
	//mg_stop(ctx);
	ctx = 0;
	exit (0);
}


static void
civetweb_init(void)
{
	struct mg_callbacks callbacks;
	struct mg_server_port ports[8];
	memset(&callbacks, 0, sizeof(callbacks));
	memset(&ports, 0, sizeof(ports));

	ctx = mg_start(&callbacks, 0, OPTIONS);

	if (!ctx) {
		fprintf(stderr, "\nCivetWeb test server failed to start\n");
		TESTabort();
	}

	int ret = mg_get_server_ports(ctx, 8, ports);
	if (ret != 1) {
		fprintf(stderr,
		        "\nCivetWeb test server: cannot determine port number\n");
		TESTabort();
	}
	if (ports[0].is_ssl != 0) {
		fprintf(stderr,
		        "\nCivetWeb fuzz test works on HTTP, not HTTPS.\n"
		        "TLS library should be fuzzed separately.\n");
		TESTabort();
	}
	PORT_NUM_HTTP = ports[0].port;

	printf("CivetWeb server running on port %i\n", (int)PORT_NUM_HTTP);
}


static inline int
LLVMFuzzerTestOneInput_REQUEST(const uint8_t *data, size_t size)
{
	if (call_count == 0) {
		civetweb_init();
	}
	call_count++;

	int r;
	SOCKET sock = socket(AF_INET, SOCK_STREAM, 6);
	if (sock == -1) {
		r = errno;
		fprintf(stderr, "Error: Cannot create socket [%s]\n", strerror(r));
		return 1;
	}
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");
	sin.sin_port = htons(PORT_NUM_HTTP);
	r = connect(sock, (struct sockaddr *)&sin, sizeof(sin));
	if (r != 0) {
		r = errno;
		fprintf(stderr, "Error: Cannot connect [%s]\n", strerror(r));
		closesocket(sock);
		return 1;
	}

	char trash[1024];
	r = send(sock, data, size, 0);
	if (r != (int)size) {
		fprintf(stderr, "Warning: %i bytes sent (TODO: Repeat)\n", r);
	}

	int data_read = 0;
	while ((r = recv(sock, trash, sizeof(trash), 0)) > 0) {
		data_read += r;
	};

	shutdown(sock, SHUT_RDWR);
	closesocket(sock);

	static int max_data_read = 0;
	if (data_read > max_data_read) {
		max_data_read = data_read;
		printf("GOT data: %i\n", data_read);
	}

	civetweb_exit ();
	return 0;
}


static inline void
test_one_file(const char *filename) {
	int fd;
	struct stat st;
	char *data;
	ssize_t n;

	if ((fd = open(filename, O_RDONLY)) == -1) {
		fprintf(stderr, "Failed to open %s: %s\n", filename,
			strerror(errno));
		return;
	}

	if (fstat(fd, &st) != 0) {
		fprintf(stderr, "Failed to stat %s: %s\n", filename,
			strerror(errno));
		goto closefd;
	}

	data = (char *)malloc(st.st_size);
	n = read(fd, data, st.st_size);
	if (n == st.st_size) {
		printf("testing %zd bytes from %s\n", n, filename);
		fflush(stdout);
		LLVMFuzzerTestOneInput_REQUEST((const uint8_t *)data, n);
		fflush(stderr);
	} else {
		if (n < 0) {
			fprintf(stderr,
				"Failed to read %zd bytes from %s: %s\n",
				(ssize_t)st.st_size, filename, strerror(errno));
		} else {
			fprintf(stderr,
				"Failed to read %zd bytes from %s, got %zd\n",
				(ssize_t)st.st_size, filename, n);
		}
	}
	free(data);
closefd:
	close(fd);
}


int main(int argc, char **argv) {

    if (argc < 2)
    {
        printf ("@@@Please specify the input path!!\r\n");
        return 0;
    }

    test_one_file (argv[1]);
    return 0;
}




