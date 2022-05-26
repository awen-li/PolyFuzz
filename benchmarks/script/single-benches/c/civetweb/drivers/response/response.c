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
/* Init mock server ... test with CivetWeb client       */
/********************************************************/
struct tcp_func_prm {
	SOCKET sock;
};

struct tRESPONSE {
	char data[4096];
	size_t size;
} RESPONSE;


volatile int mock_server_stop_flag = 0;

static void
mock_server_exit(void)
{
	printf("MOCK server exit\n");
	mock_server_stop_flag = 1;
}


static void *
mock_server_thread(void *arg)
{
	char req[1024 * 16];
	SOCKET svr = (SOCKET)(-1);

	/* Get thread parameters and free arg */
	{
		struct tcp_func_prm *ptcp_func_prm = (struct tcp_func_prm *)arg;
		svr = ptcp_func_prm->sock;
		free(arg);
	}

	mock_server_stop_flag = 0;
	printf("MOCK server ready, sock %i\n", svr);

next_request:
	while (!mock_server_stop_flag) {
		struct sockaddr_in cliadr;
		socklen_t adrlen = sizeof(cliadr);
		int buf_filled = 0;
		int req_ready = 0;

		memset(&cliadr, 0, sizeof(cliadr));

		SOCKET cli = accept(svr, (struct sockaddr *)&cliadr, &adrlen);

		if (cli == -1) {
			int er = errno;
			fprintf(stderr, "Error: Accept failed [%s]\n", strerror(er));
			test_sleep(1);
			goto next_request;
		}

		/* Read request */
		do {
			int r =
			    recv(cli, req + buf_filled, sizeof(req) - buf_filled - 1, 0);
			if (r > 0) {
				buf_filled += r;
				req[buf_filled] = 0;
				if (strstr(req, "\r\n\r\n") != NULL) {
					req_ready = 1;
				}
			} else {
				/* some error */
				int er = errno;
				fprintf(stderr, "Error: Recv failed [%s]\n", strerror(er));
				test_sleep(1);
				goto next_request;
			}
		} while (!req_ready);

		/* Request is complete here.
		 * Now send response */
		send(cli, RESPONSE.data, RESPONSE.size, MSG_NOSIGNAL);

		/* Close connection. */
		shutdown(cli, SHUT_RDWR);
		closesocket(cli);
	}
	return 0;
}


static void
mock_server_init(void)
{
	int r;
	int bind_success = 0;
	SOCKET sock = socket(AF_INET, SOCK_STREAM, 6);
	if (sock == -1) {
		r = errno;
		fprintf(stderr, "Error: Cannot create socket [%s]\n", strerror(r));
		TESTabort();
	}

	for (PORT_NUM_HTTP = 1024; PORT_NUM_HTTP != 0; PORT_NUM_HTTP++) {
		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = inet_addr("127.0.0.1");
		sin.sin_port = htons(PORT_NUM_HTTP);
		r = bind(sock, (struct sockaddr *)&sin, sizeof(sin));
		if (r == 0) {
			bind_success = 1;
			break;
		}
		r = errno;
		fprintf(stderr, "Warning: Cannot bind [%s]\n", strerror(r));
	}

	if (!bind_success) {
		fprintf(stderr, "Error: Cannot bind to any port\n");
		closesocket(sock);
		TESTabort();
	}

	printf("MOCK server running on port %i\n", (int)PORT_NUM_HTTP);

	r = listen(sock, 128);
	if (r != 0) {
		r = errno;
		fprintf(stderr, "Error: Cannot listen [%s]\n", strerror(r));
		closesocket(sock);
		TESTabort();
	}

	pthread_t thread_id;
	pthread_attr_t attr;
	int result;
	struct tcp_func_prm *thread_prm;

	thread_prm = (struct tcp_func_prm *)malloc(sizeof(struct tcp_func_prm));
	if (!thread_prm) {
		fprintf(stderr, "Error: Out of memory\n");
		closesocket(sock);
		TESTabort();
	}
	thread_prm->sock = sock;

	(void)pthread_attr_init(&attr);
	(void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	result = pthread_create(&thread_id,
	                        &attr,
	                        mock_server_thread,
	                        (void *)thread_prm);
	(void)pthread_attr_destroy(&attr);
	if (result != 0) {
		r = errno;
		fprintf(stderr, "Error: Cannot create thread [%s]\n", strerror(r));
		closesocket(sock);
		TESTabort();
	}

}


static inline int
LLVMFuzzerTestOneInput_RESPONSE(const uint8_t *data, size_t size)
{
	if (call_count == 0) {
		mock_server_init();
	}
	call_count++;

	if (size > sizeof(RESPONSE.data)) {
		return 1;
	}

	memcpy(RESPONSE.data, data, size);
	RESPONSE.size = size;

	char errbuf[256];

	struct mg_connection *conn = mg_connect_client(
	    "127.0.0.1", PORT_NUM_HTTP, 0, errbuf, sizeof(errbuf));
	if (!conn) {
		printf("Connect error: %s\n", errbuf);
		test_sleep(1);
		return 1;
	}
	mg_printf(conn, "GET / HTTP/1.0\r\n\r\n");

	int r = mg_get_response(conn, errbuf, sizeof(errbuf), 1000);
	const struct mg_response_info *ri = mg_get_response_info(conn);

	(void)r;
	(void)ri;

	mg_close_connection(conn);
    mock_server_exit ();
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
		LLVMFuzzerTestOneInput_RESPONSE((const uint8_t *)data, n);
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

