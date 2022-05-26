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


static int
test_civetweb_client(const char *server,
                     uint16_t port,
                     int use_ssl,
                     const char *uri)
{
	/* Client var */
	struct mg_connection *client;
	char client_err_buf[256];
	char client_data_buf[4096];
	const struct mg_response_info *client_ri;
	int64_t data_read;
	int r;

	client = mg_connect_client(
	    server, port, use_ssl, client_err_buf, sizeof(client_err_buf));

	if ((client == NULL) || (0 != strcmp(client_err_buf, ""))) {
		fprintf(stderr,
		        "%s connection to server [%s] port [%u] failed: [%s]\n",
		        use_ssl ? "HTTPS" : "HTTP",
		        server,
		        port,
		        client_err_buf);
		if (client) {
			mg_close_connection(client);
		}

		/* In heavy fuzz testing, sometimes we run out of available sockets.
		 * Wait for some seconds, and retry. */
		test_sleep(5);

		/* retry once */
		client = mg_connect_client(
		    server, port, use_ssl, client_err_buf, sizeof(client_err_buf));
		if (!client) {
			fprintf(stderr, "Retry: error\n");
			return 1;
		}
		fprintf(stderr, "Retry: success\n");
	}

	mg_printf(client, "GET %s HTTP/1.0\r\n\r\n", uri);

	r = mg_get_response(client, client_err_buf, sizeof(client_err_buf), 10000);

	if ((r < 0) || (0 != strcmp(client_err_buf, ""))) {
		mg_close_connection(client);
		return 1;
	}

	client_ri = mg_get_response_info(client);
	if (client_ri == NULL) {
		mg_close_connection(client);
		return 1;
	}

	data_read = 0;
	while (data_read < client_ri->content_length) {
		/* store the first sizeof(client_data_buf) bytes
		 * of the HTTP response. */
		r = mg_read(client,
		            client_data_buf + data_read,
		            sizeof(client_data_buf) - (size_t)data_read);
		if (r > 0) {
			data_read += r;
		}

		/* buffer filled? */
		if (sizeof(client_data_buf) == (size_t)data_read) {
			/* ignore the rest */
			while (r > 0) {
				char trash[1024];
				r = mg_read(client, trash, sizeof(trash));
			}
			break;
		}
	}

	/* Nothing left to read */
	r = mg_read(client, client_data_buf, sizeof(client_data_buf));
	if (r != 0) {
		mg_close_connection(client);
		return 1;
	}

	mg_close_connection(client);
	return 0;
}


static inline int
LLVMFuzzerTestOneInput_URI(const uint8_t *data, size_t size)
{
	static char URI[1024 * 64]; /* static, to avoid stack overflow */

	if (call_count == 0) {
	    civetweb_init ();
		memset(URI, 0, sizeof(URI));
	}
	call_count++;

	if (size < sizeof(URI)) {
		memcpy(URI, data, size);
		URI[size] = 0;
	} else {
		return 1;
	}

	test_civetweb_client("127.0.0.1", PORT_NUM_HTTP, 0, URI);

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
		LLVMFuzzerTestOneInput_URI((const uint8_t *)data, n);
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

