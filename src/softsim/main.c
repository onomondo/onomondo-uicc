/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/utils.h>

#define VPCD_PORT 0x8C7B
#define VPCD_HOST "127.0.0.1"

#define VPCD_CTRL_OFF 0x00
#define VPCD_CTRL_ON 0x01
#define VPCD_CTRL_RESET 0x02
#define VPCD_CTRL_ATR 0x04

bool running = true;
#define POLL_INTERVAL 5 /* sec */

static int vpcd_rx(int socket_fd, uint8_t *buf, size_t len)
{
	int rc;
	uint16_t len_rx;
	uint16_t len_bytes;

	/* Receive length */
	rc = read(socket_fd, &len_rx, sizeof(len_rx));
	if (rc != 2) {
		SS_LOGP(SVPCD, running ? LERROR : LINFO, "vpcd_rx: error reading length -- abort!\n");
		return -EINVAL;
	}
	len_bytes = ntohs(len_rx);
	if (len_bytes > len) {
		SS_LOGP(SVPCD, LERROR, "vpcd_rx: buffer too small (%lu < %u) -- abort!\n", len, len_bytes);
		return -EINVAL;
	}

	/* Receive data */
	rc = read(socket_fd, buf, len_bytes);
	if (rc < 0) {
		SS_LOGP(SVPCD, LERROR, "vpcd_rx: no data received -- abort!\n");
		return -EINVAL;
	}

	SS_LOGP(SVPCD, LDEBUG, "vpcd_rx: received %u bytes: %04x:%s\n", rc, len_rx, ss_hexdump(buf, rc));

	return rc;
}

static int vpcd_tx(int socket_fd, uint8_t *buf, size_t len)
{
	uint16_t len_tx;
	int rc;

	assert(len <= 0xffff);

	len_tx = htons((uint16_t)len);
	SS_LOGP(SVPCD, LDEBUG, "vpcd_tx: sending %lu bytes: %04x:%s\n", len, len_tx, ss_hexdump(buf, len));
	rc = write(socket_fd, &len_tx, sizeof(len_tx));
	if (rc != 2)
		return -EINVAL;
	rc = write(socket_fd, buf, len);
	if (rc != len)
		return -EINVAL;

	return 0;
}

static int handle_request(struct ss_context *ctx, int socket_fd)
{
	uint8_t vpcd_pdu[65536];
	int rc;
	uint8_t card_response[256 + 2];
	size_t card_response_len;

	rc = vpcd_rx(socket_fd, vpcd_pdu, sizeof(vpcd_pdu));
	if (rc < 0) {
		SS_LOGP(SVPCD, running ? LERROR : LINFO, "VPCD socket disconnected, terminating\n");
		exit(0);
	}
	if (rc == 1) {
		/* Control byte */
		switch (vpcd_pdu[0]) {
		case VPCD_CTRL_OFF:
			SS_LOGP(SVPCD, LDEBUG, "POWER OFF request => reset\n");
			ss_reset(ctx);
			break;
		case VPCD_CTRL_ON:
			SS_LOGP(SVPCD, LDEBUG, "POWER ON request => reset\n");
			ss_reset(ctx);
			break;
		case VPCD_CTRL_RESET:
			SS_LOGP(SVPCD, LDEBUG, "RESET request\n");
			ss_reset(ctx);
			break;
		case VPCD_CTRL_ATR:
			SS_LOGP(SVPCD, LDEBUG, "ATR request\n");
			card_response_len = ss_atr(ctx, card_response, sizeof(card_response));
			vpcd_tx(socket_fd, card_response, card_response_len);
			break;
		default:
			SS_LOGP(SVPCD, LDEBUG, "Invalid request => ignored\n");
		}
	} else {
		size_t request_length = rc;
		/* Card APDU */
		card_response_len = ss_transact(ctx, card_response, sizeof(card_response), vpcd_pdu, &request_length);
		if (request_length >= 0 && request_length < rc)
			SS_LOGP(SVPCD, LERROR, "APDU contained trailing bytes that were ignored.\n");
		vpcd_tx(socket_fd, card_response, card_response_len);
	}
	return rc;
}

/* Subtract timeval y from x, see also:
 * https://www.gnu.org/software/libc/manual/html_node/Calculating-Elapsed-Time.html */
int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y)
{
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;
	return x->tv_sec < y->tv_sec;
}

/* Handle regular polling of the softsim (proactive SIM tasks) */
static void handle_poll(struct ss_context *ctx)
{
	struct timeval time;
	static struct timeval time_prev = {};
	struct timeval time_elapsed;
	static struct timeval timer = {};
	int rc;

	gettimeofday(&time, NULL);
	if (time_prev.tv_sec == 0 && time_prev.tv_usec == 0)
		time_prev = time;

	rc = timeval_subtract(&time_elapsed, &time, &time_prev);
	if (rc < 0) {
		goto leave;
	}

	if (timer.tv_usec + time_elapsed.tv_usec > 999999) {
		timer.tv_usec = (timer.tv_usec + time_elapsed.tv_usec) - 1000000;
		timer.tv_sec = timer.tv_sec + time_elapsed.tv_sec + 1;
	} else {
		timer.tv_usec = timer.tv_usec + time_elapsed.tv_usec;
		timer.tv_sec = timer.tv_sec + time_elapsed.tv_sec;
	}

	if (timer.tv_sec >= POLL_INTERVAL) {
		ss_poll(ctx);
		timer.tv_sec = 0;
		timer.tv_usec = 0;
	}

leave:
	time_prev = time;
}

/*! Terminate the program regularly.
 *
 * This allows a test environment to send SIGUSR1 to the process when it is
 * done. As opposed to any default handler, this lets the process exit
 * successfully in the regular case, whereas the address sanitizer (ASAN) has
 * still a chance to run and set an unsuccessful exit state if any memory leaks
 * were detected.
 */
static void sig_usr1(int signum)
{
	running = false;
}

int main(void)
{
	int socket_fd;
	int socket_flag;
	struct sockaddr_in vpcd_server_addr;
	struct ss_context *ctx;
	fd_set fdset;
	int rc;
	struct timeval select_timer;
	struct timeval select_timeout;

	signal(SIGUSR1, sig_usr1);

	SS_LOGP(SVPCD, LINFO, "softsim!\n");

	ctx = ss_new_ctx();

	socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_fd < 0) {
		SS_LOGP(SVPCD, LERROR, "cannot create socket for VPCD server -- abort!\n");
		exit(1);
	}

	vpcd_server_addr.sin_family = AF_INET;
	vpcd_server_addr.sin_addr.s_addr = inet_addr(VPCD_HOST);
	vpcd_server_addr.sin_port = htons(VPCD_PORT);

	socket_flag = 1;
	if (setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&socket_flag, sizeof(socket_fd))) {
		SS_LOGP(SVPCD, LERROR, "cannot set socket options -- abort!\n");
		exit(1);
	}

	if (connect(socket_fd, (struct sockaddr *)&vpcd_server_addr, sizeof(vpcd_server_addr)) != 0) {
		SS_LOGP(SVPCD, LERROR, "cannot connect to VPCD server -- abort!\n");
		exit(1);
	}

	SS_LOGP(SVPCD, LINFO, "connected.\n");

	FD_ZERO(&fdset);
	FD_SET(socket_fd, &fdset);

	select_timeout.tv_sec = 0;
	select_timeout.tv_usec = 500000;

	while (running) {
		select_timer = select_timeout;

		rc = select(socket_fd + 1, &fdset, NULL, NULL, &select_timer);
		if (rc < 0)
			SS_LOGP(SVPCD, LERROR, "error in select -- abort!\n");
		else if (rc)
			handle_request(ctx, socket_fd);
		else
			SS_LOGP(SVPCD, LERROR, "select timeout -- pcscd silent?\n");

		handle_poll(ctx);
	}

	ss_free_ctx(ctx);

	return 0;
}
