
#include <sys/socket.h>
#include <endian.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>

#include "queue.h"
#include "hci_sock.h"

#define MGMT_BUF_LEN 512
#define MGMT_HDR_SIZE (sizeof(struct mgmt_hdr))

typedef void (*mgmt_request_func_t)(uint8_t status, uint16_t length,
                                    const void *param, void *user_data);
typedef void (*mgmt_notify_func_t)(uint16_t index, uint16_t length,
                                   const void *param, void *user_data);
typedef void (*mgmt_destroy_func_t)(void *user_data);

typedef struct req_node {
	unsigned int id;
	uint16_t opcode;
	uint16_t index;
	bool pending;
	bool destroy;
	void *buf;
	uint16_t len;
	mgmt_request_func_t callback;
	void *user_data;
	TAILQ_ENTRY(req_node) nodes;
} req_node_t;

typedef struct notify_node {
	unsigned int id;
	uint16_t event;
	uint16_t index;
	bool removed;
	mgmt_notify_func_t callback;
	mgmt_destroy_func_t destroy;
	void *user_data;
	TAILQ_ENTRY(notify_node) nodes;
} notify_node_t;

typedef TAILQ_HEAD(req_qs, req_node) req_q_t;
typedef TAILQ_HEAD(notify_qs, notify_node) notify_q_t;

struct mgmt {
	int fd;
	bool close_on_free;
	void *buf;
	uint16_t len;
	unsigned int next_request_id;
	unsigned int next_notify_id;
	req_q_t *req_q;
	req_q_t *reply_q;
	notify_q_t *notify_q;
	//TAILQ_HEAD(pending_qs, pending_node) pending_q;
};


static int hcil_create_req(uint16_t opcode, uint16_t index,
                           uint16_t len, const void *param, req_node_t * result)
{
	struct req_node *req;
	struct mgmt_hdr *hdr;

	if (!opcode) {
		return -EIO;
	}

	if (len > 0 && !param) {
		return -EIO;
	}

	req = (struct req_node *) malloc(sizeof(struct req_node));
	if (!req) {
		return -ENOMEM;
	}

	req->len = len + MGMT_HDR_SIZE;
	req->buf = malloc(req->len);
	if (!req->buf) {
		free(req);
		return -ENOMEM;
	}

	if (len > 0) {
		memcpy(req->buf + MGMT_HDR_SIZE, param, len);
	}

	hdr = req->buf;
	hdr->opcode = htobe16(opcode);
	hdr->index = htobe16(index);
	hdr->len = htobe16(len);

	req->opcode = opcode;
	req->index = index;
	result = req;

	return 0;
}

static int hcil_write(struct mgmt *mgmt, req_node_t * req)
{
	do {
		error = write(mgmt->fd, req->buf, req->len);
	} while ((error == -1) && errno == EINTR);

	if (error == -1) {
		if (req->callback) {
			request->callback(MGMT_STATUS_FAILED, 0, NULL, req->user_data);
		}
		return -errno;
	}

	fsync(mgmt->fd);
	req->pending = true;

	return 0;
}

static int hcil_push_req(struct mgmt *mgmt, uint16_t opcode, uint16_t index,
                         uint16_t length, const void *param,
                         mgmt_request_func_t callback,
                         req_q_t *head)
{
	req_node_t *req;
	int error = 0;

	if ((error = hcil_create_req(opcode, index, length, param, callback, req))) {
		return error;
	}

	if (mgmt->next_request_id < 1) {
		mgmt->next_request_id = 1;
	}

	req->id = mgmt->next_request_id++;

	if (head) {
		TAILQ_INSERT_TAIL(head, req, nodes);
	} else if ((error = hcil_write(mgmt, req))) {
		return error;
	}

	return req->id;
}

/* return 1 on no-op, 0 on successful write, errno on fail */
static int hcil_pop(struct mgmt *mgmt, req_q_t * head)
{
	req_node_t *e = NULL;

	if (!TAILQ_EMPTY(head)) {
		e = TAILQ_FIRST(head);
		if ((error = hcil_write(mgmt, e))) {

		}

		TAILQ_REMOVE(head, e, nodes);
		free(e);
		e = NULL;

		return error;
	}

	return 1;
}

static int hcil_pop_write(struct mgmt *mgmt)
{
	int error = 0;
	req_node_t *e = NULL;

	/* reply commands take priority on writes */
	/* allow multiple replies to jump req queue */
	if ((error = hcil_pop(mgmt, mgmt->reply_q))) {
		/* if no-op on reply_q pop, attempt pop on req_q */
		if (error == 1) {
			return hcil_pop(mgmt, mgmt->req_q);
		}
	}

	return error;
}

int hcil_send(struct mgmt *mgmt, uint16_t opcode, uint16_t index,
              uint16_t length, const void *param,
              mgmt_request_func_t callback)
{
	if (!mgmt) {
		return -EIO;
	}

	return hcil_push_req(mgmt, opcode, index, length, param, callback, mgmt->req_q);
}

int hcil_send_nowait(struct mgmt *mgmt, uint16_t opcode, uint16_t index,
                     uint16_t length, const void *param,
                     mgmt_request_func_t callback)
{
	if (!mgmt) {
		return -EIO;
	}

	return hcil_push_req(mgmt, opcode, index, length, param, callback, NULL);
}

int hcil_reply(struct mgmt *mgmt, uint16_t opcode, uint16_t index,
               uint16_t length, const void *param,
               mgmt_request_func_t callback)
{
	if (!mgmt) {
		return -EIO;
	}

	return hcil_push_req(mgmt, opcode, index, length, param, callback, mgmt->reply_q);
}

int hcil_set_close_on_free(struct mgmt * mgmt, bool val)
{
	if (!mgmt) {
		return -EIO;
	}

	mgmt->close_on_free = val;

	return 0;
}

struct mgmt *hcil_mgmt_new(int fd)
{
	struct mgmt *mgmt;

	if (fd < 0) {
		return NULL;
	}

	mgmt = (struct mgmt *) malloc(sizeof(struct mgmt));
	if (!mgmt) {
		return NULL;
	}

	mgmt->fd = fd;
	mgmt->close_on_free = false;

	mgmt->len = MGMT_BUF_LEN;
	mgmt->buf = malloc(MGMT_BUF_LEN);
	if (!mgmt->buf) {
		free(mgmt);
		return NULL;
	}


	TAILQ_INIT(&mgmt->req_q);
	TAILQ_INIT(&mgmt->reply_q);
	TAILQ_INIT(&mgmt->notify_q);

	return mgmt;
}

void hcil_free_session(struct mgmt *mgmt)
{
	if (!mgmt) {
		return;
	}


	if (mgmt->close_on_free) {
		close(mgmt->fd);
	}

	free(mgmt->buf);
	mgmt->buf = NULL;
}

struct mgmt *hcil_new_session(void)
{
	struct mgmt *mgmt;
	union {
		struct sockaddr common;
		struct sockaddr_hci hci;
	} addr;
	int fd;

	fd = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
	            BTPROTO_HCI);
	if (fd < 0) {
		return NULL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.hci.hci_family  = AF_BLUETOOTH;
	addr.hci.hci_dev     = HCI_DEV_NONE;
	addr.hci.hci_channel = HCI_CHANNEL_CONTROL;

	if (bind(fd, &addr.common, sizeof(addr.hci)) < 0) {
		close(fd);
		return NULL;
	}

	mgmt = hcil_mgmt_new(fd);
	if (!mgmt) {
		close(fd);
		return NULL;
	}

	mgmt->close_on_free = true;

	return mgmt;
}

int main(int argc, char *argv[])
{
#if 0
	struct mgmt *mgmt;
	union {
		struct sockaddr common;
		struct sockaddr_hci hci;
	} addr;
	int fd;

	fd = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
	            BTPROTO_HCI);
	if (fd < 0) {
		return NULL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.hci.hci_family = AF_BLUETOOTH;
	addr.hci.hci_dev = HCI_DEV_NONE;
	addr.hci.hci_channel = HCI_CHANNEL_CONTROL;

	if (bind(fd, &addr.common, sizeof(addr.hci)) < 0) {
		close(fd);
		return NULL;
	}
#endif

}
