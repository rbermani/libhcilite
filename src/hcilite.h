
#include <stdbool.h>
#include <stdint.h>

#ifndef __HCILITE_H
#define __HCILITE_H

typedef void (*hcil_request_func_t)(uint8_t status, uint16_t length,
                                    const void *param, void *user_data);
typedef void (*hcil_notify_func_t)(uint16_t index, uint16_t length,
                                   const void *param, void *user_data);
typedef void (*hcil_destroy_func_t)(void *user_data);

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

struct mgmt *hcil_new_session(void);
void hcil_free_session(struct mgmt *mgmt);
struct mgmt *hcil_mgmt_new(int fd);
int hcil_set_close_on_free(struct mgmt * mgmt, bool val);
int hcil_reply(struct mgmt *mgmt, uint16_t opcode, uint16_t index,
               uint16_t length, const void *param,
               hcil_request_func_t callback);
int hcil_send_nowait(struct mgmt *mgmt, uint16_t opcode, uint16_t index,
                     uint16_t length, const void *param,
                     hcil_request_func_t callback);
int hcil_send(struct mgmt *mgmt, uint16_t opcode, uint16_t index,
              uint16_t length, const void *param,
              hcil_request_func_t callback);


#endif /*  __HCILITE_H */
