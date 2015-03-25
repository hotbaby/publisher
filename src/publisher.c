/*************************************************************************
> File Name: publisher.c
> Author: yy
> Mail: mengyy_linux@163.com
 ************************************************************************/

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <curl/curl.h>

#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/list.h>
#include <libubus.h>
#include <json/json.h>

#define TIMER_INTERVAL      (100)   /* ms */

typedef struct curl_buffer{
    const char  *buff;
    int         len;
    int         pos;
}curl_buffer_t;

typedef struct msg_queue {
    char                *buffer;
    uint32_t            buffer_size;
    struct list_head    list;
}msg_queue_t;

typedef struct uloop_time_ctx{
    struct uloop_timeout    timeout;    
}uloop_timer_ctx_t;

typedef enum {
    TYPE_UBUS_OBJECT_ADD = 0,
    TYPE_UBUS_OBJECT_REMOTE,
    TYPE_UBUS_MAX,
}TYPE_METHOD;

static const char *types[] = {
    [TYPE_UBUS_OBJECT_ADD]      = "ubus.object.add",
    [TYPE_UBUS_OBJECT_REMOTE]   = "ubus.object.remove",
};

struct list_head q;

static struct ubus_subscriber notifier_event;

static void notifier_listen(struct ubus_context *ctx);
static void notifier_subscribe(struct ubus_context *ctx, uint32_t id);
static void notifier_unsubscribe(struct ubus_context *ctx, uint32_t id);

static void enqueue(struct list_head *new,
        struct list_head *queue)
{
    list_add_tail(new, queue);
}

static struct list_head* dequeue(struct list_head *queue)
{
    if (list_empty(queue))
    {
        return NULL;
    }

    struct list_head *node = queue->next;
    list_del(node);

    return node;
}

size_t curl_read_cb(void *ptr, size_t size, size_t nitems, void *stream)
{
    curl_buffer_t *buffer = (curl_buffer_t *)stream;

    int len = buffer->len - buffer->pos;
    if (len > size * nitems)
    {
        len = size * nitems;
    }

    memcpy(ptr, buffer->buff + buffer->pos, len);
    buffer->pos += len;

    return len;
}

static int event_notify_cb(struct ubus_context *ctx,
        struct ubus_object *obj,
        struct ubus_request_data *req,
        const char *method,
        struct blob_attr *msg)
{
    char        *str = NULL;

    str = blobmsg_format_json(msg, true);

    fprintf(stderr, "Received notification '%s': %s\n", method, str);

    if (str)
    {
#if 0
        msg_queue_t *node = NULL;
        const int   msg_buff_size = 512;

        /* optimize memory management */
        node = calloc(1, sizeof(*node));
        assert(node != NULL);

        node->buffer = calloc(1, msg_buff_size);
        assert(node->buffer != NULL);
        node->buffer_size = sprintf(node->buffer, "Received notification '%s': %s", method, str);

        enqueue(&node->list, &q);
#else

        CURL            *curl = NULL;
        uint32_t        size;
        curl_buffer_t   curl_buffer;
        char            *tmp_buf;


        tmp_buf = calloc(1, strlen(str) * 2);
        assert(tmp_buf != NULL);

        curl_buffer.len = sprintf(tmp_buf, "Received notification '%s': '%s'\n", method, str);
        curl_buffer.buff = tmp_buf;
        curl_buffer.pos = 0;

        curl = curl_easy_init();
        assert(curl != NULL);

        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
        curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1/pub?id=my_channel_1");
        curl_easy_setopt(curl, CURLOPT_POST, 1);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, curl_buffer.len);
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

        curl_easy_setopt(curl, CURLOPT_READFUNCTION, curl_read_cb);
        curl_easy_setopt(curl, CURLOPT_READDATA, &curl_buffer);

        curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        if (tmp_buf)
        {
            free(tmp_buf);
            tmp_buf = NULL;
        }
    }
#endif

    if (str)
    {
        free(str);
        str = NULL;
    }

    return 0;
}

static void event_remove_cb(struct ubus_context *ctx,
        struct ubus_subscriber *s,
        uint32_t id)
{
    fprintf(stderr, "Object %08x went away\n", id);
}


static void notifier_subscribe(struct ubus_context *ctx, uint32_t id)
{
    int             ret;
    const char      *path = NULL;
    static bool     registered = 0;

    fprintf(stderr, "notifier subscribe id:0x%x\n", id);

    if (!registered)
    {
        ubus_register_subscriber(ctx, &notifier_event);
    }

    notifier_event.remove_cb = event_remove_cb;
    notifier_event.cb = event_notify_cb;

    ret = ubus_subscribe(ctx, &notifier_event, id);

    return;
}

static void notifier_unsubscribe(struct ubus_context *ctx, uint32_t id)
{
    fprintf(stderr, "notifier unsubscribe id:0x%x\n", id);

    ubus_unsubscribe(ctx, &notifier_event, id);

    return;
}

static void listener_hander_cb(struct ubus_context *ctx,
        struct ubus_event_handler *ev,
        const char *type,
        struct blob_attr *msg)
{
    int         i;
    int         event_type;
    const char  *json_string = NULL;
    json_object *json_obj;
    uint32_t    id;
    const char  *path = NULL;

    json_string = blobmsg_format_json(msg, true);
    fprintf(stderr, "{ \"%s\": %s  }\n", type, json_string);

    for(i = 0; i < TYPE_UBUS_MAX; i++)
    {
        if (!strncmp(type, types[i], strlen(types[i])))
        {
            event_type = i;
        }
    }

    {
        json_obj = json_tokener_parse(json_string);

        json_object_object_foreach(json_obj, key, val)
        {
            if (!strncmp(key, "id", strlen("id"))
                    && json_object_get_type(val) == json_type_int)
            {
                id = json_object_get_int(val);
            }
            else if (!strncmp(key, "path", strlen("path"))
                    && json_object_get_type(val) == json_type_string)
            {
                path = strdup(json_object_get_string(val));
            }
            else
            {
                /* nothing to do */
            }
        }

        json_object_put(json_obj);
    }
    
    switch(event_type)
    {
        case TYPE_UBUS_OBJECT_ADD:

            notifier_subscribe(ctx, id);
            notifier_listen(ctx);
            break;

        case TYPE_UBUS_OBJECT_REMOTE:

            notifier_unsubscribe(ctx, id);
            break;

        default:
            break;
    }

    if (path != NULL)
    {
        free((void*)path);
        path = NULL;    
    }

    if (json_string != NULL)
    {
        free((void*)json_string);
        json_string = NULL;
    }

    return;
}

static void notifier_listen(struct ubus_context *ctx)
{
    const char  *pattern = "*";
    static struct ubus_event_handler    listener;

    memset(&listener, 0, sizeof(listener));
    listener.cb = listener_hander_cb;

    ubus_register_event_handler(ctx, &listener, pattern);

    return;
}

static void notifier_register(struct ubus_context *ctx)
{
    uint32_t    id;
    const char  *hostapd_default_path_1 = "hostapd.wlan0";
    const char  *hostapd_default_path_2 = "hostapd.wlan1";

    if (!ubus_lookup_id(ctx, hostapd_default_path_1, &id))
    {
        notifier_subscribe(ctx, id);
    }

    if (!ubus_lookup_id(ctx, hostapd_default_path_2, &id))
    {
        notifier_subscribe(ctx, id);
    }

    notifier_listen(ctx);
}

static void timer_handler_cb(struct uloop_timeout *t)
{
    return ;

    uloop_timer_ctx_t   *timer_ctx = NULL;
    struct list_head    *list = NULL;

    list = dequeue(&q);

    if (list)
    {
        int                 nret;
        char                http_header[512] = {0};  /* ensure large enough */
        uint32_t            http_header_size;
        char                *offset = NULL;
        struct msg_queue    *node = NULL;

        node = container_of(list, msg_queue_t, list);
        fprintf(stderr, "send to web subscriber msg:%s\n", node->buffer);

    
        offset = http_header;
        nret = sprintf(offset, "POST /pub?id=my_channel_1 HTTP/1.1\r\n");
        nret = sprintf(offset + nret, "Host: 127.0.0.1\r\n");
        nret = sprintf(offset + nret, "Accept: */*\r\n");
        nret = sprintf(offset + nret, "Content-Length: %d\r\n", node->buffer_size);
        nret = sprintf(offset + nret, "Content-Type: text/plain\r\n");
        nret = sprintf(offset + nret, "\r\n");
        offset += nret;

        http_header_size = offset - http_header;

        /* send http header */

        /* send http body */

        /* free message queue node memory */
        free((void*)node->buffer);
        node->buffer = NULL;
        free((void*)node);
        node = NULL;
    }

    uloop_timeout_set(t, TIMER_INTERVAL);
}

int main(int argc, char **argv)
{
    struct ubus_context     *ubus_ctx;
    uloop_timer_ctx_t       timer_ctx;

    uloop_init();
    signal(SIGPIPE, SIG_IGN);

    INIT_LIST_HEAD(&q);

    ubus_ctx = ubus_connect(NULL);
    assert(ubus_ctx != NULL);

    ubus_add_uloop(ubus_ctx);

    notifier_register(ubus_ctx);

    memset(&timer_ctx, 0, sizeof(timer_ctx));
    timer_ctx.timeout.cb = timer_handler_cb;
    timer_ctx.timeout.pending = false;

    uloop_timeout_set(&timer_ctx.timeout, TIMER_INTERVAL);

    uloop_run();

    ubus_free(ubus_ctx);
    uloop_done();

    return 0;
}
