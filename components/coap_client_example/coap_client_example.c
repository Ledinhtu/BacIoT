#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/param.h>


#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"

#include "nvs_flash.h"

#include "protocol_examples_common.h"

#include "coap3/coap.h"


#ifndef CONFIG_COAP_CLIENT_SUPPORT
#error COAP_CLIENT_SUPPORT needs to be enabled
#endif /* COAP_CLIENT_SUPPORT */

#define COAP_DEFAULT_TIME_SEC 60

/* The examples use uri Logging Level that
   you can set via 'idf.py menuconfig'.

   If you'd rather not, just change the below entry to a value
   that is between 0 and 7 with
   the config you want - ie #define EXAMPLE_COAP_LOG_DEFAULT_LEVEL 7
*/
#define EXAMPLE_COAP_LOG_DEFAULT_LEVEL CONFIG_COAP_LOG_DEFAULT_LEVEL

/* The examples use uri "coap://californium.eclipseprojects.io" that
   you can set via the project configuration (idf.py menuconfig)

   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define COAP_DEFAULT_DEMO_URI "coaps://californium.eclipseprojects.io"
*/
#define COAP_DEFAULT_DEMO_URI CONFIG_EXAMPLE_TARGET_DOMAIN_URI

const static char *TAG = "CoAP_client_example";

static int resp_wait = 1;
static coap_optlist_t *optlist = NULL;
static int wait_ms;

/**
 * 
*/
static coap_response_t
message_handler(coap_session_t *session,
                const coap_pdu_t *sent,
                const coap_pdu_t *received,
                const coap_mid_t mid)
{
    const unsigned char *data = NULL;
    size_t data_len;
    size_t offset;
    size_t total;
    coap_pdu_code_t rcvd_code = coap_pdu_get_code(received);


    if (COAP_RESPONSE_CLASS(rcvd_code) == 2) {
        if (coap_get_data_large(received, &data_len, &data, &offset, &total)) {
            if (data_len != total) {
                printf("Unexpected partial data received offset %u, length %u\n", offset, data_len);
            }
            printf("Received:\n%.*s\n", (int)data_len, data);
            resp_wait--;
        }
        return COAP_RESPONSE_OK;
    }
    printf("%d.%02d", (rcvd_code >> 5), rcvd_code & 0x1F);
    if (coap_get_data_large(received, &data_len, &data, &offset, &total)) {
        printf(": ");
        while(data_len--) {
            printf("%c", isprint(*data) ? *data : '.');
            data++;
        }
    }
    printf("\n");
    resp_wait--;
    return COAP_RESPONSE_OK;
}


/**
 * 
*/
static void
coap_log_handler (coap_log_t level, const char *message)
{
    uint32_t esp_level = ESP_LOG_INFO;
    char *cp = strchr(message, '\n');

    if (cp)
        ESP_LOG_LEVEL(esp_level, TAG, "%.*s", (int)(cp-message), message);
    else
        ESP_LOG_LEVEL(esp_level, TAG, "%s", message);
}

/**
 * 
*/
static coap_address_t *
coap_get_address(coap_uri_t *uri)
{
  static coap_address_t dst_addr;
    char *phostname = NULL;
    struct addrinfo hints;
    struct addrinfo *addrres;
    int error;
    char tmpbuf[INET6_ADDRSTRLEN];

    phostname = (char *)calloc(1, uri->host.length + 1);
    if (phostname == NULL) {
        ESP_LOGE(TAG, "calloc failed");
        return NULL;
    }
    memcpy(phostname, uri->host.s, uri->host.length);

    memset ((char *)&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;

    error = getaddrinfo(phostname, NULL, &hints, &addrres);
    if (error != 0) {
        ESP_LOGE(TAG, "DNS lookup failed for destination address %s. error: %d", phostname, error);
        free(phostname);
        return NULL;
    }
    if (addrres == NULL) {
        ESP_LOGE(TAG, "DNS lookup %s did not return any addresses", phostname);
        free(phostname);
        return NULL;
    }
    free(phostname);
    coap_address_init(&dst_addr);
    switch (addrres->ai_family) {
    case AF_INET:
        memcpy(&dst_addr.addr.sin, addrres->ai_addr, sizeof(dst_addr.addr.sin));
        dst_addr.addr.sin.sin_port        = htons(uri->port);
        inet_ntop(AF_INET, &dst_addr.addr.sin.sin_addr, tmpbuf, sizeof(tmpbuf));
        ESP_LOGI(TAG, "DNS lookup succeeded. IP=%s", tmpbuf);
        break;
    case AF_INET6:
        memcpy(&dst_addr.addr.sin6, addrres->ai_addr, sizeof(dst_addr.addr.sin6));
        dst_addr.addr.sin6.sin6_port        = htons(uri->port);
        inet_ntop(AF_INET6, &dst_addr.addr.sin6.sin6_addr, tmpbuf, sizeof(tmpbuf));
        ESP_LOGI(TAG, "DNS lookup succeeded. IP=%s", tmpbuf);
        break;
    default:
        ESP_LOGE(TAG, "DNS lookup response failed");
        return NULL;
    }
    freeaddrinfo(addrres);

    return &dst_addr;
}

/**
 * 
*/
static int
coap_build_optlist(coap_uri_t *uri, coap_optlist_t *optlist)
{
#define BUFSIZE 40
    unsigned char _buf[BUFSIZE];
    unsigned char *buf;
    size_t buflen;
    int res;

    optlist = NULL;

    if (uri->scheme == COAP_URI_SCHEME_COAPS && !coap_dtls_is_supported()) {
        ESP_LOGE(TAG, "MbedTLS DTLS Client Mode not configured");
        return 0;
    }
    if (uri->scheme == COAP_URI_SCHEME_COAPS_TCP && !coap_tls_is_supported()) {
        ESP_LOGE(TAG, "MbedTLS TLS Client Mode not configured");
        return 0;
    }
    if (uri->scheme == COAP_URI_SCHEME_COAP_TCP && !coap_tcp_is_supported()) {
        ESP_LOGE(TAG, "TCP Client Mode not configured");
        return 0;
    }

    if (uri->path.length) {
        buflen = BUFSIZE;
        buf = _buf;
        res = coap_split_path(uri->path.s, uri->path.length, buf, &buflen);

        while (res--) {
            coap_insert_optlist(&optlist,
                                coap_new_optlist(COAP_OPTION_URI_PATH,
                                                 coap_opt_length(buf),
                                                 coap_opt_value(buf)));

            buf += coap_opt_size(buf);
        }
    }

    if (uri->query.length) {
        buflen = BUFSIZE;
        buf = _buf;
        res = coap_split_query(uri->query.s, uri->query.length, buf, &buflen);

        while (res--) {
            coap_insert_optlist(&optlist,
                                coap_new_optlist(COAP_OPTION_URI_QUERY,
                                                 coap_opt_length(buf),
                                                 coap_opt_value(buf)));

            buf += coap_opt_size(buf);
        }
    }
    return 1;
}

/**-------------------------------------------------------------------------------------------------------------*/

static void coap_example_client(void *p)
{
    coap_address_t   *dst_addr;
    static coap_uri_t uri;
    const char       *server_uri = "coap://192.168.1.5:5684/obs";
    coap_context_t *ctx = NULL;
    coap_session_t *session = NULL;
    coap_pdu_t *request = NULL;
    unsigned char token[8];
    size_t tokenlength;

    /* Set up the CoAP logging */
    coap_set_log_handler(coap_log_handler);
    coap_set_log_level(EXAMPLE_COAP_LOG_DEFAULT_LEVEL);

    /* Set up the CoAP context */
    ctx = coap_new_context(NULL);
    if (!ctx) {
        ESP_LOGE(TAG, "coap_new_context() failed");
        goto clean_up;
    }
    coap_context_set_block_mode(ctx,
                                COAP_BLOCK_USE_LIBCOAP|COAP_BLOCK_SINGLE_BODY);

    coap_register_response_handler(ctx, message_handler);

    if (coap_split_uri((const uint8_t *)server_uri, strlen(server_uri), &uri) == -1) {
        ESP_LOGE(TAG, "CoAP server uri error");
        goto clean_up;
    }
    if (!coap_build_optlist(&uri))
        goto clean_up;

    dst_addr = coap_get_address(&uri);
    if (!dst_addr)
        goto clean_up;

    /*
     * Note that if the URI starts with just coap:// (not coaps://) the
     * session will still be plain text.
     */
    if (uri.scheme == COAP_URI_SCHEME_COAPS || uri.scheme == COAP_URI_SCHEME_COAPS_TCP) {

    } else {
        session = coap_new_client_session(ctx, NULL, dst_addr,
                                          uri.scheme == COAP_URI_SCHEME_COAP_TCP ? COAP_PROTO_TCP :
                                          COAP_PROTO_UDP);
    }
    if (!session) {
        ESP_LOGE(TAG, "coap_new_client_session() failed");
        goto clean_up;
    }

    while (1) {
        request = coap_new_pdu(coap_is_mcast(dst_addr) ? COAP_MESSAGE_NON : COAP_MESSAGE_CON,
                               COAP_REQUEST_CODE_GET, session);
        if (!request) {
            ESP_LOGE(TAG, "coap_new_pdu() failed");
            goto clean_up;
        }
        /* Add in an unique token */
        coap_session_new_token(session, &tokenlength, token);
        coap_add_token(request, tokenlength, token);

        /*
         * To make this a POST, you will need to do the following
         * Change COAP_REQUEST_CODE_GET to COAP_REQUEST_CODE_POST for coap_new_pdu()
         * Add in here a Content-Type Option based on the format of the POST text.  E.G. for JSON
         *   u_char buf[4];
         *   coap_insert_optlist(&optlist,
         *                       coap_new_optlist(COAP_OPTION_CONTENT_FORMAT,
         *                                        coap_encode_var_safe (buf, sizeof (buf),
         *                                                              COAP_MEDIATYPE_APPLICATION_JSON),
         *                                        buf));
         * Add in here the POST data of length length. E.G.
         *   coap_add_data_large_request(session, request, length, data, NULL, NULL);
         */
        // TEST_POST
        // coap_add_optlist_pdu(request, &optlist);
        // coap_delete_optlist(optlist);
        // optlist = NULL;

        // char *buf = "Hello, I'm a Client";
        // coap_insert_optlist(&optlist,
        //     coap_new_optlist(COAP_OPTION_CONTENT_FORMAT,
        //                     // coap_encode_var_safe ((uint8_t *)buf, sizeof (buf),
        //                     //             COAP_MEDIATYPE_APPLICATION_JSON),
        //                     sizeof(buf),
        //                     (uint8_t *)buf));

        // coap_add_optlist_pdu(request, &optlist);

        // coap_add_data_large_request(session, request, sizeof(buf), (uint8_t *)buf, NULL, NULL);       

        ESP_LOGI(TAG, "I'm here");
        char *buf = "Hello, I'm a Client";
        // coap_insert_optlist(&optlist,
        //     coap_new_optlist(COAP_OPTION_OBSERVE,
        //                     coap_encode_var_safe((uint8_t *)buf, sizeof(buf),COAP_OBSERVE_ESTABLISH), 
        //                     // buf,
        //                     // sizeof(buf),
        //                     (uint8_t *)buf));
        // COAP_OBSERVE_ESTABLISH, NULL
        ESP_LOGI(TAG, "I'm comming");
        coap_insert_optlist(&optlist,
            coap_new_optlist(COAP_OPTION_OBSERVE,
                            COAP_OBSERVE_ESTABLISH, 
                            NULL));
        coap_add_optlist_pdu(request, &optlist);

        // coap_add_data_large_request(session, request, sizeof(buf), (uint8_t *)buf, NULL, NULL); 
        ESP_LOGI(TAG, "I'm done");

        resp_wait = 4;
        coap_send(session, request);

        ESP_LOGI(TAG, "I'm send");

        wait_ms = COAP_DEFAULT_TIME_SEC * 1000;

        while (resp_wait) {
            int result = coap_io_process(ctx, wait_ms > 1000 ? 1000 : wait_ms);
           
            if (result >= 0) {
                if (result >= wait_ms) {
                    ESP_LOGE(TAG, "No response from server");
                    break;
                } else {
                    wait_ms -= result;
                }
            }

            // vTaskDelay(5000 / portTICK_PERIOD_MS);
        }
        ESP_LOGI(TAG, "I'm insert");

        coap_insert_optlist(&optlist,
            coap_new_optlist(COAP_OPTION_OBSERVE,
                            COAP_OBSERVE_CANCEL, 
                            NULL));
        ESP_LOGI(TAG, "I'm insert_optlist");
        coap_add_optlist_pdu(request, &optlist);

        // coap_cancel_observe();
        coap_send(session, request);
        ESP_LOGI(TAG, "I'm clean");


        for(int countdown = 20; countdown >= 0; countdown--) {
            if (countdown % 2)
            {
                ESP_LOGI(TAG, "%d... ", countdown);
                /* code */
            }
            
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
        ESP_LOGI(TAG, "Starting again!");
        // break;
    }

    // vTaskDelay(portMAX_DELAY / portTICK_PERIOD_MS);

clean_up:
    if (optlist) {
        coap_delete_optlist(optlist);
        optlist = NULL;
    }
    if (session) {
        coap_session_release(session);
    }
    if (ctx) {
        coap_free_context(ctx);
    }
    coap_cleanup();

    ESP_LOGI(TAG, "Finished");
    vTaskDelete(NULL);
}


