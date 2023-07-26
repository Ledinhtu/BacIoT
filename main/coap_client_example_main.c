/* CoAP client Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

/*
 * WARNING
 * libcoap is not multi-thread safe, so only this thread must make any coap_*()
 * calls.  Any external (to this thread) data transmitted in/out via libcoap
 * therefore has to be passed in/out by xQueue*() via this thread.
 */

#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/param.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/timers.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"

#include "nvs_flash.h"

#include "protocol_examples_common.h"

#include "coap3/coap.h"


#include "dht.h"
#include "driver/gpio.h"

#define COAP_OBSERVE_URI "coap://192.168.1.5:5684/obs" 
#define COAP_POST_URI "coap://192.168.1.5:5684/POST"
#define BLINK_GPIO GPIO_NUM_2
#define DHT11_PIN 4
#define NODE_ID 104
#define DHT_PERIOD 3000
#define TIME_PUMP 30000
#define NUM_TIMERS 5



#ifndef CONFIG_COAP_CLIENT_SUPPORT
#error COAP_CLIENT_SUPPORT needs to be enabled
#endif /* COAP_CLIENT_SUPPORT */

#define COAP_DEFAULT_TIME_SEC 60

/* The examples use simple Pre-Shared-Key configuration that you can set via
   'idf.py menuconfig'.

   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_COAP_PSK_KEY "some-agreed-preshared-key"

   Note: PSK will only be used if the URI is prefixed with coaps://
   instead of coap:// and the PSK must be one that the server supports
   (potentially associated with the IDENTITY)
*/
#define EXAMPLE_COAP_PSK_KEY CONFIG_EXAMPLE_COAP_PSK_KEY
#define EXAMPLE_COAP_PSK_IDENTITY CONFIG_EXAMPLE_COAP_PSK_IDENTITY

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

const static char *TAG = "CoAP_client";
 TimerHandle_t xTimers;

static int resp_wait = 1;
static int resp_wait_observe = 1;
static int resp_wait_post = 1;

static coap_optlist_t *optlist_observe = NULL;
static coap_optlist_t *optlist_post = NULL;
// static coap_optlist_t *optlist = NULL;
static int wait_ms;
static int wait_ms_post;
static int wait_ms_observe;

coap_context_t *ctx_observe = NULL;

static int16_t temperature;
static int16_t humidity;

TickType_t timePump = 0;

#ifdef CONFIG_COAP_MBEDTLS_PKI
/* CA cert, taken from coap_ca.pem
   Client cert, taken from coap_client.crt
   Client key, taken from coap_client.key

   The PEM, CRT and KEY file are examples taken from
   https://github.com/eclipse/californium/tree/master/demo-certs/src/main/resources
   as the Certificate test (by default) is against the californium server.

   To embed it in the app binary, the PEM, CRT and KEY file is named
   in the component.mk COMPONENT_EMBED_TXTFILES variable.
 */
extern uint8_t ca_pem_start[] asm("_binary_coap_ca_pem_start");
extern uint8_t ca_pem_end[]   asm("_binary_coap_ca_pem_end");
extern uint8_t client_crt_start[] asm("_binary_coap_client_crt_start");
extern uint8_t client_crt_end[]   asm("_binary_coap_client_crt_end");
extern uint8_t client_key_start[] asm("_binary_coap_client_key_start");
extern uint8_t client_key_end[]   asm("_binary_coap_client_key_end");
#endif /* CONFIG_COAP_MBEDTLS_PKI */

static void configure_led(void)
{
    ESP_LOGI(TAG, "Example configured to blink GPIO LED!");
    gpio_reset_pin(BLINK_GPIO);
    /* Set the GPIO as a push/pull output */
    gpio_set_direction(BLINK_GPIO, GPIO_MODE_OUTPUT);
}

// SemaphoreHandle_t xSemaphore = xSemaphoreCreateBinary();
// static void turnOff_Pump(void){
//     for (; ; )
//     {
//         if( xSemaphore != NULL ) {
//             if( xSemaphoreTake( xSemaphore, ( TickType_t ) portMAX_DELAY) == pdTRUE ) {
//                 vTaskDelay(30000 / portTICK_PERIOD_MS);
//                 gpio_set_level(BLINK_GPIO, 0);
//             }
//         }  
//     }  
// }

static void turnOff_Pump(TimerHandle_t xTimer){
    gpio_set_level(BLINK_GPIO, 0);
    // xTimerStop( xTimer, 0 );
}


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
            resp_wait = 0;
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
    resp_wait = 0;
    return COAP_RESPONSE_OK;
}

static coap_response_t
post_message_handler(coap_session_t *session,
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
            resp_wait_post = 0;
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
    resp_wait_post = 0;
    return COAP_RESPONSE_OK;
}

static coap_response_t
observe_message_handler(coap_session_t *session,
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
            resp_wait_observe = 0;

            char status[10] = "";
            sprintf(status,"%.*s", (int)data_len, data);
            if(!strcmp(status, "true")){
                ESP_LOGE(TAG, "TRUE");
                gpio_set_level(BLINK_GPIO, 1);
                // printf("TRUE");
                if( xTimers != NULL ) {
                    if( xTimerStart( xTimers, 0 ) != pdPASS )
                    {
                        ESP_LOGE(TAG, "Timer start FAIL!");

                    } else
                    {
                        ESP_LOGE(TAG, "Timer start SUCCESSED!");
                    }
                    
                }
            }
            else if(!strcmp(status, "false")){
                ESP_LOGE(TAG, "FALSE");
                gpio_set_level(BLINK_GPIO, 0);

                if( xTimerReset( xTimers, 0 ) != pdPASS )
                {
                    ESP_LOGE(TAG, "xTimerReset");
                }
                if( xTimers != NULL ) {
                    if( xTimerStop( xTimers, 0 ) != pdPASS )
                    {
                        ESP_LOGE(TAG, "Timer stop FAIL");
                    } else
                    {
                        ESP_LOGE(TAG, "Timer stop SUCCESSED!");
                    }
                    
                }
                // printf("FALSE");
            }
            else {
                ESP_LOGE(TAG, "ERR");
                // printf("ERR");
            }

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
    resp_wait_observe = 0;
    return COAP_RESPONSE_OK;
}

#ifdef CONFIG_COAP_MBEDTLS_PKI

static int
verify_cn_callback(const char *cn,
                   const uint8_t *asn1_public_cert,
                   size_t asn1_length,
                   coap_session_t *session,
                   unsigned depth,
                   int validated,
                   void *arg
                  )
{
    coap_log(LOG_INFO, "CN '%s' presented by server (%s)\n",
             cn, depth ? "CA" : "Certificate");
    return 1;
}
#endif /* CONFIG_COAP_MBEDTLS_PKI */

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

static int
coap_build_optlist(coap_optlist_t **optlist, coap_uri_t *uri)
{
#define BUFSIZE 40
    unsigned char _buf[BUFSIZE];
    unsigned char *buf;
    size_t buflen;
    int res;

    *optlist = NULL;

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
            coap_insert_optlist(optlist,
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
            coap_insert_optlist(optlist,
                                coap_new_optlist(COAP_OPTION_URI_QUERY,
                                                 coap_opt_length(buf),
                                                 coap_opt_value(buf)));

            buf += coap_opt_size(buf);
        }
    }
    return 1;
}
#ifdef CONFIG_COAP_MBEDTLS_PSK
static coap_session_t *
coap_start_psk_session(coap_context_t *ctx, coap_address_t *dst_addr, coap_uri_t *uri)
{
 static coap_dtls_cpsk_t dtls_psk;
 static char client_sni[256];

    memset(client_sni, 0, sizeof(client_sni));
    memset (&dtls_psk, 0, sizeof(dtls_psk));
    dtls_psk.version = COAP_DTLS_CPSK_SETUP_VERSION;
    dtls_psk.validate_ih_call_back = NULL;
    dtls_psk.ih_call_back_arg = NULL;
    if (uri->host.length)
        memcpy(client_sni, uri->host.s, MIN(uri->host.length, sizeof(client_sni) - 1));
    else
        memcpy(client_sni, "localhost", 9);
    dtls_psk.client_sni = client_sni;
    dtls_psk.psk_info.identity.s = (const uint8_t *)EXAMPLE_COAP_PSK_IDENTITY;
    dtls_psk.psk_info.identity.length = sizeof(EXAMPLE_COAP_PSK_IDENTITY)-1;
    dtls_psk.psk_info.key.s = (const uint8_t *)EXAMPLE_COAP_PSK_KEY;
    dtls_psk.psk_info.key.length = sizeof(EXAMPLE_COAP_PSK_KEY)-1;
    return coap_new_client_session_psk2(ctx, NULL, dst_addr,
                                       uri->scheme == COAP_URI_SCHEME_COAPS ? COAP_PROTO_DTLS : COAP_PROTO_TLS,
                                       &dtls_psk);
}
#endif /* CONFIG_COAP_MBEDTLS_PSK */

#ifdef CONFIG_COAP_MBEDTLS_PKI
static coap_session_t *
coap_start_pki_session(coap_context_t *ctx, coap_address_t *dst_addr, coap_uri_t *uri)
{
    unsigned int ca_pem_bytes = ca_pem_end - ca_pem_start;
    unsigned int client_crt_bytes = client_crt_end - client_crt_start;
    unsigned int client_key_bytes = client_key_end - client_key_start;
 static coap_dtls_pki_t dtls_pki;
 static char client_sni[256];

    memset (&dtls_pki, 0, sizeof(dtls_pki));
    dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;
    if (ca_pem_bytes) {
        /*
         * Add in additional certificate checking.
         * This list of enabled can be tuned for the specific
         * requirements - see 'man coap_encryption'.
         *
         * Note: A list of root cas file can be setup separately using
         * coap_context_set_pki_root_cas(), but the below is used to
         * define what checking actually takes place.
         */
        dtls_pki.verify_peer_cert        = 1;
        dtls_pki.check_common_ca         = 1;
        dtls_pki.allow_self_signed       = 1;
        dtls_pki.allow_expired_certs     = 1;
        dtls_pki.cert_chain_validation   = 1;
        dtls_pki.cert_chain_verify_depth = 2;
        dtls_pki.check_cert_revocation   = 1;
        dtls_pki.allow_no_crl            = 1;
        dtls_pki.allow_expired_crl       = 1;
        dtls_pki.allow_bad_md_hash       = 1;
        dtls_pki.allow_short_rsa_length  = 1;
        dtls_pki.validate_cn_call_back   = verify_cn_callback;
        dtls_pki.cn_call_back_arg        = NULL;
        dtls_pki.validate_sni_call_back  = NULL;
        dtls_pki.sni_call_back_arg       = NULL;
        memset(client_sni, 0, sizeof(client_sni));
        if (uri->host.length) {
            memcpy(client_sni, uri->host.s, MIN(uri->host.length, sizeof(client_sni)));
        } else {
            memcpy(client_sni, "localhost", 9);
        }
        dtls_pki.client_sni = client_sni;
    }
    dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM_BUF;
    dtls_pki.pki_key.key.pem_buf.public_cert = client_crt_start;
    dtls_pki.pki_key.key.pem_buf.public_cert_len = client_crt_bytes;
    dtls_pki.pki_key.key.pem_buf.private_key = client_key_start;
    dtls_pki.pki_key.key.pem_buf.private_key_len = client_key_bytes;
    dtls_pki.pki_key.key.pem_buf.ca_cert = ca_pem_start;
    dtls_pki.pki_key.key.pem_buf.ca_cert_len = ca_pem_bytes;

    return coap_new_client_session_pki(ctx, NULL, dst_addr,
                                              uri->scheme == COAP_URI_SCHEME_COAPS ? COAP_PROTO_DTLS : COAP_PROTO_TLS,
                                              &dtls_pki);
}
#endif /* CONFIG_COAP_MBEDTLS_PKI */

static void coap_client_get(void *p)
{
    coap_optlist_t *optlist;
    coap_address_t   *dst_addr;
    static coap_uri_t uri;
    const char       *server_uri = COAP_DEFAULT_DEMO_URI;
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
    if (!coap_build_optlist(&optlist, &uri))
        goto clean_up;

    dst_addr = coap_get_address(&uri);
    if (!dst_addr)
        goto clean_up;

    /*
     * Note that if the URI starts with just coap:// (not coaps://) the
     * session will still be plain text.
     */
    if (uri.scheme == COAP_URI_SCHEME_COAPS || uri.scheme == COAP_URI_SCHEME_COAPS_TCP) {
#ifndef CONFIG_MBEDTLS_TLS_CLIENT
        ESP_LOGE(TAG, "MbedTLS (D)TLS Client Mode not configured");
        goto clean_up;
#endif /* CONFIG_MBEDTLS_TLS_CLIENT */

#ifdef CONFIG_COAP_MBEDTLS_PSK
        session = coap_start_psk_session(ctx, dst_addr, &uri);
#endif /* CONFIG_COAP_MBEDTLS_PSK */

#ifdef CONFIG_COAP_MBEDTLS_PKI
        session = coap_start_pki_session(ctx, dst_addr, &uri);
#endif /* CONFIG_COAP_MBEDTLS_PKI */
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
         *   coap_add_data_large_request(session, request length, data, NULL, NULL);
         */

        coap_add_optlist_pdu(request, &optlist);

        resp_wait = 1;
        coap_send(session, request);

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
        }
        for(int countdown = 10; countdown >= 0; countdown--) {
            ESP_LOGI(TAG, "%d... ", countdown);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
        ESP_LOGI(TAG, "Starting again!");
    }

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

static void coap_client_post(void *p)
{
    static coap_optlist_t *optlist = NULL;

    coap_address_t   *dst_addr;
    static coap_uri_t uri;
    const char       *server_uri = COAP_POST_URI;
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

    coap_register_response_handler(ctx, post_message_handler);

    if (coap_split_uri((const uint8_t *)server_uri, strlen(server_uri), &uri) == -1) {
        ESP_LOGE(TAG, "CoAP server uri error");
        goto clean_up;
    }
    if (!coap_build_optlist(&optlist, &uri))
        goto clean_up;

    dst_addr = coap_get_address(&uri);
    if (!dst_addr)
        goto clean_up;

    /*
     * Note that if the URI starts with just coap:// (not coaps://) the
     * session will still be plain text.
     */
    if (uri.scheme == COAP_URI_SCHEME_COAPS || uri.scheme == COAP_URI_SCHEME_COAPS_TCP) {
#ifndef CONFIG_MBEDTLS_TLS_CLIENT
        ESP_LOGE(TAG, "MbedTLS (D)TLS Client Mode not configured");
        goto clean_up;
#endif /* CONFIG_MBEDTLS_TLS_CLIENT */

#ifdef CONFIG_COAP_MBEDTLS_PSK
        session = coap_start_psk_session(ctx, dst_addr, &uri);
#endif /* CONFIG_COAP_MBEDTLS_PSK */

#ifdef CONFIG_COAP_MBEDTLS_PKI
        session = coap_start_pki_session(ctx, dst_addr, &uri);
#endif /* CONFIG_COAP_MBEDTLS_PKI */
    } else {
        session = coap_new_client_session(ctx, NULL, dst_addr,
                                          uri.scheme == COAP_URI_SCHEME_COAP_TCP ? COAP_PROTO_TCP :
                                          COAP_PROTO_UDP);
    }
    if (!session) {
        ESP_LOGE(TAG, "coap_new_client_session() failed");
        goto clean_up;
    }
    TickType_t xLastWakeTime;
    const TickType_t xFrequency = DHT_PERIOD;//period
    xLastWakeTime = xTaskGetTickCount();
    while (1) {
        request = coap_new_pdu(coap_is_mcast(dst_addr) ? COAP_MESSAGE_NON : COAP_MESSAGE_CON,
                               COAP_REQUEST_CODE_POST, session);
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
         *   coap_add_data_large_request(session, request length, data, NULL, NULL);
         */

        // char* buf = "{\"temp\":20}";
        char buf [255];
        uint8_t length = 0;

        if (dht_read_data(DHT_TYPE_DHT11, (gpio_num_t)DHT11_PIN, &humidity, &temperature) == ESP_OK)
        {
            ESP_LOGI(TAG, "Humidity: %d%% Temp: %dC\n", humidity / 10, temperature / 10);
            // check_alarm();
            length = sprintf(buf, "{\"ID\":%d,\n\"temp\":%d,\n\"humi\":%d}", NODE_ID, temperature/10, humidity/10);
            ESP_LOGW(TAG, "BUF: %s", buf);
        }
        else
        {
            printf("Could not read data from sensor\n");
        }

        vTaskDelay(10 / portTICK_PERIOD_MS);

        coap_insert_optlist(&optlist,
            coap_new_optlist(COAP_OPTION_CONTENT_FORMAT,
                            strlen(buf),
                            ( uint8_t *) buf));

        coap_add_optlist_pdu(request, &optlist);

        coap_add_data_large_request(session, request, strlen(buf), ( uint8_t *)buf, NULL, NULL);

        resp_wait_post = 1;
        coap_send(session, request);

        wait_ms_post = COAP_DEFAULT_TIME_SEC * 1000;

        while (resp_wait_post) {
            int result = coap_io_process(ctx, wait_ms_post > 1000 ? 1000 : wait_ms_post);
            if (result >= 0) {
                if (result >= wait_ms_post) {
                    ESP_LOGE(TAG, "No response from server");
                    break;
                } else {
                    wait_ms_post -= result;
                }
            }
        }
        // for(int countdown = 10; countdown >= 0; countdown--) {
        //     ESP_LOGI(TAG, "%d... ", countdown);
        //     vTaskDelay(1000 / portTICK_PERIOD_MS);
        // }
        ESP_LOGE(TAG, "I'm Sleep!");
        // vTaskDelay(3000 / portTICK_PERIOD_MS);
        // vTaskDelayUntil(&xLastWakeTime, xFrequency);
        vTaskDelayUntil(&xLastWakeTime, DHT_PERIOD);
        ESP_LOGI(TAG, "Starting again!");
    }

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

static void coap_client_observe(void *p)
{
    static coap_optlist_t *optlist = NULL;

    coap_address_t   *dst_addr;
    static coap_uri_t uri;
    const char       *server_uri = COAP_OBSERVE_URI;
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

    coap_register_response_handler(ctx, observe_message_handler);

    if (coap_split_uri((const uint8_t *)server_uri, strlen(server_uri), &uri) == -1) {
        ESP_LOGE(TAG, "CoAP server uri error");
        goto clean_up;
    }
    if (!coap_build_optlist(&optlist, &uri))
        goto clean_up;

    dst_addr = coap_get_address(&uri);
    if (!dst_addr)
        goto clean_up;

    /*
     * Note that if the URI starts with just coap:// (not coaps://) the
     * session will still be plain text.
     */
    if (uri.scheme == COAP_URI_SCHEME_COAPS || uri.scheme == COAP_URI_SCHEME_COAPS_TCP) {
#ifndef CONFIG_MBEDTLS_TLS_CLIENT
        ESP_LOGE(TAG, "MbedTLS (D)TLS Client Mode not configured");
        goto clean_up;
#endif /* CONFIG_MBEDTLS_TLS_CLIENT */

#ifdef CONFIG_COAP_MBEDTLS_PSK
        session = coap_start_psk_session(ctx, dst_addr, &uri);
#endif /* CONFIG_COAP_MBEDTLS_PSK */

#ifdef CONFIG_COAP_MBEDTLS_PKI
        session = coap_start_pki_session(ctx, dst_addr, &uri);
#endif /* CONFIG_COAP_MBEDTLS_PKI */
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
         *   coap_add_data_large_request(session, request length, data, NULL, NULL);
         */

        coap_insert_optlist(&optlist,
            coap_new_optlist(COAP_OPTION_OBSERVE,
                            COAP_OBSERVE_ESTABLISH, 
                            NULL));

        coap_add_optlist_pdu(request, &optlist);

        resp_wait_observe = 1;
        coap_send(session, request);

    
        wait_ms_observe = COAP_DEFAULT_TIME_SEC * 1000;

        while (resp_wait_observe) {
            int result = coap_io_process(ctx, wait_ms_observe > 1000 ? 1000 : wait_ms_observe);
            if (result >= 0) {
                if (result >= wait_ms_observe) {
                    ESP_LOGE(TAG, "No response from server");
                    goto clean_up;
                } else {
                    wait_ms_observe -= result;
                }
            }
        }
        ESP_LOGE(TAG, "Have response from server");
        ctx_observe = ctx;
        vTaskSuspend( NULL );
        // for(int countdown = 10; countdown >= 0; countdown--) {
        //     ESP_LOGI(TAG, "%d... ", countdown);
        //     vTaskDelay(1000 / portTICK_PERIOD_MS);
        // }
        // ESP_LOGI(TAG, "Starting again!");

    }

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

static void coap_client_message_handler(void *p) {
    while (1)
    {
    ESP_LOGW(TAG, "JOIN");
        if (ctx_observe)
        {
            int result = coap_io_process(ctx_observe, 500);
            // ESP_LOGI(TAG, "result: %d", result);
            /* code */
        } else
        {
            ESP_LOGE(TAG, "ctx_observe =  NULL");
            /* code */
        }
        /* code */
        vTaskDelay(500 / portTICK_PERIOD_MS);
    }
     
}

void app_main(void)
{
    ESP_ERROR_CHECK( nvs_flash_init() );
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());

    configure_led();

    xTimers = xTimerCreate("pump_timer", TIME_PUMP / portTICK_PERIOD_MS, pdFALSE, ( void * ) 0, turnOff_Pump);

    xTaskCreate(coap_client_observe, "coap_observe", 8 * 1024, NULL, 5, NULL);

    xTaskCreate(coap_client_post, "post_message", 8 * 1024, NULL, 6, NULL);

    xTaskCreate(coap_client_message_handler, "message_handler", 8 * 1024, NULL, 7, NULL);

    // xTaskCreate(coap_example_client, "coap", 8 * 1024, NULL, 5, NULL);
}
