#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <orbis/Http.h>
#include <orbis/Ssl.h>
#include <orbis/Net.h>
#include <orbis/Sysmodule.h>

extern "C" void mh_log(const char* fmt, ...);

#ifdef __DEBUG_LOG__
#define PROXY_LOG(fmt, ...) mh_log("[proxy] " fmt "\n", ##__VA_ARGS__)
#else
#define PROXY_LOG(fmt, ...) ((void)0)
#endif

#define PROXY_PORT 4040
#define BUFFER_SIZE 8192

static bool g_proxy_running = false;
static pthread_t g_proxy_thread;
static int32_t g_http_ctx_id = -1;
static int32_t g_ssl_ctx_id = -1;
static int32_t g_net_pool_id = -1;
static OrbisNetId g_server_sock = -1;

static bool init_http_client(int net_mem_id) {
    // Load HTTP and SSL modules
    int ret = sceSysmoduleLoadModuleInternal(ORBIS_SYSMODULE_INTERNAL_SSL);
    if (ret != 0 && ret != 0x80108005) { // 0x80108005 = already loaded
        PROXY_LOG("Failed to load SSL module: 0x%08X", ret);
        return false;
    }

    ret = sceSysmoduleLoadModuleInternal(ORBIS_SYSMODULE_INTERNAL_HTTP);
    if (ret != 0 && ret != 0x80108005) {
        PROXY_LOG("Failed to load HTTP module: 0x%08X", ret);
        return false;
    }

    // Initialize SSL
    g_ssl_ctx_id = sceSslInit(256 * 1024);
    if (g_ssl_ctx_id < 0) {
        PROXY_LOG("sceSslInit failed: 0x%08X", g_ssl_ctx_id);
        return false;
    }

    // Initialize HTTP with the net memory pool ID
    g_http_ctx_id = sceHttpInit(net_mem_id, g_ssl_ctx_id, 256 * 1024);
    if (g_http_ctx_id < 0) {
        PROXY_LOG("sceHttpInit failed: 0x%08X", g_http_ctx_id);
        sceSslTerm();
        return false;
    }

    PROXY_LOG("HTTP/SSL initialized (netmem=%d)", net_mem_id);
    return true;
}

static void cleanup_http_client() {
    if (g_http_ctx_id >= 0) {
        sceHttpTerm(g_http_ctx_id);
        g_http_ctx_id = -1;
    }
    if (g_ssl_ctx_id >= 0) {
        sceSslTerm();
        g_ssl_ctx_id = -1;
    }
}

// Fetch from SponsorBlock API using sceHttp
static bool fetch_sponsorblock(const char* video_id, char* response_buf, size_t buf_size) {
    char url[512];
    snprintf(url, sizeof(url),
             "https://sponsor.ajay.app/api/skipSegments?videoID=%s&categories=[\"sponsor\",\"intro\",\"outro\",\"interaction\",\"selfpromo\",\"preview\",\"music_offtopic\"]",
             video_id);

    PROXY_LOG("Fetching: %s", url);

    // Create template
    int32_t tmpl_id = sceHttpCreateTemplate(g_http_ctx_id, "SponsorBlock-PS4/1.0", 1, 0);
    if (tmpl_id < 0) {
        PROXY_LOG("sceHttpCreateTemplate failed: 0x%08X", tmpl_id);
        return false;
    }

    // Create connection
    int32_t conn_id = sceHttpCreateConnectionWithURL(tmpl_id, url, 0);
    if (conn_id < 0) {
        PROXY_LOG("sceHttpCreateConnectionWithURL failed: 0x%08X", conn_id);
        sceHttpDeleteTemplate(tmpl_id);
        return false;
    }

    // Create request (GET method = 0)
    int32_t req_id = sceHttpCreateRequestWithURL(conn_id, 0, url, 0);
    if (req_id < 0) {
        PROXY_LOG("sceHttpCreateRequestWithURL failed: 0x%08X", req_id);
        sceHttpDeleteConnection(conn_id);
        sceHttpDeleteTemplate(tmpl_id);
        return false;
    }

    // Send request
    int32_t ret = sceHttpSendRequest(req_id, NULL, 0);
    if (ret < 0) {
        PROXY_LOG("sceHttpSendRequest failed: 0x%08X", ret);
        sceHttpDeleteRequest(req_id);
        sceHttpDeleteConnection(conn_id);
        sceHttpDeleteTemplate(tmpl_id);
        return false;
    }

    // Get response status
    int32_t status_code = 0;
    ret = sceHttpGetStatusCode(req_id, &status_code);
    if (ret < 0) {
        PROXY_LOG("sceHttpGetStatusCode failed: 0x%08X", ret);
        sceHttpDeleteRequest(req_id);
        sceHttpDeleteConnection(conn_id);
        sceHttpDeleteTemplate(tmpl_id);
        return false;
    }

    PROXY_LOG("HTTP %d", status_code);

    bool success = false;
    if (status_code == 200) {
        // Read response data
        size_t total_read = 0;
        while (total_read < buf_size - 1) {
            int32_t read_size = sceHttpReadData(req_id, response_buf + total_read, buf_size - total_read - 1);
            if (read_size < 0) {
                PROXY_LOG("sceHttpReadData failed: 0x%08X", read_size);
                break;
            }
            if (read_size == 0) break; // EOF
            total_read += read_size;
        }
        response_buf[total_read] = '\0';
        PROXY_LOG("Read %zu bytes", total_read);
        success = total_read > 0;
    } else if (status_code == 404) {
        strcpy(response_buf, "[]");
        success = true;
    }

    sceHttpDeleteRequest(req_id);
    sceHttpDeleteConnection(conn_id);
    sceHttpDeleteTemplate(tmpl_id);

    return success;
}

// Handle proxy client request
static void handle_client(OrbisNetId client_sock) {
    char request_buf[BUFFER_SIZE];
    char response_buf[BUFFER_SIZE];

    // Read HTTP request
    int32_t received = sceNetRecv(client_sock, request_buf, sizeof(request_buf) - 1, 0);
    if (received <= 0) {
        sceNetSocketClose(client_sock);
        return;
    }
    request_buf[received] = '\0';

    PROXY_LOG("Request: %.100s", request_buf);

    // Parse video ID from URL: GET /videoID HTTP/1.1
    char* get_line = strstr(request_buf, "GET /");
    if (!get_line) {
        const char* err_response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        sceNetSend(client_sock, err_response, strlen(err_response), 0);
        sceNetSocketClose(client_sock);
        return;
    }

    char video_id[32] = {0};
    sscanf(get_line, "GET /%31s HTTP", video_id);

    PROXY_LOG("Video ID: %s", video_id);

    // Fetch from SponsorBlock
    char sb_response[4096] = {0};
    bool success = fetch_sponsorblock(video_id, sb_response, sizeof(sb_response));

    if (success) {
        // Send HTTP response
        snprintf(response_buf, sizeof(response_buf),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/json\r\n"
                 "Access-Control-Allow-Origin: *\r\n"
                 "Content-Length: %zu\r\n"
                 "\r\n"
                 "%s",
                 strlen(sb_response), sb_response);
    } else {
        snprintf(response_buf, sizeof(response_buf),
                 "HTTP/1.1 404 Not Found\r\n"
                 "Content-Type: application/json\r\n"
                 "Access-Control-Allow-Origin: *\r\n"
                 "Content-Length: 2\r\n"
                 "\r\n"
                 "[]");
    }

    sceNetSend(client_sock, response_buf, strlen(response_buf), 0);
    sceNetSocketClose(client_sock);
}

// Proxy server thread
static void* proxy_thread_func(void* arg) {
    PROXY_LOG("Proxy thread starting");

    // Initialize network
    int ret = sceSysmoduleLoadModuleInternal(ORBIS_SYSMODULE_INTERNAL_NET);
    if (ret != 0 && ret != 0x80108005) {
        PROXY_LOG("Failed to load NET module: 0x%08X", ret);
        return NULL;
    }

    // Initialize network
    ret = sceNetInit();
    if (ret < 0) {
        PROXY_LOG("sceNetInit failed: 0x%08X", ret);
        return NULL;
    }

    // Create network memory pool for HTTP
    g_net_pool_id = sceNetPoolCreate("http_pool", 64 * 1024, 0);
    if (g_net_pool_id < 0) {
        PROXY_LOG("sceNetPoolCreate failed: 0x%08X", g_net_pool_id);
        return NULL;
    }
    PROXY_LOG("Network pool created (id=%d)", g_net_pool_id);

    if (!init_http_client(g_net_pool_id)) {
        PROXY_LOG("Failed to initialize HTTP client");
        if (g_net_pool_id >= 0) {
            sceNetPoolDestroy(g_net_pool_id);
            g_net_pool_id = -1;
        }
        return NULL;
    }

    // Create socket using sceNet
    g_server_sock = sceNetSocket("proxy_server", ORBIS_NET_AF_INET, ORBIS_NET_SOCK_STREAM, 0);
    if (g_server_sock < 0) {
        PROXY_LOG("sceNetSocket failed: 0x%08X", g_server_sock);
        cleanup_http_client();
        return NULL;
    }

    // Set SO_REUSEADDR and SO_REUSEPORT to allow rebinding
    int opt = 1;
    sceNetSetsockopt(g_server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sceNetSetsockopt(g_server_sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    // Try to bind to a port, incrementing if already bound
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int actual_port = PROXY_PORT;
    ret = -1;
    for (int port_try = PROXY_PORT; port_try < PROXY_PORT + 10; port_try++) {
        addr.sin_port = htons(port_try);
        ret = sceNetBind(g_server_sock, (OrbisNetSockaddr*)&addr, sizeof(addr));
        if (ret >= 0) {
            actual_port = port_try;
            break;
        }
        PROXY_LOG("Port %d bind failed: 0x%08X, trying next...", port_try, ret);
    }

    if (ret < 0) {
        PROXY_LOG("Failed to bind to any port in range");
        sceNetSocketClose(g_server_sock);
        g_server_sock = -1;
        cleanup_http_client();
        return NULL;
    }

    PROXY_LOG("Bound to port %d", actual_port);

    // Listen
    ret = sceNetListen(g_server_sock, 5);
    if (ret < 0) {
        PROXY_LOG("sceNetListen failed: 0x%08X", ret);
        sceNetSocketClose(g_server_sock);
        g_server_sock = -1;
        cleanup_http_client();
        return NULL;
    }

    PROXY_LOG("Listening on localhost:%d", actual_port);

    // Accept loop
    while (g_proxy_running) {
        OrbisNetSockaddr client_addr;
        OrbisNetSocklen_t client_len = sizeof(client_addr);

        OrbisNetId client_sock = sceNetAccept(g_server_sock, &client_addr, &client_len);
        if (client_sock < 0) {
            if (g_proxy_running) {
                PROXY_LOG("sceNetAccept failed: 0x%08X", client_sock);
            }
            break;
        }

        PROXY_LOG("Client connected");
        handle_client(client_sock);
    }

    if (g_server_sock >= 0) {
        sceNetSocketClose(g_server_sock);
        g_server_sock = -1;
    }
    cleanup_http_client();

    if (g_net_pool_id >= 0) {
        sceNetPoolDestroy(g_net_pool_id);
        g_net_pool_id = -1;
    }

    PROXY_LOG("Proxy thread stopped");

    return NULL;
}

extern "C" bool start_sponsorblock_proxy() {
    if (g_proxy_running) {
        return true;
    }

    g_proxy_running = true;

    pthread_attr_t attr;
    pthread_attr_init(&attr);

    int ret = pthread_create(&g_proxy_thread, &attr, proxy_thread_func, NULL);
    if (ret != 0) {
        PROXY_LOG("pthread_create failed: %d", ret);
        g_proxy_running = false;
        return false;
    }

    PROXY_LOG("Proxy thread created");
    return true;
}

extern "C" void stop_sponsorblock_proxy() {
    if (!g_proxy_running) {
        return;
    }

    g_proxy_running = false;

    // Close server socket to unblock accept()
    if (g_server_sock >= 0) {
        sceNetSocketClose(g_server_sock);
        g_server_sock = -1;
    }

    pthread_join(g_proxy_thread, NULL);
    PROXY_LOG("Proxy stopped");
}
