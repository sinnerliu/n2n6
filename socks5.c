#include "socks5.h"
#include "n2n.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#endif

extern volatile int g_edge_running;

// 传递给客户端处理线程的参数结构体
typedef struct {
    SOCKET client_fd;
} socks5_client_ctx_t;

// 传递给监听线程的参数结构体
typedef struct {
    uint32_t ip_addr;
    int port;
} socks5_listen_ctx_t;

#ifdef _WIN32
static DWORD WINAPI socks5_client_thread(LPVOID lpArg);
static DWORD WINAPI socks5_listen_thread(LPVOID lpArg);
#else
static void* socks5_client_thread(void* lpArg);
static void* socks5_listen_thread(void* lpArg);
#endif

void start_socks5(uint32_t ip_addr, int port) {
    socks5_listen_ctx_t *ctx = malloc(sizeof(socks5_listen_ctx_t));
    if (!ctx) {
        traceEvent(TRACE_ERROR, "SOCKS5: 无法为监听上下文分配内存");
        return;
    }
    ctx->ip_addr = ip_addr;
    ctx->port = port;

#ifdef _WIN32
    HANDLE hThread = CreateThread(NULL, 0, socks5_listen_thread, (void*)ctx, 0, NULL);
    if (hThread != NULL) {
        CloseHandle(hThread);
    } else {
        traceEvent(TRACE_ERROR, "SOCKS5: 无法创建监听线程");
        free(ctx);
    }
#else
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, socks5_listen_thread, (void*)ctx) == 0) {
        pthread_detach(thread_id);
    } else {
        traceEvent(TRACE_ERROR, "SOCKS5: 无法创建监听线程");
        free(ctx);
    }
#endif
}

#ifdef _WIN32
static DWORD WINAPI socks5_listen_thread(LPVOID lpArg)
#else
static void* socks5_listen_thread(void* lpArg)
#endif
{
    socks5_listen_ctx_t *ctx = (socks5_listen_ctx_t*)lpArg;
    uint32_t ip_addr = ctx->ip_addr;
    int port = ctx->port;
    free(ctx);

    SOCKET listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd == INVALID_SOCKET) {
        traceEvent(TRACE_ERROR, "SOCKS5: 无法创建监听套接字");
        return 0;
    }

    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = ip_addr;
    bind_addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) == SOCKET_ERROR) {
        struct in_addr in_ip;
        in_ip.s_addr = ip_addr;
        traceEvent(TRACE_ERROR, "SOCKS5: 绑定到地址 %s:%d 失败", inet_ntoa(in_ip), port);
        closesocket(listen_fd);
        return 0;
    }

    if (listen(listen_fd, 10) == SOCKET_ERROR) {
        traceEvent(TRACE_ERROR, "SOCKS5: 监听失败");
        closesocket(listen_fd);
        return 0;
    }

    struct in_addr in_ip;
    in_ip.s_addr = ip_addr;
    traceEvent(TRACE_NORMAL, "SOCKS5: 成功启动，正在监听在 %s:%d", inet_ntoa(in_ip), port);

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    while (g_edge_running) {
        // 使用 select 检查 listen_fd 是否有可读事件，防止 accept 永远阻塞导致 edge 退出时无法回收
        fd_set read_fds;
        struct timeval timeout;
        FD_ZERO(&read_fds);
        FD_SET(listen_fd, &read_fds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int select_ret = select((int)(listen_fd + 1), &read_fds, NULL, NULL, &timeout);
        if (select_ret < 0) {
            if (g_edge_running) {
                traceEvent(TRACE_ERROR, "SOCKS5: 监听套接字 select 错误");
            }
            break;
        }
        if (select_ret == 0) {
            // 超时，继续循环检查 g_edge_running
            continue;
        }

        SOCKET client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd == INVALID_SOCKET) {
            if (!g_edge_running) break;
            continue;
        }

        socks5_client_ctx_t *client_ctx = malloc(sizeof(socks5_client_ctx_t));
        if (!client_ctx) {
            closesocket(client_fd);
            continue;
        }
        client_ctx->client_fd = client_fd;

#ifdef _WIN32
        HANDLE hThread = CreateThread(NULL, 0, socks5_client_thread, (void*)client_ctx, 0, NULL);
        if (hThread != NULL) {
            CloseHandle(hThread);
        } else {
            closesocket(client_fd);
            free(client_ctx);
        }
#else
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, socks5_client_thread, (void*)client_ctx) == 0) {
            pthread_detach(thread_id);
        } else {
            closesocket(client_fd);
            free(client_ctx);
        }
#endif
    }

    closesocket(listen_fd);
    traceEvent(TRACE_NORMAL, "SOCKS5: 监听套接字已关闭，SOCKS5 服务终止");
    return 0;
}

#ifdef _WIN32
static DWORD WINAPI socks5_client_thread(LPVOID lpArg)
#else
static void* socks5_client_thread(void* lpArg)
#endif
{
    socks5_client_ctx_t *ctx = (socks5_client_ctx_t*)lpArg;
    SOCKET client_fd = ctx->client_fd;
    free(ctx);

    SOCKET remote_fd = INVALID_SOCKET;
    unsigned char buf[512];
    int r;

    // 1. 握手阶段 (Handshake)
    // 读取客户端发送的协商包: VER (1 byte) | NMETHODS (1 byte)
    r = recv(client_fd, (char*)buf, 2, 0);
    if (r <= 0) goto cleanup;

    if (buf[0] != 0x05) {
        // 只支持 SOCKS5
        goto cleanup;
    }

    int nmethods = buf[1];
    if (nmethods <= 0 || nmethods > 255) goto cleanup;

    // 读取所有的 METHODS 列表
    r = recv(client_fd, (char*)&buf[2], nmethods, 0);
    if (r <= 0) goto cleanup;

    // 检查是否支持 No Authentication Required (0x00)
    int support_no_auth = 0;
    for (int i = 0; i < nmethods; i++) {
        if (buf[2 + i] == 0x00) {
            support_no_auth = 1;
            break;
        }
    }

    if (!support_no_auth) {
        // 发送不支持的方法响应
        unsigned char fail_method[2] = {0x05, 0xFF};
        send(client_fd, (char*)fail_method, 2, 0);
        goto cleanup;
    }

    // 回应客户端：选择 NO AUTHENTICATION REQUIRED (0x00)
    unsigned char succ_method[2] = {0x05, 0x00};
    send(client_fd, (char*)succ_method, 2, 0);

    // 2. 请求阶段 (Request)
    // 读取请求前 4 字节: VER (1) | CMD (1) | RSV (1) | ATYP (1)
    r = recv(client_fd, (char*)buf, 4, 0);
    if (r <= 0) goto cleanup;

    if (buf[0] != 0x05) goto cleanup;
    int cmd = buf[1];
    int atyp = buf[3];

    if (cmd != 0x01) {
        // 只支持 CONNECT 命令 (0x01)
        // 响应：REP = 0x07 (不支持该命令)
        unsigned char fail_cmd[10] = {0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        send(client_fd, (char*)fail_cmd, 10, 0);
        goto cleanup;
    }

    struct sockaddr_storage dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    int family = AF_UNSPEC;

    if (atyp == 0x01) {
        // IPv4 目标地址: 4 字节 IP + 2 字节端口
        struct sockaddr_in *addr4 = (struct sockaddr_in*)&dest_addr;
        addr4->sin_family = AF_INET;
        r = recv(client_fd, (char*)&(addr4->sin_addr), 4, 0);
        if (r <= 0) goto cleanup;
        uint16_t port_net;
        r = recv(client_fd, (char*)&port_net, 2, 0);
        if (r <= 0) goto cleanup;
        addr4->sin_port = port_net;
        family = AF_INET;
    } else if (atyp == 0x03) {
        // 域名目标地址: 1 字节域名长度 + 域名 + 2 字节端口
        unsigned char domain_len;
        r = recv(client_fd, (char*)&domain_len, 1, 0);
        if (r <= 0) goto cleanup;
        
        char domain[256];
        r = recv(client_fd, domain, domain_len, 0);
        if (r <= 0) goto cleanup;
        domain[domain_len] = '\0';

        uint16_t port_net;
        r = recv(client_fd, (char*)&port_net, 2, 0);
        if (r <= 0) goto cleanup;

        // 解析域名
        struct addrinfo hints, *result = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%u", ntohs(port_net));

        if (getaddrinfo(domain, port_str, &hints, &result) != 0) {
            // 解析失败，响应 REP = 0x04 (主机不可达)
            unsigned char fail_dns[10] = {0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            send(client_fd, (char*)fail_dns, 10, 0);
            goto cleanup;
        }

        memcpy(&dest_addr, result->ai_addr, result->ai_addrlen);
        family = result->ai_family;
        freeaddrinfo(result);
    } else if (atyp == 0x04) {
        // IPv6 目标地址: 16 字节 IP + 2 字节端口
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)&dest_addr;
        addr6->sin6_family = AF_INET6;
        r = recv(client_fd, (char*)&(addr6->sin6_addr), 16, 0);
        if (r <= 0) goto cleanup;
        uint16_t port_net;
        r = recv(client_fd, (char*)&port_net, 2, 0);
        if (r <= 0) goto cleanup;
        addr6->sin6_port = port_net;
        family = AF_INET6;
    } else {
        // 不支持的目标类型
        // 响应 REP = 0x08 (不支持的地址类型)
        unsigned char fail_atyp[10] = {0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        send(client_fd, (char*)fail_atyp, 10, 0);
        goto cleanup;
    }

    // 3. 连接目标主机
    remote_fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (remote_fd == INVALID_SOCKET) {
        // 响应 REP = 0x01 (普通故障)
        unsigned char fail_sock[10] = {0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        send(client_fd, (char*)fail_sock, 10, 0);
        goto cleanup;
    }

    int conn_len = (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    if (connect(remote_fd, (struct sockaddr*)&dest_addr, conn_len) == SOCKET_ERROR) {
        // 连接失败，响应 REP = 0x05 (连接被拒绝)
        unsigned char fail_conn[10] = {0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        send(client_fd, (char*)fail_conn, 10, 0);
        goto cleanup;
    }

    // 连接成功！响应客户端: REP = 0x00 (成功)
    unsigned char succ_resp[10] = {0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    send(client_fd, (char*)succ_resp, 10, 0);

    // 4. 双向 TCP 数据中转
    fd_set fds;
    char forward_buf[8192];
    int running = 1;

    while (running && g_edge_running) {
        FD_ZERO(&fds);
        FD_SET(client_fd, &fds);
        FD_SET(remote_fd, &fds);
        SOCKET max_fd = (client_fd > remote_fd) ? client_fd : remote_fd;

        // 设置一个超时，以便能够感知并响应 g_edge_running 退出
        struct timeval timeout;
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;

        int select_ret = select((int)(max_fd + 1), &fds, NULL, NULL, &timeout);
        if (select_ret < 0) {
            break;
        }
        if (select_ret == 0) {
            continue;
        }

        // 转发客户端发送的数据到目标服务器
        if (FD_ISSET(client_fd, &fds)) {
            int n = recv(client_fd, forward_buf, sizeof(forward_buf), 0);
            if (n <= 0) break;
            int sent = 0;
            while (sent < n) {
                int k = send(remote_fd, forward_buf + sent, n - sent, 0);
                if (k <= 0) {
                    running = 0;
                    break;
                }
                sent += k;
            }
        }

        // 转发目标服务器发送的数据到客户端
        if (FD_ISSET(remote_fd, &fds)) {
            int n = recv(remote_fd, forward_buf, sizeof(forward_buf), 0);
            if (n <= 0) break;
            int sent = 0;
            while (sent < n) {
                int k = send(client_fd, forward_buf + sent, n - sent, 0);
                if (k <= 0) {
                    running = 0;
                    break;
                }
                sent += k;
            }
        }
    }

cleanup:
    if (remote_fd != INVALID_SOCKET) {
        closesocket(remote_fd);
    }
    closesocket(client_fd);
    return 0;
}
