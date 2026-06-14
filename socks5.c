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
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <fcntl.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#endif

extern volatile int g_edge_running;

/* 设置套接字阻塞/非阻塞模式 */
static void set_socket_nonblocking(SOCKET fd, int nonblocking) {
#ifdef _WIN32
    unsigned long mode = nonblocking ? 1 : 0;
    ioctlsocket(fd, FIONBIO, &mode);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) {
        if (nonblocking) {
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        } else {
            fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        }
    }
#endif
}

// 传递给客户端处理线程的参数结构体
typedef struct {
    SOCKET client_fd;
} socks5_client_ctx_t;

#ifdef _WIN32
static DWORD WINAPI socks5_client_thread(LPVOID lpArg);
static DWORD WINAPI socks5_listen_thread(LPVOID lpArg);
#else
static void* socks5_client_thread(void* lpArg);
static void* socks5_listen_thread(void* lpArg);
#endif

int start_socks5(uint32_t ip_addr, int port) {
    SOCKET listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd == INVALID_SOCKET) {
        traceEvent(TRACE_ERROR, "SOCKS5: Failed to create listening socket");
        return -1;
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
#ifdef _WIN32
        int err = WSAGetLastError();
        int is_addr_not_avail = (err == WSAEADDRNOTAVAIL);
        int is_port_in_use = (err == WSAEADDRINUSE);
#else
        int err = errno;
        int is_addr_not_avail = (err == EADDRNOTAVAIL);
        int is_port_in_use = (err == EADDRINUSE);
#endif
        if (is_addr_not_avail) {
            // 网卡 IP 分配初期（特别是 Windows DAD 冲突检测期间），绑定会返回此错误。
            // 降低为 TRACE_DEBUG 级别以保持控制台清爽，静默重试。
            traceEvent(TRACE_DEBUG, "SOCKS5: Failed to bind to %s:%d (interface IP not ready yet, retrying...)", inet_ntoa(in_ip), port);
        } else if (is_port_in_use) {
            // 端口确实被占用或未释放，提示警告，每 3 秒重试一次，不刷屏
            traceEvent(TRACE_WARNING, "SOCKS5: Failed to bind to %s:%d (port might be in use, retrying...)", inet_ntoa(in_ip), port);
        } else {
            traceEvent(TRACE_ERROR, "SOCKS5: Failed to bind to %s:%d (error=%d)", inet_ntoa(in_ip), port, err);
        }
        closesocket(listen_fd);
        return -1;
    }

    if (listen(listen_fd, 10) == SOCKET_ERROR) {
        traceEvent(TRACE_ERROR, "SOCKS5: Failed to listen on port");
        closesocket(listen_fd);
        return -1;
    }

    // 将 listen_fd 封装好传递给异步监听线程
    SOCKET *p_fd = malloc(sizeof(SOCKET));
    if (!p_fd) {
        traceEvent(TRACE_ERROR, "SOCKS5: Failed to allocate memory");
        closesocket(listen_fd);
        return -1;
    }
    *p_fd = listen_fd;

#ifdef _WIN32
    HANDLE hThread = CreateThread(NULL, 0, socks5_listen_thread, (void*)p_fd, 0, NULL);
    if (hThread != NULL) {
        CloseHandle(hThread);
    } else {
        traceEvent(TRACE_ERROR, "SOCKS5: Failed to create listening thread");
        closesocket(listen_fd);
        free(p_fd);
        return -1;
    }
#else
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, socks5_listen_thread, (void*)p_fd) == 0) {
        pthread_detach(thread_id);
    } else {
        traceEvent(TRACE_ERROR, "SOCKS5: Failed to create listening thread");
        closesocket(listen_fd);
        free(p_fd);
        return -1;
    }
#endif

    struct in_addr in_ip;
    in_ip.s_addr = ip_addr;
    traceEvent(TRACE_NORMAL, "SOCKS5: Started successfully, listening on %s:%d", inet_ntoa(in_ip), port);
    return 0;
}

#ifdef _WIN32
static DWORD WINAPI socks5_listen_thread(LPVOID lpArg)
#else
static void* socks5_listen_thread(void* lpArg)
#endif
{
    SOCKET *p_fd = (SOCKET*)lpArg;
    SOCKET listen_fd = *p_fd;
    free(p_fd);

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    while (g_edge_running) {
        fd_set read_fds;
        struct timeval timeout;
        FD_ZERO(&read_fds);
        FD_SET(listen_fd, &read_fds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int select_ret = select((int)(listen_fd + 1), &read_fds, NULL, NULL, &timeout);
        if (select_ret < 0) {
            if (g_edge_running) {
                traceEvent(TRACE_ERROR, "SOCKS5: Listening socket select error");
            }
            break;
        }
        if (select_ret == 0) {
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
    traceEvent(TRACE_NORMAL, "SOCKS5: Listening socket closed, SOCKS5 service terminated");
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
    r = recv(client_fd, (char*)buf, 2, 0);
    if (r <= 0) goto cleanup;

    if (buf[0] != 0x05) goto cleanup;

    int nmethods = buf[1];
    if (nmethods <= 0 || nmethods > 255) goto cleanup;

    r = recv(client_fd, (char*)&buf[2], nmethods, 0);
    if (r <= 0) goto cleanup;

    int support_no_auth = 0;
    for (int i = 0; i < nmethods; i++) {
        if (buf[2 + i] == 0x00) {
            support_no_auth = 1;
            break;
        }
    }

    if (!support_no_auth) {
        unsigned char fail_method[2] = {0x05, 0xFF};
        send(client_fd, (char*)fail_method, 2, 0);
        goto cleanup;
    }

    unsigned char succ_method[2] = {0x05, 0x00};
    send(client_fd, (char*)succ_method, 2, 0);

    // 2. 请求阶段 (Request)
    r = recv(client_fd, (char*)buf, 4, 0);
    if (r <= 0) goto cleanup;

    if (buf[0] != 0x05) goto cleanup;
    int cmd = buf[1];
    int atyp = buf[3];

    if (cmd != 0x01) {
        unsigned char fail_cmd[10] = {0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        send(client_fd, (char*)fail_cmd, 10, 0);
        goto cleanup;
    }

    struct sockaddr_storage dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    int family = AF_UNSPEC;

    if (atyp == 0x01) {
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

        struct addrinfo hints, *result = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%u", ntohs(port_net));

        if (getaddrinfo(domain, port_str, &hints, &result) != 0) {
            unsigned char fail_dns[10] = {0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            send(client_fd, (char*)fail_dns, 10, 0);
            goto cleanup;
        }

        memcpy(&dest_addr, result->ai_addr, result->ai_addrlen);
        family = result->ai_family;
        freeaddrinfo(result);
    } else if (atyp == 0x04) {
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
        unsigned char fail_atyp[10] = {0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        send(client_fd, (char*)fail_atyp, 10, 0);
        goto cleanup;
    }

    // 3. 连接目标主机
    remote_fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (remote_fd == INVALID_SOCKET) {
        unsigned char fail_sock[10] = {0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        send(client_fd, (char*)fail_sock, 10, 0);
        goto cleanup;
    }

    /* 将套接字设为非阻塞以进行超时 connect */
    set_socket_nonblocking(remote_fd, 1);

    int conn_len = (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    int conn_ret = connect(remote_fd, (struct sockaddr*)&dest_addr, conn_len);
    int is_connecting = 0;

    if (conn_ret == SOCKET_ERROR) {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            is_connecting = 1;
        }
#else
        if (errno == EINPROGRESS) {
            is_connecting = 1;
        }
#endif
    }

    if (is_connecting) {
        fd_set write_fds, err_fds;
        struct timeval tv;
        FD_ZERO(&write_fds);
        FD_ZERO(&err_fds);
        FD_SET(remote_fd, &write_fds);
        FD_SET(remote_fd, &err_fds);

        tv.tv_sec = 5;  /* 5 秒连接超时 */
        tv.tv_usec = 0;

        int select_ret = select((int)(remote_fd + 1), NULL, &write_fds, &err_fds, &tv);
        if (select_ret <= 0) {
            /* 超时或 select 错误 */
            unsigned char fail_conn[10] = {0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            send(client_fd, (char*)fail_conn, 10, 0);
            goto cleanup;
        }

        /* 检查是否有错误发生 */
        if (FD_ISSET(remote_fd, &err_fds)) {
            unsigned char fail_conn[10] = {0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            send(client_fd, (char*)fail_conn, 10, 0);
            goto cleanup;
        }

        if (FD_ISSET(remote_fd, &write_fds)) {
            int valopt = 0;
            socklen_t lon = sizeof(valopt);
            if (getsockopt(remote_fd, SOL_SOCKET, SO_ERROR, (char*)(&valopt), &lon) < 0 || valopt != 0) {
                unsigned char fail_conn[10] = {0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                send(client_fd, (char*)fail_conn, 10, 0);
                goto cleanup;
            }
        }
    } else if (conn_ret == SOCKET_ERROR) {
        /* 其他连接错误，直接失败 */
        unsigned char fail_conn[10] = {0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        send(client_fd, (char*)fail_conn, 10, 0);
        goto cleanup;
    }

    /* 连接成功后还原为阻塞模式，保证后续双向 select 转发的逻辑结构匹配 */
    set_socket_nonblocking(remote_fd, 0);

    /* 极致网络优化：禁用 Nagle 算法（启用 TCP_NODELAY），优化双向 TCP 缓冲区为 256KB */
    int flag_nodelay = 1;
    int buf_size = 262144; /* 256KB */
    
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&flag_nodelay, sizeof(flag_nodelay));
    setsockopt(remote_fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&flag_nodelay, sizeof(flag_nodelay));
    
    setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF, (const char*)&buf_size, sizeof(buf_size));
    setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, (const char*)&buf_size, sizeof(buf_size));
    setsockopt(remote_fd, SOL_SOCKET, SO_SNDBUF, (const char*)&buf_size, sizeof(buf_size));
    setsockopt(remote_fd, SOL_SOCKET, SO_RCVBUF, (const char*)&buf_size, sizeof(buf_size));

    // 响应客户端: REP = 0x00 (成功)
    unsigned char succ_resp[10] = {0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    send(client_fd, (char*)succ_resp, 10, 0);

    // 4. 双向 TCP 数据中转
    fd_set fds;
    char forward_buf[65536]; /* 扩容单次转发缓冲区至 64KB */
    int running = 1;

    while (running && g_edge_running) {
        FD_ZERO(&fds);
        FD_SET(client_fd, &fds);
        FD_SET(remote_fd, &fds);
        SOCKET max_fd = (client_fd > remote_fd) ? client_fd : remote_fd;

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
#ifdef _WIN32
        shutdown(remote_fd, SD_BOTH);
#else
        shutdown(remote_fd, SHUT_RDWR);
#endif
        closesocket(remote_fd);
    }
#ifdef _WIN32
    shutdown(client_fd, SD_BOTH);
#else
    shutdown(client_fd, SHUT_RDWR);
#endif
    closesocket(client_fd);
    return 0;
}
