#ifndef _N2N_SOCKS5_H_
#define _N2N_SOCKS5_H_

#include <stdint.h>

/**
 * 启动 SOCKS5 代理服务器。
 * 该接口是异步的，会在内部生成监听线程。
 * 
 * @param ip_addr 绑定的 IPv4 地址（网络字节序）
 * @param port 监听的端口（主机字节序）
 */
void start_socks5(uint32_t ip_addr, int port);

#endif /* _N2N_SOCKS5_H_ */
