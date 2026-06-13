#ifndef _N2N_SOCKS5_H_
#define _N2N_SOCKS5_H_

#include <stdint.h>

/**
 * 启动 SOCKS5 代理服务器。
 * 该接口会将监听端口绑定动作放在调用线程同步执行，成功绑定后异步拉起服务线程。
 * 
 * @param ip_addr 绑定的 IPv4 地址（网络字节序）
 * @param port 监听的端口（主机字节序）
 * @return 成功返回 0，失败返回 -1
 */
int start_socks5(uint32_t ip_addr, int port);

#endif /* _N2N_SOCKS5_H_ */
