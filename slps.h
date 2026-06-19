/**
 * @file slps.h
 * @brief SLPS (Security Lattice-based Proxy Signature) 方案头文件
 *
 * 本方案基于 ML-DSA (Dilithium) 格密码框架，实现了无证书代理签名机制。
 * 包含以下核心算法：
 *   1. Setup      - 系统参数生成
 *   2. User-Key-Gen    - 用户密钥对生成
 *   3. User-Sign  - 用户签名
 *   4. User-Verify - 用户签名验证
 *   5. Principal-Authorize-Agent - 授权代理凭证生成
 *   6. Credential-Verify - 代理凭证验证
 *   7. Agent-Sign  - 代理签名
 *   8. Agent-Verify - 代理签名验证
 *
 * 参考文献:
 *   - SLPS_scheme_20260417.tex (SLPS 伪代码)
 *   - Dilithium / ML-DSA (基础格密码框架)
 */

#ifndef SLPS_H
#define SLPS_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "polyvec.h"
#include "poly.h"

/* 命名空间宏 (与 Dilithium 保持一致) */
#ifndef SLPS_NAMESPACE
#define SLPS_NAMESPACE(s) slps_##s
#endif

/*===============================================================
 * SLPS 方案字节大小常数 (与伪代码中的数据结构一一对应)
 *===============================================================*/

#define SLPS_PARAMSBYTES    (SEEDBYTES)                          /**< params = rho (仅种子) */
#define SLPS_TRBYTES       (TRBYTES)                            /**< tr = H1(rho || t) */
#define SLPS_CIDBYTES      (CTILDEBYTES)                        /**< 挑战哈希长度 */

/** User-Key-Gen 输出的公钥: pk = t (K 个多项式, 23-bit 压缩) */
#define SLPS_PKIDBYTES     (K * SCLLS_POLYT_PACKEDBYTES)

/** User-Key-Gen 输出的私钥: sk = (K_ID, tr, s1, s2)
 *  key || tr || L*s1 (eta packed) || K*s2 (eta packed) */
#define SLPS_SKIDBYTES     (SEEDBYTES + TRBYTES \
                            + L * POLYETA_PACKEDBYTES \
                            + K * POLYETA_PACKEDBYTES)

/** 代理凭证: T_IDp = (IDp, IDa, ~c_IDp, z_IDp) */
#define SLPS_TIDP_IDBYTES (SEEDBYTES)  /**< IDp 身份信息 */
#define SLPS_TIDP_IDABYTES (SEEDBYTES) /**< IDa 身份信息 */
#define SLPS_ZIDP_PACKEDBYTES (L * POLYZ_PACKEDBYTES) /**< z_IDp 长度 */
#define SLPS_TIDPBYTES     (SLPS_TIDP_IDBYTES + SLPS_TIDP_IDABYTES \
                            + SLPS_CIDBYTES + SLPS_ZIDP_PACKEDBYTES)

/** Agent-Sign 输出的签名: sigma = (~c_IDp, ~c_IDa, z_a, h_w)
 *  ~c_IDp || ~c_IDa || z_a (2*gamma1 packed) || h_w (K*hw packed) */
#define SLPS_ZA_PACKEDBYTES  (L * SCLLS_POLYZ0_PACKEDBYTES)
#define SLPS_HW_PACKEDBYTES  (K * SCLLS_HWBYTES_PERPOLY)
#define SLPS_SIGBYTES        (SLPS_CIDBYTES + SLPS_CIDBYTES \
                              + SLPS_ZA_PACKEDBYTES + SLPS_HW_PACKEDBYTES)


/*===============================================================
 * SLPS 方案函数声明
 *===============================================================*/

/**
 * @brief Setup: 系统参数生成
 *
 * 伪代码对应 (Algorithm Setup):
 *   rho <- {0,1}^256
 *   params := (H1, H2, H3, rho)
 *
 * 代码作用:
 *   从一个随机种子(seed)派生:
 *     rho (生成矩阵 A 的种子)
 *   输出:
 *     params = rho (公共参数, 仅包含种子 rho)
 *
 * @param params    输出参数 buffer (SLPS_PARAMSBYTES 字节)
 * @param seed      输入随机种子 (SEEDBYTES 字节)
 * @return          成功返回 0
 */
int slps_setup(uint8_t* params, const uint8_t* seed);

/**
 * @brief User-Key-Gen: 用户密钥对生成
 *
 * 伪代码对应 (Algorithm User-Key-Gen):
 *   xi <- {0,1}^256
 *   K_IDi <- {0,1}^256
 *   theta_IDi = H2(xi || IDi)
 *   (s1_IDi, s2_IDi) = ExpandS(theta_IDi)
 *   t_IDi = A * s1_IDi + s2_IDi
 *   tr_IDi = H1(rho || t_IDi)
 *   pk_IDi = (t_IDi)
 *   sk_IDi = (K_IDi, tr_IDi, s1_IDi, s2_IDi)
 *
 * @param pk        输出公钥 (SLPS_PKIDBYTES 字节, t_IDi)
 * @param sk        输出私钥 (SLPS_SKIDBYTES 字节, K_IDi||tr||s1||s2)
 * @param params    输入公共参数 (包含 rho)
 * @param id        输入用户身份信息 (SEEDBYTES 字节)
 * @param seed      输入随机种子 (SEEDBYTES 字节, 用于生成 xi 和 K_ID)
 * @return          成功返回 0
 */
int slps_user_key_gen(uint8_t* pk,
                      uint8_t* sk,
                      const uint8_t* params,
                      const uint8_t* id,
                      const uint8_t* seed);

/**
 * @brief User-Sign: 用户签名生成
 *
 * 伪代码对应 (Algorithm User-Sign):
 *   mu = H2(tr_IDi || M)
 *   nu1 = H2(K_IDi || mu)
 *   y = ExpandMask(nu1, kappa)
 *   w = A * y
 *   w1 = HighBits(w, 2*gamma2)
 *   ~c = H3(mu || w1)
 *   c = SampleInBall(~c)
 *   z = y + c * s1_IDi
 *   r0 = LowBits(w - c * s2_IDi, 2*gamma2)
 *   sigma_IDi = (~c, z)
 *
 * @param sigma     输出签名 (SLPS_SKIDBYTES 中的 ~c 部分, 实际输出 ~c||z)
 * @param m         输入消息
 * @param mlen      消息长度
 * @param params    输入公共参数
 * @param sk        输入用户私钥
 * @param seed      输入随机种子
 * @return          成功返回 0
 */
int slps_user_sign(uint8_t* sigma,
                   const uint8_t* m,
                   const uint8_t mlen,
                   const uint8_t* params,
                   const uint8_t* sk,
                   const uint8_t* seed);

/**
 * @brief User-Verify: 用户签名验证
 *
 * 伪代码对应 (Algorithm User-Verify):
 *   tr = H1(rho || t_IDi)
 *   mu = H2(tr || M)
 *   c = SampleInBall(~c)
 *   w'1 = HighBits(A*z - c*t_IDi, 2*gamma2)
 *   ~c' = H3(mu || w'1)
 *   if ||z||_inf < gamma1 - beta and ~c = ~c': Verify = True
 *
 * @param m         输入消息
 * @param mlen      消息长度
 * @param sigma     输入签名 (~c || z)
 * @param params    输入公共参数
 * @param pk        输入用户公钥
 * @return          验证成功返回 0, 失败返回 -1
 */
int slps_user_verify(const uint8_t* m,
                     const uint8_t mlen,
                     const uint8_t* sigma,
                     const uint8_t* params,
                     const uint8_t* pk);

/**
 * @brief Principal-Authorize-Agent: 授权代理凭证生成
 *
 * 伪代码对应 (Algorithm Principal-Authorize-Agent):
 *   tr_IDa = H1(rho || t_IDa)
 *   mu_IDp = H2(tr_IDp || tr_IDa || IDp || IDa)
 *   nu2 = H2(K_IDp || mu_IDp)
 *   y_IDp = ExpandMask(nu2, kappa)
 *   w_IDp = A * y_IDp
 *   w1_IDp = HighBits(w_IDp, 2*gamma2)
 *   ~c_IDp = H3(mu_IDp || w1_IDp)
 *   c_IDp = SampleInBall(~c_IDp)
 *   z_IDp = y_IDp + c_IDp * s1_IDp
 *   r0_IDp = LowBits(w_IDp - c_IDp * s2_IDp, 2*gamma2)
 *   T_IDp = (IDp, IDa, ~c_IDp, z_IDp)
 *
 * @param t         输出代理凭证 T_IDp (SLPS_TIDPBYTES 字节)
 * @param params    输入公共参数
 * @param sk        输入授权者私钥 sk_IDp
 * @param idp       输入授权者身份 IDp
 * @param ida       输入代理者身份 IDa
 * @param pka       输入代理者公钥 pk_IDa
 * @param seed      输入随机种子
 * @return          成功返回 0
 */
int slps_principal_authorize_agent(uint8_t* t,
                                   const uint8_t* params,
                                   const uint8_t* sk,
                                   const uint8_t* idp,
                                   const uint8_t* ida,
                                   const uint8_t* pka,
                                   const uint8_t* seed);

/**
 * @brief Credential-Verify: 代理凭证验证
 *
 * 伪代码对应 (Algorithm Credential-Verify):
 *   tr_IDp = H1(rho || t_IDp)
 *   tr_IDa = H1(rho || t_IDa)
 *   mu_IDp = H2(tr_IDp || tr_IDa || IDp || IDa)
 *   c_IDp = SampleInBall(~c_IDp)
 *   w'1_IDp = HighBits(A*z_IDp - c_IDp*t_IDp, 2*gamma2)
 *   ~c'_IDp = H3(mu_IDp || w'1_IDp)
 *   if ||z_IDp||_inf < gamma1 - beta and ~c_IDp = ~c'_IDp: Verify = True
 *
 * @param t         输入代理凭证 T_IDp
 * @param params    输入公共参数
 * @param pkp       输入授权者公钥 pk_IDp
 * @param pka       输入代理者公钥 pk_IDa
 * @param idp       输入授权者身份 IDp
 * @param ida       输入代理者身份 IDa
 * @return          验证成功返回 0, 失败返回 -1
 */
int slps_credential_verify(const uint8_t* t,
                           const uint8_t* params,
                           const uint8_t* pkp,
                           const uint8_t* pka,
                           const uint8_t* idp,
                           const uint8_t* ida);

/**
 * @brief Agent-Sign: 代理签名生成
 *
 * 伪代码对应 (Algorithm Agent-Sign):
 *   c_IDp = SampleInBall(~c_IDp)
 *   w'1_IDp = HighBits(A*z_IDp - c_IDp*t_IDp, 2*gamma2)
 *   mu_IDa = H2(tr_IDa || M)
 *   nu3 = H2(K_IDa || mu)
 *   y_IDa = ExpandMask(nu3, kappa)
 *   w_IDa = A * y_IDa
 *   w1_a = HighBits(w_IDa, 2*gamma2) + w'1_IDp
 *   ~c_IDa = H3(mu_IDa || w1_a)
 *   c_IDa = SampleInBall(~c_IDa)
 *   z_IDa = y_IDa + c_IDa * s1_IDa
 *   r0_IDa = LowBits(w_IDa - c_IDa * s2_IDa, 2*gamma2)
 *   z_a = z_IDa + z_IDp
 *   h_w = Makeh_w(A*z_IDp - c_IDp*t_IDp, w_IDa - c_IDa*s2_IDa, 2*gamma2)
 *   sigma_IDa = (~c_IDp, ~c_IDa, z_a, h_w)
 *
 * @param sig       输出代理签名 (SLPS_SIGBYTES 字节)
 * @param m         输入消息
 * @param mlen      消息长度
 * @param params    输入公共参数
 * @param t         输入代理凭证 T_IDp
 * @param pkp       输入授权者公钥
 * @param sk        输入代理者私钥 sk_IDa
 * @param seed      输入随机种子
 * @return          成功返回 0
 */
int slps_agent_sign(uint8_t* sig,
                    const uint8_t* m,
                    const uint8_t mlen,
                    const uint8_t* params,
                    const uint8_t* t,
                    const uint8_t* pkp,
                    const uint8_t* sk,
                    const uint8_t* seed);

/**
 * @brief Agent-Verify: 代理签名验证
 *
 * 伪代码对应 (Algorithm Agent-Verify):
 *   c_IDp = SampleInBall(~c_IDp)
 *   c_IDa = SampleInBall(~c_IDa)
 *   w'1_a = HighBits(A*z_a - c_IDp*t_IDp - c_IDa*t_IDa, 2*gamma2) - h_w
 *   mu_IDa = H2(tr_IDa || M)
 *   ~c'_IDa = H3(mu_IDa || w'1_IDa)
 *   if ||z_a||_inf < 2*gamma1 - 2*beta and ~c_IDa = ~c'_IDa: Verify = True
 *
 * @param m         输入消息
 * @param mlen      消息长度
 * @param sig       输入代理签名
 * @param params    输入公共参数
 * @param pkp       输入授权者公钥
 * @param pka       输入代理者公钥
 * @param ida       输入代理者身份
 * @param idp       输入授权者身份
 * @return          验证成功返回 0, 失败返回 -1
 */
int slps_agent_verify(const uint8_t* m,
                      const uint8_t mlen,
                      const uint8_t* sig,
                      const uint8_t* params,
                      const uint8_t* pkp,
                      const uint8_t* pka,
                      const uint8_t* ida,
                      const uint8_t* idp);

#endif /* SLPS_H */
