/**
 * @file slps_packing.h
 * @brief SLPS 方案的字节打包/解包函数声明
 *
 * SLPS 中各数据结构的字节布局:
 *   params      = rho[SEEDBYTES]
 *   pk_IDi     = t_IDi[0..K-1] (每个 SCLLS_POLYT_PACKEDBYTES 字节)
 *   sk_IDi     = key[SEEDBYTES] || tr[TRBYTES] || s1[0..L-1] || s2[0..K-1]
 *   T_IDp      = IDp[SEEDBYTES] || IDa[SEEDBYTES] || ~c_IDp[CTILDEBYTES] || z_IDp[0..L-1]
 *   sigma_IDa  = ~c_IDp[CTILDEBYTES] || ~c_IDa[CTILDEBYTES] || z_a[0..L-1] || h_w[0..K-1]
 */

#ifndef SLPS_PACKING_H
#define SLPS_PACKING_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"
#include "slps.h"

/*===============================================================
 * params: rho 种子 (仅 SEEDBYTES)
 *===============================================================*/
#define slps_pack_params SLPS_NAMESPACE(slps_pack_params)
void slps_pack_params(uint8_t params[SLPS_PARAMSBYTES],
                     const uint8_t rho[SEEDBYTES]);

#define slps_unpack_params SLPS_NAMESPACE(slps_unpack_params)
void slps_unpack_params(uint8_t rho[SEEDBYTES],
                       const uint8_t params[SLPS_PARAMSBYTES]);

/*===============================================================
 * pk_ID: t 向量 (K 个多项式, 23-bit 压缩)
 *===============================================================*/
#define slps_pack_pk SLPS_NAMESPACE(slps_pack_pk)
void slps_pack_pk(uint8_t pk[SLPS_PKIDBYTES],
                 const polyveck* t);

#define slps_unpack_pk SLPS_NAMESPACE(slps_unpack_pk)
void slps_unpack_pk(polyveck* t,
                   const uint8_t pk[SLPS_PKIDBYTES]);

/*===============================================================
 * sk_ID: (key, tr, s1, s2)
 *===============================================================*/
#define slps_pack_sk SLPS_NAMESPACE(slps_pack_sk)
void slps_pack_sk(uint8_t sk[SLPS_SKIDBYTES],
                 const uint8_t key[SEEDBYTES],
                 const uint8_t tr[TRBYTES],
                 const polyvecl* s1,
                 const polyveck* s2);

#define slps_unpack_sk SLPS_NAMESPACE(slps_unpack_sk)
void slps_unpack_sk(uint8_t key[SEEDBYTES],
                   uint8_t tr[TRBYTES],
                   polyvecl* s1,
                   polyveck* s2,
                   const uint8_t sk[SLPS_SKIDBYTES]);

/*===============================================================
 * T_IDp: 代理凭证 (IDp, IDa, ~c_IDp, z_IDp)
 *===============================================================*/
#define slps_pack_tidp SLPS_NAMESPACE(slps_pack_tidp)
void slps_pack_tidp(uint8_t t[SLPS_TIDPBYTES],
                   const uint8_t idp[SLPS_TIDP_IDBYTES],
                   const uint8_t ida[SLPS_TIDP_IDABYTES],
                   const uint8_t cid[SLPS_CIDBYTES],
                   const polyvecl* zidp);

#define slps_unpack_tidp SLPS_NAMESPACE(slps_unpack_tidp)
void slps_unpack_tidp(uint8_t idp[SLPS_TIDP_IDBYTES],
                     uint8_t ida[SLPS_TIDP_IDABYTES],
                     uint8_t cid[SLPS_CIDBYTES],
                     polyvecl* zidp,
                     const uint8_t t[SLPS_TIDPBYTES]);

/*===============================================================
 * sigma_IDa: 代理签名 (~c_IDp, ~c_IDa, z_a, h_w)
 *===============================================================*/
#define slps_pack_sigma SLPS_NAMESPACE(slps_pack_sigma)
void slps_pack_sigma(uint8_t sig[SLPS_SIGBYTES],
                    const uint8_t cidp[SLPS_CIDBYTES],
                    const uint8_t cida[SLPS_CIDBYTES],
                    const polyvecl* za,
                    const polyveck* hw);

#define slps_unpack_sigma SLPS_NAMESPACE(slps_unpack_sigma)
void slps_unpack_sigma(uint8_t cidp[SLPS_CIDBYTES],
                      uint8_t cida[SLPS_CIDBYTES],
                      polyvecl* za,
                      polyveck* hw,
                      const uint8_t sig[SLPS_SIGBYTES]);

/*===============================================================
 * 用户签名 sigma_IDi 打包 (用于 User-Sign 输出)
 * 实际就是 (~c, z) 的拼接，~c[CTILDEBYTES] || z[L] (polyz_pack)
 * 注意: User-Verify 不需要完整的 sigma 格式，只需要 pk 中的 t
 * 这里我们定义一个简化的 sigma 格式用于 User-Sign
 *===============================================================*/
/** 用户签名 ~c[CTILDEBYTES] || z[0..L-1] (每个 polyz_pack) */
#define SLPS_USERSIGBYTES (SLPS_CIDBYTES + L * POLYZ_PACKEDBYTES)

#define slps_pack_user_sig SLPS_NAMESPACE(slps_pack_user_sig)
void slps_pack_user_sig(uint8_t sig[SLPS_USERSIGBYTES],
                       const uint8_t cid[SLPS_CIDBYTES],
                       const polyvecl* z);

#define slps_unpack_user_sig SLPS_NAMESPACE(slps_unpack_user_sig)
void slps_unpack_user_sig(uint8_t cid[SLPS_CIDBYTES],
                         polyvecl* z,
                         const uint8_t sig[SLPS_USERSIGBYTES]);

#endif /* SLPS_PACKING_H */
