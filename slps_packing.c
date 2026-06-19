/**
 * @file slps_packing.c
 * @brief SLPS 方案的字节打包/解包函数实现
 *
 * 数据布局约定:
 *   params      = rho[32]
 *   pk_ID      = t[0..K-1] 每个 SCLLS_POLYT_PACKEDBYTES (736) 字节
 *   sk_ID      = key[32] || tr[64] || s1[0..L-1] || s2[0..K-1]
 *                每个 s1/s2 系数范围 [-ETA, ETA], 打包为 POLYETA_PACKEDBYTES
 *   T_IDp      = IDp[32] || IDa[32] || ~c_IDp[32] || z_IDp[0..L-1]
 *                每个 z 系数范围 [-(GAMMA1-1), GAMMA1], 打包为 POLYZ_PACKEDBYTES
 *   sigma_IDa  = ~c_IDp[32] || ~c_IDa[32] || z_a[0..L-1] || h_w[0..K-1]
 *                z_a: 范围 [-2*GAMMA1, 2*GAMMA1], 打包为 SCLLS_POLYZ0_PACKEDBYTES
 *                h_w: hw 系数, 打包为 SCLLS_HWBYTES_PERPOLY
 *   sigma_IDi  = ~c[32] || z[0..L-1] (polyz_pack)
 */

#include <stdint.h>
#include "params.h"
#include "slps_packing.h"
#include "polyvec.h"
#include "poly.h"

/*===============================================================
 * params: rho 种子
 *===============================================================*/

/**
 * @brief 打包 params = rho
 *
 * @param params  输出 buffer (SLPS_PARAMSBYTES = SEEDBYTES)
 * @param rho     输入 rho 种子
 */
void slps_pack_params(uint8_t params[SLPS_PARAMSBYTES],
                     const uint8_t rho[SEEDBYTES])
{
  unsigned int i;
  for (i = 0; i < SEEDBYTES; ++i)
    params[i] = rho[i];
}

/**
 * @brief 解包 params 得到 rho
 *
 * @param rho    输出 rho 种子
 * @param params 输入 params buffer
 */
void slps_unpack_params(uint8_t rho[SEEDBYTES],
                       const uint8_t params[SLPS_PARAMSBYTES])
{
  unsigned int i;
  for (i = 0; i < SEEDBYTES; ++i)
    rho[i] = params[i];
}

/*===============================================================
 * pk_ID: t 向量 (K 个多项式)
 *===============================================================*/

/**
 * @brief 打包 pk_ID = (t)
 *
 * @param pk  输出 buffer (K * SCLLS_POLYT_PACKEDBYTES 字节)
 * @param t   输入 K 维多项式向量
 */
void slps_pack_pk(uint8_t pk[SLPS_PKIDBYTES],
                 const polyveck* t)
{
  unsigned int i;
  for (i = 0; i < K; ++i)
    sclls_polyt_pack(pk + i * SCLLS_POLYT_PACKEDBYTES, &t->vec[i]);
}

/**
 * @brief 解包 pk_ID 得到 t
 *
 * @param t  输出 K 维多项式向量
 * @param pk 输入 pk buffer
 */
void slps_unpack_pk(polyveck* t,
                   const uint8_t pk[SLPS_PKIDBYTES])
{
  unsigned int i;
  for (i = 0; i < K; ++i)
    sclls_polyt_unpack(&t->vec[i], pk + i * SCLLS_POLYT_PACKEDBYTES);
}

/*===============================================================
 * sk_ID: (key, tr, s1, s2)
 *===============================================================*/

/**
 * @brief 打包 sk_ID = (key, tr, s1, s2)
 *
 * 布局: key[SEEDBYTES] || tr[TRBYTES] || s1[0..L-1] || s2[0..K-1]
 *
 * @param sk  输出 buffer (SLPS_SKIDBYTES 字节)
 * @param key 输入密钥种子
 * @param tr  输入追踪值
 * @param s1  输入 L 维短向量 (系数范围 [-ETA, ETA])
 * @param s2  输入 K 维短向量 (系数范围 [-ETA, ETA])
 */
void slps_pack_sk(uint8_t sk[SLPS_SKIDBYTES],
                 const uint8_t key[SEEDBYTES],
                 const uint8_t tr[TRBYTES],
                 const polyvecl* s1,
                 const polyveck* s2)
{
  unsigned int i;

  /* key */
  for (i = 0; i < SEEDBYTES; ++i)
    sk[i] = key[i];
  sk += SEEDBYTES;

  /* tr */
  for (i = 0; i < TRBYTES; ++i)
    sk[i] = tr[i];
  sk += TRBYTES;

  /* s1: L 个多项式, 每个 polyeta_pack */
  for (i = 0; i < L; ++i)
    polyeta_pack(sk + i * POLYETA_PACKEDBYTES, &s1->vec[i]);
  sk += L * POLYETA_PACKEDBYTES;

  /* s2: K 个多项式, 每个 polyeta_pack */
  for (i = 0; i < K; ++i)
    polyeta_pack(sk + i * POLYETA_PACKEDBYTES, &s2->vec[i]);
}

/**
 * @brief 解包 sk_ID = (key, tr, s1, s2)
 *
 * @param key 输出密钥种子
 * @param tr  输出追踪值
 * @param s1  输出 L 维短向量
 * @param s2  输出 K 维短向量
 * @param sk  输入 sk buffer
 */
void slps_unpack_sk(uint8_t key[SEEDBYTES],
                   uint8_t tr[TRBYTES],
                   polyvecl* s1,
                   polyveck* s2,
                   const uint8_t sk[SLPS_SKIDBYTES])
{
  unsigned int i;
  const uint8_t* p = sk;

  /* key */
  for (i = 0; i < SEEDBYTES; ++i)
    key[i] = p[i];
  p += SEEDBYTES;

  /* tr */
  for (i = 0; i < TRBYTES; ++i)
    tr[i] = p[i];
  p += TRBYTES;

  /* s1 */
  for (i = 0; i < L; ++i)
    polyeta_unpack(&s1->vec[i], p + i * POLYETA_PACKEDBYTES);
  p += L * POLYETA_PACKEDBYTES;

  /* s2 */
  for (i = 0; i < K; ++i)
    polyeta_unpack(&s2->vec[i], p + i * POLYETA_PACKEDBYTES);
}

/*===============================================================
 * T_IDp: 代理凭证 (IDp, IDa, ~c_IDp, z_IDp)
 *===============================================================*/

/**
 * @brief 打包代理凭证 T_IDp
 *
 * 布局: IDp[SEEDBYTES] || IDa[SEEDBYTES] || ~c_IDp[CTILDEBYTES] || z_IDp[0..L-1]
 *
 * @param t    输出 buffer (SLPS_TIDPBYTES 字节)
 * @param idp  输入授权者身份
 * @param ida  输入代理者身份
 * @param cid  输入挑战哈希 ~c_IDp
 * @param zidp 输入 z_IDp 向量 (系数范围 [-(GAMMA1-1), GAMMA1])
 */
void slps_pack_tidp(uint8_t t[SLPS_TIDPBYTES],
                   const uint8_t idp[SLPS_TIDP_IDBYTES],
                   const uint8_t ida[SLPS_TIDP_IDABYTES],
                   const uint8_t cid[SLPS_CIDBYTES],
                   const polyvecl* zidp)
{
  unsigned int i;

  /* IDp */
  for (i = 0; i < SLPS_TIDP_IDBYTES; ++i)
    t[i] = idp[i];
  t += SLPS_TIDP_IDBYTES;

  /* IDa */
  for (i = 0; i < SLPS_TIDP_IDABYTES; ++i)
    t[i] = ida[i];
  t += SLPS_TIDP_IDABYTES;

  /* ~c_IDp */
  for (i = 0; i < SLPS_CIDBYTES; ++i)
    t[i] = cid[i];
  t += SLPS_CIDBYTES;

  /* z_IDp: L 个多项式, 每个 polyz_pack */
  for (i = 0; i < L; ++i)
    polyz_pack(t + i * POLYZ_PACKEDBYTES, &zidp->vec[i]);
}

/**
 * @brief 解包代理凭证 T_IDp
 *
 * @param idp  输出授权者身份
 * @param ida  输出代理者身份
 * @param cid  输出挑战哈希 ~c_IDp
 * @param zidp 输出 z_IDp 向量
 * @param t    输入 T_IDp buffer
 */
void slps_unpack_tidp(uint8_t idp[SLPS_TIDP_IDBYTES],
                     uint8_t ida[SLPS_TIDP_IDABYTES],
                     uint8_t cid[SLPS_CIDBYTES],
                     polyvecl* zidp,
                     const uint8_t t[SLPS_TIDPBYTES])
{
  unsigned int i;
  const uint8_t* p = t;

  /* IDp */
  for (i = 0; i < SLPS_TIDP_IDBYTES; ++i)
    idp[i] = p[i];
  p += SLPS_TIDP_IDBYTES;

  /* IDa */
  for (i = 0; i < SLPS_TIDP_IDABYTES; ++i)
    ida[i] = p[i];
  p += SLPS_TIDP_IDABYTES;

  /* ~c_IDp */
  for (i = 0; i < SLPS_CIDBYTES; ++i)
    cid[i] = p[i];
  p += SLPS_CIDBYTES;

  /* z_IDp */
  for (i = 0; i < L; ++i)
    polyz_unpack(&zidp->vec[i], p + i * POLYZ_PACKEDBYTES);
}

/*===============================================================
 * sigma_IDa: 代理签名 (~c_IDp, ~c_IDa, z_a, h_w)
 *===============================================================*/

/**
 * @brief 打包代理签名 sigma_IDa
 *
 * 布局: ~c_IDp[CTILDEBYTES] || ~c_IDa[CTILDEBYTES] || z_a[0..L-1] || h_w[0..K-1]
 *
 * z_a 系数范围 [-2*GAMMA1, 2*GAMMA1], 使用 sclls_polyz0_pack 打包
 * h_w 系数范围 {-1,0,1,±(GAMMA2-ETA)}, 使用 sclls_polyhw_pack 打包
 *
 * @param sig   输出 buffer (SLPS_SIGBYTES 字节)
 * @param cidp  输入 ~c_IDp (挑战哈希)
 * @param cida  输入 ~c_IDa (挑战哈希)
 * @param za    输入 z_a 向量 (z_IDa + z_IDp)
 * @param hw    输入 h_w 向量 (提示)
 */
void slps_pack_sigma(uint8_t sig[SLPS_SIGBYTES],
                    const uint8_t cidp[SLPS_CIDBYTES],
                    const uint8_t cida[SLPS_CIDBYTES],
                    const polyvecl* za,
                    const polyveck* hw)
{
  unsigned int i;

  /* ~c_IDp */
  for (i = 0; i < SLPS_CIDBYTES; ++i)
    sig[i] = cidp[i];
  sig += SLPS_CIDBYTES;

  /* ~c_IDa */
  for (i = 0; i < SLPS_CIDBYTES; ++i)
    sig[i] = cida[i];
  sig += SLPS_CIDBYTES;

  /* z_a: L 个多项式, 每个 sclls_polyz0_pack */
  for (i = 0; i < L; ++i)
    sclls_polyz0_pack(sig + i * SCLLS_POLYZ0_PACKEDBYTES, &za->vec[i]);
  sig += L * SCLLS_POLYZ0_PACKEDBYTES;

  /* h_w: K 个多项式, 每个 sclls_polyhw_pack */
  for (i = 0; i < K; ++i)
    sclls_polyhw_pack(sig + i * SCLLS_HWBYTES_PERPOLY, &hw->vec[i]);
}

/**
 * @brief 解包代理签名 sigma_IDa
 *
 * @param cidp  输出 ~c_IDp
 * @param cida  输出 ~c_IDa
 * @param za    输出 z_a 向量
 * @param hw    输出 h_w 向量
 * @param sig   输入 sigma buffer
 */
void slps_unpack_sigma(uint8_t cidp[SLPS_CIDBYTES],
                      uint8_t cida[SLPS_CIDBYTES],
                      polyvecl* za,
                      polyveck* hw,
                      const uint8_t sig[SLPS_SIGBYTES])
{
  unsigned int i;
  const uint8_t* p = sig;

  /* ~c_IDp */
  for (i = 0; i < SLPS_CIDBYTES; ++i)
    cidp[i] = p[i];
  p += SLPS_CIDBYTES;

  /* ~c_IDa */
  for (i = 0; i < SLPS_CIDBYTES; ++i)
    cida[i] = p[i];
  p += SLPS_CIDBYTES;

  /* z_a */
  for (i = 0; i < L; ++i)
    sclls_polyz0_unpack(&za->vec[i], p + i * SCLLS_POLYZ0_PACKEDBYTES);
  p += L * SCLLS_POLYZ0_PACKEDBYTES;

  /* h_w */
  for (i = 0; i < K; ++i)
    sclls_polyhw_unpack(&hw->vec[i], p + i * SCLLS_HWBYTES_PERPOLY);
}

/*===============================================================
 * 用户签名 (~c, z) 用于 User-Sign 输出
 *===============================================================*/

/**
 * @brief 打包用户签名 sigma_IDi = (~c, z)
 *
 * 布局: ~c[CTILDEBYTES] || z[0..L-1] (polyz_pack)
 *
 * @param sig  输出 buffer (SLPS_USERSIGBYTES 字节)
 * @param cid  输入 ~c
 * @param z    输入 z 向量 (系数范围 [-(GAMMA1-1), GAMMA1])
 */
void slps_pack_user_sig(uint8_t sig[SLPS_USERSIGBYTES],
                       const uint8_t cid[SLPS_CIDBYTES],
                       const polyvecl* z)
{
  unsigned int i;

  /* ~c */
  for (i = 0; i < SLPS_CIDBYTES; ++i)
    sig[i] = cid[i];
  sig += SLPS_CIDBYTES;

  /* z: L 个多项式, 每个 polyz_pack */
  for (i = 0; i < L; ++i)
    polyz_pack(sig + i * POLYZ_PACKEDBYTES, &z->vec[i]);
}

/**
 * @brief 解包用户签名 sigma_IDi = (~c, z)
 *
 * @param cid  输出 ~c
 * @param z    输出 z 向量
 * @param sig  输入 sig buffer
 */
void slps_unpack_user_sig(uint8_t cid[SLPS_CIDBYTES],
                         polyvecl* z,
                         const uint8_t sig[SLPS_USERSIGBYTES])
{
  unsigned int i;
  const uint8_t* p = sig;

  /* ~c */
  for (i = 0; i < SLPS_CIDBYTES; ++i)
    cid[i] = p[i];
  p += SLPS_CIDBYTES;

  /* z */
  for (i = 0; i < L; ++i)
    polyz_unpack(&z->vec[i], p + i * POLYZ_PACKEDBYTES);
}
