/**
 * @file slps.c
 * @brief SLPS (Security Lattice-based Proxy Signature) 方案核心实现
 *
 * 基于 ML-DSA (Dilithium) 格密码框架，实现无证书代理签名机制。
 * 包含以下算法:
 *   1. Setup              - 系统参数生成
 *   2. User-Key-Gen      - 用户密钥对生成
 *   3. User-Sign         - 用户签名
 *   4. User-Verify       - 用户签名验证
 *   5. Principal-Authorize-Agent - 授权代理凭证生成
 *   6. Credential-Verify - 代理凭证验证
 *   7. Agent-Sign        - 代理签名
 *   8. Agent-Verify      - 代理签名验证
 *
 * 参考文献:
 *   - SLPS_scheme_20260417.tex
 *   - Dilithium / ML-DSA
 *
 * 域状态约定:
 *   - 标准域: 多项式系数在 [-Q, Q) 或 [0, Q) 范围内
 *   - NTT 域: 系数经过 ntt() 转换，用于加速乘法
 *   - 约减操作:
 *     poly_reduce / polyveck_reduce: 模 Q 约减到 [-Q/8, Q/8] 附近
 *     poly_caddq / polyveck_caddq: 规范化到 [0, Q) 标准代表元
 *   - 矩阵乘法流程: ntt -> pointwise_montgomery -> reduce -> invntt_tomont -> caddq
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "params.h"
#include "slps.h"
#include "slps_packing.h"
#include "polyvec.h"
#include "poly.h"
#include "symmetric.h"
#include "fips202.h"


/*===============================================================
 * slps_setup —— Setup: 系统参数生成
 *
 * 伪代码对应 (Algorithm Setup):
 *   rho <- {0,1}^256
 *   params := (H1, H2, H3, rho)
 *
 * 代码作用:
 *   从随机种子派生 rho (矩阵 A 的生成种子)。
 *   rho 通过 KDF 从 seed 派生，加上域名标签确保独立性。
 *   params 仅包含 rho, 矩阵 A 在各算法中通过 ExpandA(rho) 动态生成。
 *
 * 输出:
 *   params = rho (SLPS_PARAMSBYTES = SEEDBYTES 字节)
 *
 * 域状态: 无需进行多项式运算，直接从种子派生
 *===============================================================*/
int slps_setup(uint8_t* params, const uint8_t* seed)
{
  uint8_t seed_in[SEEDBYTES + 2];
  memcpy(seed_in, seed, SEEDBYTES);
  seed_in[SEEDBYTES + 0] = K;  /* Setup 域名标签 */
  seed_in[SEEDBYTES + 1] = L;
  shake256(params, SEEDBYTES, seed_in, SEEDBYTES + 2);
  return 0;
}


/*===============================================================
 * slps_user_key_gen —— User-Key-Gen: 用户密钥对生成
 *
 * 伪代码对应 (Algorithm User-Key-Gen):
 *   xi     <- {0,1}^256                    ← 直接取 seed
 *   K_IDi  <- {0,1}^256                    ← 从 seed 独立派生 H(seed)
 *   theta_IDi = H2(xi || IDi)             ← 将身份绑定到 theta
 *   (s1_IDi, s2_IDi) = ExpandS(theta_IDi)  ← 从 theta 采样短向量
 *   t_IDi = A * s1_IDi + s2_IDi
 *   tr_IDi = H1(rho || t_IDi)
 *   pk_IDi = (t_IDi)
 *   sk_IDi = (K_IDi, tr_IDi, s1_IDi, s2_IDi)
 *
 * 代码作用:
 *   为用户 IDi 生成密钥对 (pk, sk)。
 *   pk 包含公开向量 t_IDi, sk 包含秘密向量 s1, s2 和追踪值 tr。
 *
 * 输出:
 *   pk = t_IDi (K 个多项式, 压缩, SLPS_PKIDBYTES 字节)
 *   sk = K_IDi || tr || s1 || s2 (SLPS_SKIDBYTES 字节)
 *
 * 域状态变化:
 *   s1, s2: ETA 级短向量, 标准域
 *   t = A*s1 + s2: 标准域, 打包前需 caddq 到 [0, Q)
 *===============================================================*/
int slps_user_key_gen(uint8_t* pk,
                      uint8_t* sk,
                      const uint8_t* params,
                      const uint8_t* id,
                      const uint8_t* seed)
{
  uint8_t databuf[SEEDBYTES + CRHBYTES];    /* [32+64] = 96 字节 */
  uint8_t theta[CRHBYTES];                  /* theta = H2(xi || IDi) */
  uint8_t tr[TRBYTES];
  uint8_t rho_buf[SEEDBYTES];
  unsigned int i;
  keccak_state state;
  polyvecl mat[K], s1, s1hat;
  polyveck s2, t;

  /*
   * databuf 布局:
   *   [0..31]  xi     (32B, 从 seed 派生, 仅 Step 2 使用)
   *   [32..63] K_IDi  (32B, 从 seed 派生, Step 10 打包私钥使用)
   *
   * theta 存于独立的 theta[] 数组中 (64B)，不占用 databuf。
   * ExpandS 从独立的 theta[] 读取:
   *   theta[0..31]  驱动 s1 (L 个 eta 级短向量, nonce 从 0 开始)
   *   theta[32..63] 驱动 s2 (K 个 eta 级短向量, nonce 从 L 开始)
   */

  /* Step 1: 从 seed 派生 xi 和 K_IDi (独立 KDF，域名标签区分) */
  /* 用单次 shake256 输出 64B，前 32B 为 xi，后 32B 为 K_IDi */
  {
    uint8_t seed_in[SEEDBYTES + 2];
    memcpy(seed_in, seed, SEEDBYTES);
    seed_in[SEEDBYTES + 0] = L;  /* xi 的域名标签 */
    seed_in[SEEDBYTES + 1] = K;  /* K_IDi 的域名标签 */
    shake256(databuf, SEEDBYTES + SEEDBYTES,
             seed_in, SEEDBYTES + 2);
  }
  /* 现在 databuf[0..31] = xi, databuf[32..63] = K_IDi (不会被覆盖) */

  /* Step 2: theta = H2(xi || IDi)，将身份绑定到私钥派生 */
  /* H2 实现为 SHAKE256，输出 64 字节 (CRHBYTES) */
  shake256_init(&state);
  shake256_absorb(&state, databuf, SEEDBYTES);   /* xi */
  shake256_absorb(&state, id, SEEDBYTES);         /* IDi */
  shake256_finalize(&state);
  shake256_squeeze(theta, CRHBYTES, &state);
  /* theta 存于独立的 theta[] 数组中，databuf 中的 K_IDi 未被覆盖 */

  /* Step 4: 从 params 解包 rho */
  slps_unpack_params(rho_buf, params);

  /* Step 5: 扩展矩阵 A 并转换到 NTT 域 */
  polyvec_matrix_expand(mat, rho_buf);

  /* Step 6: 从 theta 采样短向量 s1 和 s2 (=ExpandS theta) */
  /* theta[0..31]  驱动 s1 (L 个 eta 级短向量, nonce 从 0 开始) */
  /* theta[32..63] 驱动 s2 (K 个 eta 级短向量, nonce 从 L 开始) */
  polyvecl_uniform_eta(&s1, theta, 0);
  polyveck_uniform_eta(&s2, theta, L);

  /* Step 7: 计算 t = A * s1 + s2 */
  s1hat = s1;
  polyvecl_ntt(&s1hat);
  polyvec_matrix_pointwise_montgomery(&t, mat, &s1hat);
  polyveck_reduce(&t);
  polyveck_invntt_tomont(&t);
  polyveck_add(&t, &t, &s2);

  /* Step 8: 规范化 t 到 [0, Q) 并打包公钥 */
  polyveck_caddq(&t);
  slps_pack_pk(pk, &t);

  /* Step 9: 计算 tr = H1(rho || pk) */
  /* pk 已由 slps_pack_pk 打包，其内容正是 H1 所需的输入 */
  shake256_init(&state);
  shake256_absorb(&state, rho_buf, SEEDBYTES);
  shake256_absorb(&state, pk, SLPS_PKIDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(tr, TRBYTES, &state);

  /* Step 10: 打包私钥 sk = K_IDi || tr || s1 || s2 */
  /* K_IDi 位于 databuf[32..63] */
  slps_pack_sk(sk, databuf + SEEDBYTES, tr, &s1, &s2);

  return 0;
}


/*===============================================================
 * slps_user_sign —— User-Sign: 用户签名
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
 * 代码作用:
 *   用户用自己的私钥对消息 M 签名。
 *   包含拒绝采样循环，保证签名不泄露私钥。
 *
 * 域状态变化 (关键):
 *   y:        标准域, 范围 [-GAMMA1, GAMMA1]
 *   w = A*y:  标准域, invntt 后需 caddq
 *   c:        NTT 域, pointwise_montgomery 乘法后需 reduce + invntt
 *   z = y + c*s1:  标准域, reduce 后检查范数
 *   r0 = LowBits(w - c*s2):  标准域
 *===============================================================*/
int slps_user_sign(uint8_t* sigma,
                   const uint8_t* m,
                   const uint8_t mlen,
                   const uint8_t* params,
                   const uint8_t* sk,
                   const uint8_t* seed)
{
  uint8_t databuf[TRBYTES + 2 * CRHBYTES + SEEDBYTES];
  uint8_t w1buf[K * POLYW1_PACKEDBYTES];
  uint8_t tr[TRBYTES];
  uint8_t key[SEEDBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t cid[CTILDEBYTES];
  uint8_t *mu, *nu1;
  uint16_t nonce = 0;
  keccak_state state;
  polyvecl mat[K], s1, y, z;
  polyveck s2, t, w, w1, w0, ww;
  poly cp;
  polyvecl yhat;

  /* 解析 databuf 布局 */
  mu  = databuf;
  nu1 = mu + CRHBYTES;

  /* Step 1: 解包私钥 sk = (key, tr, s1, s2) */
  slps_unpack_sk(key, tr, &s1, &s2, sk);

  /* Step 2: 解包 params 得到 rho 并扩展矩阵 A */
  slps_unpack_params(rho, params);
  polyvec_matrix_expand(mat, rho);

  /* Step 3: 计算 mu = H2(tr || M) */
  shake256_init(&state);
  shake256_absorb(&state, tr, TRBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  /* Step 4: 计算 nu1 = H2(key || mu) */
  shake256_init(&state);
  shake256_absorb(&state, key, SEEDBYTES);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_finalize(&state);
  shake256_squeeze(nu1, CRHBYTES, &state);

  /* Step 5: s1 和 s2 转换到 NTT 域 */
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);

  /* Step 6: 拒绝采样循环 */
rej:
  /* 采样遮掩向量 y */
  polyvecl_uniform_gamma1(&y, nu1, nonce);
  nonce = nonce + L;

  /* 计算 w = A * y */
  yhat = y;
  polyvecl_ntt(&yhat);
  polyvec_matrix_pointwise_montgomery(&w, mat, &yhat);
  polyveck_reduce(&w);
  polyveck_invntt_tomont(&w);
  ww = w;
  /* 分解 w -> (w1, w0) */
  polyveck_caddq(&w);
  polyveck_decompose(&w1, &w0, &w);
  polyveck_pack_w1(w1buf, &w1);

  /* 计算挑战 ~c = H3(mu || w1) */
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, w1buf, K * POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(cid, CTILDEBYTES, &state);

  /* c = SampleInBall(~c) */
  poly_challenge(&cp, cid);
  poly_ntt(&cp);

  /* 计算 z = y + c * s1 */
  {
    polyvecl cs1;
    polyvecl_pointwise_poly_montgomery(&cs1, &cp, &s1);
    polyvecl_invntt_tomont(&cs1);
    polyvecl_add(&z, &y, &cs1);
    polyvecl_reduce(&z);
  }

  /* 拒绝采样检查 #1: ||z||_inf < GAMMA1 - BETA */
  if (polyvecl_chknorm(&z, GAMMA1 - BETA))
    goto rej;

  /* 计算 r0 = LowBits(w - c * s2) */
  {
    polyveck cs2;
    polyveck_caddq(&ww);
  
    polyveck_pointwise_poly_montgomery(&cs2, &cp, &s2);
    polyveck_reduce(&cs2);
    polyveck_invntt_tomont(&cs2);
    polyveck_sub(&ww, &ww, &cs2);
    polyveck_decompose(&w1, &w0, &ww);
    polyveck_reduce(&w0);
  }

  /* 拒绝采样检查 #2: ||r0||_inf < GAMMA2 - BETA */
  if (polyveck_chknorm(&w0, GAMMA2 - BETA))
    goto rej;

  /* Step 7: 打包签名 sigma = (~c, z) */
  slps_pack_user_sig(sigma, cid, &z);

  return 0;
}


/*===============================================================
 * slps_user_verify —— User-Verify: 用户签名验证
 *
 * 伪代码对应 (Algorithm User-Verify):
 *   tr = H1(rho || t_IDi)
 *   mu = H2(tr || M)
 *   c = SampleInBall(~c)
 *   w'1 = HighBits(A*z - c*t_IDi, 2*gamma2)
 *   ~c' = H3(mu || w'1)
 *   if ||z||_inf < gamma1 - beta and ~c = ~c': Verify = True
 *
 * 代码作用:
 *   验证用户签名 sigma 是否由对应公钥 pk 的持有者生成。
 *
 * 域状态变化:
 *   z: 标准域, unpack 后在 [-(GAMMA1-1), GAMMA1]
 *   t: 标准域, unpack 后在 [0, Q)
 *   A*z - c*t: 标准域, invntt 后需 caddq
 *===============================================================*/
int slps_user_verify(const uint8_t* m,
                     const uint8_t mlen,
                     const uint8_t* sigma,
                     const uint8_t* params,
                     const uint8_t* pk)
{
  uint8_t databuf[TRBYTES + CRHBYTES];
  uint8_t tr[TRBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t *mu;
  uint8_t cid[CTILDEBYTES], c2[CTILDEBYTES];
  uint8_t w1buf[K * POLYW1_PACKEDBYTES];
  unsigned int i;
  keccak_state state;
  polyvecl mat[K], z;
  polyveck t, az, az1, az0;
  poly cp;

  /* 解析布局 */
  mu = databuf;

  /* Step 1: 解包签名 sigma = (~c, z) */
  slps_unpack_user_sig(cid, &z, sigma);

  /* Step 2: 检查 z 的范数 ||z||_inf < GAMMA1 - BETA */
  if (polyvecl_chknorm(&z, GAMMA1 - BETA))
    return -1;

  /* Step 3: 解包公钥 pk = t */
  slps_unpack_pk(&t, pk);

  /* Step 4: 从 params 解包 rho 并扩展矩阵 A */
  slps_unpack_params(rho, params);
  polyvec_matrix_expand(mat, rho);

  /* Step 5: 计算 tr = H1(rho || pk) */
  shake256_init(&state);
  shake256_absorb(&state, rho, SEEDBYTES);
  shake256_absorb(&state, pk, SLPS_PKIDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(tr, TRBYTES, &state);

  /* Step 6: 计算 mu = H2(tr || M) */
  shake256_init(&state);
  shake256_absorb(&state, tr, TRBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  /* Step 7: 解包 ~c 为多项式 c, 转换到 NTT 域 */
  poly_challenge(&cp, cid);
  poly_ntt(&cp);

  /* Step 8: 计算 w'1 = HighBits(A*z - c*t, 2*gamma2) */
  /* 计算 A*z */
  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&az, mat, &z);
  polyveck_reduce(&az);
  polyveck_invntt_tomont(&az);

  /* 减去 c*t */
  {
    polyveck ct;
    polyveck_ntt(&t);
    polyveck_pointwise_poly_montgomery(&ct, &cp, &t);
    polyveck_reduce(&ct);
    polyveck_invntt_tomont(&ct);
    polyveck_sub(&az, &az, &ct);
    polyveck_reduce(&az);
  }

  /* 分解 az -> (az1, az0) */
  polyveck_caddq(&az);
  polyveck_decompose(&az1, &az0, &az);
  polyveck_pack_w1(w1buf, &az1);

  /* Step 9: 重新计算 ~c' = H3(mu || w'1) */
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, w1buf, K * POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(c2, CTILDEBYTES, &state);

  /* Step 10: 比较 ~c 和 ~c' */
  for (i = 0; i < CTILDEBYTES; ++i)
    if (cid[i] != c2[i])
      return -1;

  return 0;
}


/*===============================================================
 * slps_principal_authorize_agent —— Principal-Authorize-Agent: 授权代理凭证生成
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
 * 代码作用:
 *   授权者使用自己的私钥 sk_IDp, 为代理者生成授权凭证 T_IDp。
 *   包含拒绝采样循环。
 *
 * 域状态变化:
 *   y_IDp: 标准域, 范围 [-GAMMA1, GAMMA1]
 *   z_IDp: 标准域
 *   w1_IDp: w 的高 bits, 用于生成挑战
 *===============================================================*/
int slps_principal_authorize_agent(uint8_t* t,
                                   const uint8_t* params,
                                   const uint8_t* sk,
                                   const uint8_t* idp,
                                   const uint8_t* ida,
                                   const uint8_t* pka,
                                   const uint8_t* seed)
{
  uint8_t databuf[TRBYTES + 2 * CRHBYTES];
  uint8_t tra[TRBYTES];
  uint8_t w1buf[K * POLYW1_PACKEDBYTES];
  uint8_t key[SEEDBYTES];
  uint8_t trp[TRBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t cidp[CTILDEBYTES];
  uint8_t *mu, *nu2;
  uint16_t nonce = 0;
  keccak_state state;
  polyvecl mat[K], s1p, yp, zip;
  polyveck s2p, tp, wa, wa1, wa0;
  poly cp;
  polyvecl yphat;

  /* 解析布局 */
  mu  = databuf;
  nu2 = mu + CRHBYTES;

  /* Step 1: 解包授权者私钥 sk_IDp = (key, tr, s1, s2) */
  slps_unpack_sk(key, trp, &s1p, &s2p, sk);

  /* Step 2: 解包 pka = t_IDa */
  slps_unpack_pk(&tp, pka);

  /* Step 3: 解包 params 得到 rho 并扩展矩阵 A */
  slps_unpack_params(rho, params);
  polyvec_matrix_expand(mat, rho);

  /* Step 4: 计算 tr_IDa = H1(rho || t_IDa) */
  {
    uint8_t pkabuf[SLPS_PKIDBYTES];
    slps_pack_pk(pkabuf, &tp);
    shake256_init(&state);
    shake256_absorb(&state, rho, SEEDBYTES);
    shake256_absorb(&state, pkabuf, SLPS_PKIDBYTES);
    shake256_finalize(&state);
    shake256_squeeze(tra, TRBYTES, &state);
  }

  /* Step 5: 计算 mu_IDp = H2(tr_IDp || tr_IDa || IDp || IDa) */
  /* trp 是授权者自己的追踪值, 从 sk 解包得到 */
  shake256_init(&state);
  shake256_absorb(&state, trp, TRBYTES);
  shake256_absorb(&state, tra, TRBYTES);
  shake256_absorb(&state, idp, SEEDBYTES);
  shake256_absorb(&state, ida, SEEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  /* Step 6: 计算 nu2 = H2(K_IDp || mu_IDp) */
  shake256_init(&state);
  shake256_absorb(&state, key, SEEDBYTES);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_finalize(&state);
  shake256_squeeze(nu2, CRHBYTES, &state);

  /* Step 7: s1p 和 s2p 转换到 NTT 域 */
  polyvecl_ntt(&s1p);
  polyveck_ntt(&s2p);

  /* Step 8: 拒绝采样循环 */
rej:
  /* 采样遮掩向量 yp */
  polyvecl_uniform_gamma1(&yp, nu2, nonce);
  nonce = nonce + L;

  /* 计算 w_IDp = A * yp */
  yphat = yp;
  polyvecl_ntt(&yphat);
  polyvec_matrix_pointwise_montgomery(&wa, mat, &yphat);
  polyveck_reduce(&wa);
  polyveck_invntt_tomont(&wa);

  /* 分解 wa -> (wa1, wa0) */
  polyveck_caddq(&wa);
  polyveck_decompose(&wa1, &wa0, &wa);
  polyveck_pack_w1(w1buf, &wa1);

  /* 计算挑战 ~c_IDp = H3(mu_IDp || w1_IDp) */
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, w1buf, K * POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(cidp, CTILDEBYTES, &state);

  /* c_IDp = SampleInBall(~c_IDp) */
  poly_challenge(&cp, cidp);
  poly_ntt(&cp);

  /* 计算 z_IDp = yp + c_IDp * s1p */
  {
    polyvecl cs1p;
    polyvecl_pointwise_poly_montgomery(&cs1p, &cp, &s1p);
    polyvecl_invntt_tomont(&cs1p);
    polyvecl_add(&zip, &yp, &cs1p);
    polyvecl_reduce(&zip);
  }

  /* 拒绝采样检查 #1: ||z_IDp||_inf < GAMMA1 - BETA */
  if (polyvecl_chknorm(&zip, GAMMA1 - BETA))
    goto rej;

  /* 计算 r0 = LowBits(wa - c_IDp * s2p) */
  {
    polyveck cs2p, wr, wr1;
    polyveck_pointwise_poly_montgomery(&cs2p, &cp, &s2p);
    polyveck_reduce(&cs2p);
    polyveck_invntt_tomont(&cs2p);
    /* 从完整的 wa (非 wa1) 减去 c*s2，再分解取低位 */
    polyveck_sub(&wr, &wa, &cs2p);
    polyveck_reduce(&wr);
    polyveck_decompose(&wr1, &wa0, &wr);
  }

  /* 拒绝采样检查 #2: ||r0||_inf < GAMMA2 - BETA */
  if (polyveck_chknorm(&wa0, GAMMA2 - BETA))
    goto rej;

  /* Step 9: 打包凭证 T_IDp = (IDp, IDa, ~c_IDp, z_IDp) */
  slps_pack_tidp(t, idp, ida, cidp, &zip);

  return 0;
}


/*===============================================================
 * slps_credential_verify —— Credential-Verify: 代理凭证验证
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
 * 代码作用:
 *   验证代理凭证 T_IDp 是否由授权者 pkp 合法签发。
 *
 * 域状态变化:
 *   z_IDp: 标准域, unpack 后
 *   t:     标准域, unpack 后
 *===============================================================*/
int slps_credential_verify(const uint8_t* t,
                          const uint8_t* params,
                          const uint8_t* pkp,
                          const uint8_t* pka,
                          const uint8_t* idp,
                          const uint8_t* ida)
{
  uint8_t databuf[TRBYTES + CRHBYTES];
  uint8_t trp[TRBYTES], tra[TRBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t idp_in[SEEDBYTES], ida_in[SEEDBYTES];
  uint8_t *mu;
  uint8_t cidp[CTILDEBYTES], cidp2[CTILDEBYTES];
  uint8_t w1buf[K * POLYW1_PACKEDBYTES];
  unsigned int i;
  keccak_state state;
  polyvecl mat[K], zip;
  polyveck tp, tka, az, az1, az0;
  poly cp;

  /* 解析布局 */
  mu = databuf;

  /* Step 1: 解包凭证 T_IDp = (IDp, IDa, ~c_IDp, z_IDp) */
  slps_unpack_tidp(idp_in, ida_in, cidp, &zip, t);

  /* Step 2: 检查 z_IDp 的范数 ||z_IDp||_inf < GAMMA1 - BETA */
  if (polyvecl_chknorm(&zip, GAMMA1 - BETA))
    return -1;

  /* Step 2b: 校验凭证中的身份与输入身份一致 */
  if (memcmp(idp_in, idp, SEEDBYTES) != 0)
    return -1;
  if (memcmp(ida_in, ida, SEEDBYTES) != 0)
    return -1;

  /* Step 3: 解包公钥 pkp = t_IDp 和 pka = t_IDa */
  slps_unpack_pk(&tp, pkp);
  slps_unpack_pk(&tka, pka);

  /* Step 4: 从 params 解包 rho 并扩展矩阵 A */
  slps_unpack_params(rho, params);
  polyvec_matrix_expand(mat, rho);

  /* Step 5: 计算 tr_IDp = H1(rho || t_IDp) 和 tr_IDa = H1(rho || t_IDa) */
  {
    uint8_t pkpbuf[SLPS_PKIDBYTES];
    uint8_t pkabuf[SLPS_PKIDBYTES];
    slps_pack_pk(pkpbuf, &tp);
    slps_pack_pk(pkabuf, &tka);
    shake256_init(&state);
    shake256_absorb(&state, rho, SEEDBYTES);
    shake256_absorb(&state, pkpbuf, SLPS_PKIDBYTES);
    shake256_finalize(&state);
    shake256_squeeze(trp, TRBYTES, &state);
    shake256_init(&state);
    shake256_absorb(&state, rho, SEEDBYTES);
    shake256_absorb(&state, pkabuf, SLPS_PKIDBYTES);
    shake256_finalize(&state);
    shake256_squeeze(tra, TRBYTES, &state);
  }

  /* Step 6: 计算 mu_IDp = H2(tr_IDp || tr_IDa || IDp || IDa) */
  shake256_init(&state);
  shake256_absorb(&state, trp, TRBYTES);
  shake256_absorb(&state, tra, TRBYTES);
  shake256_absorb(&state, idp, SEEDBYTES);
  shake256_absorb(&state, ida, SEEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  /* Step 7: 解包 ~c_IDp 为多项式 c, 转换到 NTT 域 */
  poly_challenge(&cp, cidp);
  poly_ntt(&cp);

  /* Step 8: 计算 w'1_IDp = HighBits(A*z_IDp - c_IDp*t_IDp, 2*gamma2) */
  /* 计算 A*z_IDp */
  polyvecl_ntt(&zip);
  polyvec_matrix_pointwise_montgomery(&az, mat, &zip);
  polyveck_reduce(&az);
  polyveck_invntt_tomont(&az);

  /* 减去 c_IDp*t_IDp */
  {
    polyveck ct;
    polyveck_ntt(&tp);
    polyveck_pointwise_poly_montgomery(&ct, &cp, &tp);
    polyveck_reduce(&ct);
    polyveck_invntt_tomont(&ct);
    polyveck_sub(&az, &az, &ct);
    polyveck_reduce(&az);
  }

  /* 分解 az -> (az1, az0) */
  polyveck_caddq(&az);
  polyveck_decompose(&az1, &az0, &az);
  polyveck_pack_w1(w1buf, &az1);

  /* Step 9: 重新计算 ~c'_IDp = H3(mu_IDp || w'1_IDp) */
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, w1buf, K * POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(cidp2, CTILDEBYTES, &state);

  /* Step 10: 比较 ~c_IDp 和 ~c'_IDp */
  for (i = 0; i < CTILDEBYTES; ++i)
    if (cidp[i] != cidp2[i])
      return -1;

  return 0;
}


/*===============================================================
 * slps_agent_sign —— Agent-Sign: 代理签名
 *
 * 伪代码对应 (Algorithm Agent-Sign):
 *   c_IDp = SampleInBall(~c_IDp)
 *   w'1_IDp = HighBits(A*z_IDp - c_IDp*t_IDp, 2*gamma2)
 *   mu_IDa = H2(tr_IDa || M)
 *   nu3 = H2(K_IDa || mu)           <-- 注: 伪代码写 mu, 实际是 mu_IDa
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
 * 代码作用:
 *   代理者使用凭证 T_IDp 和自己的私钥 sk_IDa 生成代理签名。
 *   包含拒绝采样循环和 Makeh_w 提示向量计算。
 *
 * 域状态变化:
 *   z_IDp: 标准域, 从凭证解包
 *   w'1_IDp: w1 向量, 用于后续计算
 *   y_IDa: 标准域
 *   z_IDa: 标准域
 *   z_a = z_IDa + z_IDp: 标准域
 *   Makeh_w: a = A*z_IDp - c_IDp*t_IDp, b = w_IDa - c_IDa*s2_IDa
 *     -> 各参数需 caddq 后 decompose, 结果 hw 也在标准域
 *===============================================================*/
int slps_agent_sign(uint8_t* sig,
                    const uint8_t* m,
                    const uint8_t mlen,
                    const uint8_t* params,
                    const uint8_t* t,
                    const uint8_t* pkp,
                    const uint8_t* sk,
                    const uint8_t* seed)
{
  uint8_t databuf[TRBYTES + 2 * CRHBYTES];
  uint8_t tra[TRBYTES];
  uint8_t w1buf[K * POLYW1_PACKEDBYTES];
  uint8_t w1idpbuf[K * POLYW1_PACKEDBYTES];
  uint8_t key[SEEDBYTES];
  uint8_t trp[TRBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t idp_in[SEEDBYTES];
  uint8_t ida_in[SEEDBYTES];
  uint8_t *mu, *nu3;
  uint8_t cidp_bytes[CTILDEBYTES], cida_bytes[CTILDEBYTES];
  uint16_t nonce = 0;
  keccak_state state;
  polyvecl mat[K], s1, y, za_id, za, zip;
  polyveck tpidp;
  polyveck wa, wa1, wa0, cs2, hw;
  polyveck az_idp, b, w1a, w_full, w_minus_cs2, w_for_decompose, w_tmp;
  poly cp, cidp;
  polyvecl yhat;

  /* 解析布局 */
  mu  = databuf;
  nu3 = mu + CRHBYTES;

  /* Step 1: 解包凭证 T_IDp = (IDp, IDa, ~c_IDp, z_IDp) */
  slps_unpack_tidp(idp_in, ida_in, cidp_bytes, &za_id, t);
  poly_challenge(&cidp, cidp_bytes);
  poly_ntt(&cidp);

  /* Step 2: 解包授权者公钥 pkp = t_IDp */
  slps_unpack_pk(&tpidp, pkp);

  /* Step 3: 解包代理者私钥 sk_IDa = (key, tr, s1, s2) */
  slps_unpack_sk(key, trp, &s1, &cs2, sk);

  /* Step 4: 解包 params 得到 rho 并扩展矩阵 A */
  slps_unpack_params(rho, params);
  polyvec_matrix_expand(mat, rho);

  /* Step 5: tra = tr_IDa (从 sk 解包得到的追踪值) */
  memcpy(tra, trp, TRBYTES);

  /* Step 6: 计算 w'1_IDp = HighBits(A*z_IDp - c_IDp*t_IDp, 2*gamma2) */
  {
    polyveck ctpidp;
    polyvecl_ntt(&za_id);
    polyvec_matrix_pointwise_montgomery(&az_idp, mat, &za_id);
    polyveck_reduce(&az_idp);
    polyveck_invntt_tomont(&az_idp);

    polyveck_ntt(&tpidp);
    polyveck_pointwise_poly_montgomery(&ctpidp, &cidp, &tpidp);
    polyveck_reduce(&ctpidp);
    polyveck_invntt_tomont(&ctpidp);
    polyveck_sub(&az_idp, &az_idp, &ctpidp);
    polyveck_reduce(&az_idp);

    /* 分解得到 w'1_IDp (临时存放于 w1idpbuf) */
    {
      polyveck tmp1, tmp0;
      polyveck_caddq(&az_idp);
      polyveck_decompose(&tmp1, &tmp0, &az_idp);
      polyveck_pack_w1(w1idpbuf, &tmp1);
    }
  }

  /* Step 7: 计算 mu_IDa = H2(tr_IDa || M) */
  shake256_init(&state);
  shake256_absorb(&state, tra, TRBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  /* Step 8: 计算 nu3 = H2(K_IDa || mu_IDa) */
  shake256_init(&state);
  shake256_absorb(&state, key, SEEDBYTES);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_finalize(&state);
  shake256_squeeze(nu3, CRHBYTES, &state);

  /* Step 9: s1 和 s2 转换到 NTT 域 */
  polyvecl_ntt(&s1);
  polyveck_ntt(&cs2);

  /* Step 10: 拒绝采样循环 */
rej:
  /* 采样遮掩向量 y */
  polyvecl_uniform_gamma1(&y, nu3, nonce);
  nonce = nonce + L;

  /* 计算 w_IDa = A * y，同时保留完整 w 用于 w - c*s2 */
  yhat = y;
  polyvecl_ntt(&yhat);
  polyvec_matrix_pointwise_montgomery(&w_full, mat, &yhat);
  polyveck_reduce(&w_full);
  polyveck_invntt_tomont(&w_full);

  /* w_minus_cs2 = w - c*s2，用于 decompose 取低位（r0） */
  {
    polyveck cs2tmp;
    polyveck_pointwise_poly_montgomery(&cs2tmp, &cp, &cs2);
    polyveck_reduce(&cs2tmp);
    polyveck_invntt_tomont(&cs2tmp);
    polyveck_sub(&w_minus_cs2, &w_full, &cs2tmp);
    polyveck_reduce(&w_minus_cs2);
  }

  /* 对原始 w 分解取高位，用于计算 w1_a */
  w_for_decompose = w_full;
  polyveck_caddq(&w_for_decompose);
  polyveck_decompose(&wa1, &w_tmp, &w_for_decompose);

  /* w1_a = wa1 + w'1_IDp，打包 w1buf */
  {
    unsigned int j;
    sclls_polyveck_unpack_w1(&w1a, w1idpbuf);
    polyveck_add(&w1a, &w1a, &wa1);
    polyveck_caddq(&w1a);
    polyveck_pack_w1(w1buf, &w1a);
  }

  /* 对 w - c*s2 分解取低位，作为 r0 */
  polyveck_caddq(&w_minus_cs2);
  polyveck_decompose(&wa1, &wa0, &w_minus_cs2);

  /* 计算挑战 ~c_IDa = H3(mu_IDa || w1_a) */
  {
    uint8_t cida_tmp[CTILDEBYTES];
    unsigned int j;
    shake256_init(&state);
    shake256_absorb(&state, mu, CRHBYTES);
    shake256_absorb(&state, w1buf, K * POLYW1_PACKEDBYTES);
    shake256_finalize(&state);
    shake256_squeeze(cida_tmp, CTILDEBYTES, &state);

    /* c_IDa = SampleInBall(~c_IDa) */
    poly_challenge(&cp, cida_tmp);
    poly_ntt(&cp);

    /* 保存 ~c_IDa 供 Step 13 打包签名使用 */
    for (j = 0; j < CTILDEBYTES; ++j)
      cida_bytes[j] = cida_tmp[j];
  }

  /* 计算 z_IDa = y + c_IDa * s1 */
  {
    polyvecl cs1;
    polyvecl_pointwise_poly_montgomery(&cs1, &cp, &s1);
    polyvecl_invntt_tomont(&cs1);
    polyvecl_add(&za_id, &y, &cs1);
    polyvecl_reduce(&za_id);
  }

  /* 拒绝采样检查 #1: ||z_IDa||_inf < GAMMA1 - BETA */
  if (polyvecl_chknorm(&za_id, GAMMA1 - BETA))
    goto rej;

  /* 拒绝采样检查 #2: ||r0||_inf < GAMMA2 - BETA (wa0 已是 w - c*s2 的低位) */
  if (polyveck_chknorm(&wa0, GAMMA2 - BETA))
    goto rej;

  /* Step 11: 计算 z_a = z_IDa + z_IDp */
  {
    uint8_t ida_tmp[SEEDBYTES];
    slps_unpack_tidp(idp_in, ida_tmp, cidp_bytes, &zip, t);
    polyvecl_add(&za, &za_id, &zip);
  }

  /* Step 12: 计算提示 hw = Makeh_w(A*z_IDp - c_IDp*t_IDp, w - c_IDa*s2) */
  /* a = az_idp 已计算出 (A*z_IDp - c_IDp*t_IDp) */
  /* b = w - c_IDa*s2，复用 w_minus_cs2（w_full 已被 decompose 原地修改） */
  {
    polyveck b_tmp;
    /* w_minus_cs2 已是完整的 w - c*s2，无需重新计算 */
    b_tmp = w_minus_cs2;
    polyveck_caddq(&b_tmp);
    /* 调用 Makeh_w，Makeh_w 内部会 decompose az_idp 和 b_tmp */
    sclls_polyveck_make_hw(&hw, &az_idp, &b_tmp);
  }

  /* Step 13: 打包签名 sigma = (~c_IDp, ~c_IDa, z_a, h_w) */
  {
    /* ~c_IDa: 直接复用拒绝采样循环中已计算的 cida_bytes */
    slps_pack_sigma(sig, cidp_bytes, cida_bytes, &za, &hw);
  }

  return 0;
}


/*===============================================================
 * slps_agent_verify —— Agent-Verify: 代理签名验证
 *
 * 伪代码对应 (Algorithm Agent-Verify):
 *   c_IDp = SampleInBall(~c_IDp)
 *   c_IDa = SampleInBall(~c_IDa)
 *   w'1_a = HighBits(A*z_a - c_IDp*t_IDp - c_IDa*t_IDa, 2*gamma2) - h_w
 *   mu_IDa = H2(tr_IDa || M)
 *   ~c'_IDa = H3(mu_IDa || w'1_IDa)
 *   if ||z_a||_inf < 2*gamma1 - 2*beta and ~c_IDa = ~c'_IDa: Verify = True
 *
 * 代码作用:
 *   验证代理签名 sigma 是否由代理者使用合法凭证签发。
 *
 * 域状态变化:
 *   z_a: 标准域, unpack 后范围 [-2*GAMMA1, 2*GAMMA1]
 *   t:   标准域, unpack 后
 *   A*z_a - c1*t - c2*t: 标准域
 *   w'1_a = HighBits(...) - h_w: 恢复的 w1 向量
 *===============================================================*/
int slps_agent_verify(const uint8_t* m,
                      const uint8_t mlen,
                      const uint8_t* sig,
                      const uint8_t* params,
                      const uint8_t* pkp,
                      const uint8_t* pka,
                      const uint8_t* ida,
                      const uint8_t* idp)
{
  uint8_t databuf[TRBYTES + CRHBYTES];
  uint8_t tr[TRBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t *mu;
  uint8_t cidp[CTILDEBYTES], cida[CTILDEBYTES], c2[CTILDEBYTES];
  uint8_t w1buf[K * POLYW1_PACKEDBYTES];
  unsigned int i;
  keccak_state state;
  polyvecl mat[K], za;
  polyveck tkp, tka, az, az1, az0, hw;
  poly cp, cidpp;

  /* 解析布局 */
  mu = databuf;

  /* Step 1: 解包签名 sigma = (~c_IDp, ~c_IDa, z_a, h_w) */
  slps_unpack_sigma(cidp, cida, &za, &hw, sig);

  /* Step 2: 检查 z_a 的范数 ||z_a||_inf < 2*GAMMA1 - 2*BETA */
  if (polyvecl_chknorm(&za, 2 * (GAMMA1 - BETA)))
    return -1;

  /* Step 3: 解包公钥 pkp = t_IDp 和 pka = t_IDa */
  slps_unpack_pk(&tkp, pkp);
  slps_unpack_pk(&tka, pka);

  /* Step 4: 从 params 解包 rho 并扩展矩阵 A */
  slps_unpack_params(rho, params);
  polyvec_matrix_expand(mat, rho);

  /* Step 5: 计算 tr_IDa = H1(rho || t_IDa) */
  {
    uint8_t pkabuf[SLPS_PKIDBYTES];
    slps_pack_pk(pkabuf, &tka);
    shake256_init(&state);
    shake256_absorb(&state, rho, SEEDBYTES);
    shake256_absorb(&state, pkabuf, SLPS_PKIDBYTES);
    shake256_finalize(&state);
    shake256_squeeze(tr, TRBYTES, &state);
  }

  /* Step 6: 计算 mu_IDa = H2(tr_IDa || M) */
  shake256_init(&state);
  shake256_absorb(&state, tr, TRBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  /* Step 7: 解包挑战 c_IDp 和 c_IDa, 转换到 NTT 域 */
  poly_challenge(&cidpp, cidp);
  poly_ntt(&cidpp);
  poly_challenge(&cp, cida);
  poly_ntt(&cp);

  /* Step 8: 计算 w'1_a = HighBits(A*z_a - c_IDp*t_IDp - c_IDa*t_IDa, 2*gamma2) - h_w */
  /* 计算 A*z_a */
  polyvecl_ntt(&za);
  polyvec_matrix_pointwise_montgomery(&az, mat, &za);
  polyveck_reduce(&az);
  polyveck_invntt_tomont(&az);

  /* 减去 c_IDp*t_IDp */
  {
    polyveck ct;
    polyveck_ntt(&tkp);
    polyveck_pointwise_poly_montgomery(&ct, &cidpp, &tkp);
    polyveck_reduce(&ct);
    polyveck_invntt_tomont(&ct);
    polyveck_sub(&az, &az, &ct);
    polyveck_reduce(&az);
  }

  /* 减去 c_IDa*t_IDa */
  {
    polyveck ct;
    polyveck_ntt(&tka);
    polyveck_pointwise_poly_montgomery(&ct, &cp, &tka);
    polyveck_reduce(&ct);
    polyveck_invntt_tomont(&ct);
    polyveck_sub(&az, &az, &ct);
    polyveck_reduce(&az);
  }

  /* 分解并减去 h_w */
  polyveck_caddq(&az);
  polyveck_decompose(&az1, &az0, &az);
  polyveck_sub(&az1, &az1, &hw);
  polyveck_pack_w1(w1buf, &az1);

  /* Step 9: 计算 ~c'_IDa = H3(mu_IDa || w'1_a) */
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, w1buf, K * POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(c2, CTILDEBYTES, &state);

  /* Step 10: 比较 ~c_IDa 和 ~c'_IDa */
  for (i = 0; i < CTILDEBYTES; ++i)
    if (cida[i] != c2[i])
      return -1;

  return 0;
}
