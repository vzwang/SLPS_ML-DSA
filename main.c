/**
 * @file main.c
 * @brief SLPS 方案测试程序
 *
 * 测试 SLPS 的完整流程:
 *   1. Setup - 系统参数生成
 *   2. User-Key-Gen - 用户密钥对生成 (Principal 和 Agent)
 *   3. User-Sign / User-Verify - 用户签名验证
 *   4. Principal-Authorize-Agent - 代理授权凭证生成
 *   5. Credential-Verify - 凭证验证
 *   6. Agent-Sign / Agent-Verify - 代理签名验证
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "params.h"
#include "slps.h"
#include "slps_packing.h"

int main(void)
{
    /* 随机种子 */
    uint8_t seed[SEEDBYTES] = {
        0xCB, 0xB8, 0x15, 0x2F, 0x8A, 0x89, 0x01, 0xCE,
        0x2B, 0x5B, 0x5A, 0xD5, 0x0E, 0xA1, 0xB0, 0x02,
        0x8C, 0x5C, 0x3E, 0xC9, 0xF5, 0xD0, 0xA1, 0xD5,
        0x4B, 0x18, 0xB4, 0xBF, 0x55, 0xBF, 0xE6, 0x2D
    };
    uint8_t rnd[SEEDBYTES] = {
        0x2F, 0xA0, 0x7D, 0x7C, 0x60, 0x29, 0x40, 0x6B,
        0x8F, 0x52, 0xF3, 0x56, 0x19, 0xC5, 0x7B, 0x5E,
        0x5B, 0xF4, 0xE4, 0x67, 0x36, 0x6E, 0xB5, 0x82,
        0xA9, 0x34, 0xD0, 0xA8, 0x51, 0x6B, 0xB7, 0x28
    };

    /* 消息 */
    uint8_t m[SEEDBYTES] = {
        0xD5, 0xC2, 0x93, 0xCE, 0x6B, 0xDE, 0xD2, 0x1E,
        0x3A, 0xAD, 0x35, 0x61, 0x00, 0xCA, 0x8D, 0x6E,
        0x42, 0xE3, 0x94, 0x50, 0xCB, 0x1C, 0x43, 0x5B,
        0x7D, 0xD8, 0x02, 0xEA, 0x43, 0x74, 0x65, 0x32
    };
    uint8_t mlen = SEEDBYTES;

    /* 身份信息 */
    /* Principal 身份 IDp */
    uint8_t idp[SEEDBYTES];
    /* Agent 身份 IDa */
    uint8_t ida[SEEDBYTES];
    /* Principal 授权者密钥对 */
    uint8_t pkp[SLPS_PKIDBYTES];
    uint8_t skp[SLPS_SKIDBYTES];
    /* Agent 代理者密钥对 */
    uint8_t pka[SLPS_PKIDBYTES];
    uint8_t ska[SLPS_SKIDBYTES];

    /* 代理凭证 T_IDp */
    uint8_t t_idp[SLPS_TIDPBYTES];

    /* 签名 */
    uint8_t user_sig[SLPS_USERSIGBYTES];
    uint8_t agent_sig[SLPS_SIGBYTES];

    /* 返回值 */
    int ret = 0;

    /* 时间戳 */
    {
        time_t now;
        struct tm tm_local;
        char timestr[80];
        time(&now);
        if (localtime_s(&tm_local, &now) == 0 &&
            strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &tm_local) > 0)
            printf("SLPS Test Start: %s\n", timestr);
    }

    /* 初始化身份信息 */
    memset(idp, 0x01, SEEDBYTES);
    memset(ida, 0x02, SEEDBYTES);

    /*===============================================================
     * Step 1: Setup - 系统参数生成
     *===============================================================*/
    printf("\n========== Step 1: SLPS Setup ==========\n");
    {
        uint8_t params[SLPS_PARAMSBYTES];
        slps_setup(params, seed);
        printf("params_len = %d (expected %d)\n", SLPS_PARAMSBYTES, SEEDBYTES);
    }

    /*===============================================================
     * Step 2: User-Key-Gen - Principal 和 Agent 的密钥对生成
     *===============================================================*/
    printf("\n========== Step 2: User-Key-Gen ==========\n");
    {
        uint8_t params[SLPS_PARAMSBYTES];
        uint8_t seed_p[SEEDBYTES];
        uint8_t seed_a[SEEDBYTES];

        slps_setup(params, seed);

        /* Principal 密钥对 */
        memcpy(seed_p, seed, SEEDBYTES);
        seed_p[0] ^= 0x11;  /* 区分 Principal 的种子 */
        slps_user_key_gen(pkp, skp, params, idp, seed_p);
        printf("Principal:\n");
        printf("  pk_len = %d (expected %d)\n", SLPS_PKIDBYTES, K * SCLLS_POLYT_PACKEDBYTES);
        printf("  sk_len = %d (expected %d)\n", SLPS_SKIDBYTES,
               SEEDBYTES + TRBYTES + L * POLYETA_PACKEDBYTES + K * POLYETA_PACKEDBYTES);

        /* Agent 密钥对 */
        memcpy(seed_a, seed, SEEDBYTES);
        seed_a[0] ^= 0x22;  /* 区分 Agent 的种子 */
        slps_user_key_gen(pka, ska, params, ida, seed_a);
        printf("Agent:\n");
        printf("  pk_len = %d (expected %d)\n", SLPS_PKIDBYTES, K * SCLLS_POLYT_PACKEDBYTES);
        printf("  sk_len = %d (expected %d)\n", SLPS_SKIDBYTES,
               SEEDBYTES + TRBYTES + L * POLYETA_PACKEDBYTES + K * POLYETA_PACKEDBYTES);
    }

    /*===============================================================
     * Step 3: User-Sign / User-Verify - 用户签名验证
     *===============================================================*/
    printf("\n========== Step 3: User-Sign / User-Verify ==========\n");
    {
        uint8_t params[SLPS_PARAMSBYTES];
        uint8_t seed_p[SEEDBYTES];

        slps_setup(params, seed);
        memcpy(seed_p, seed, SEEDBYTES);
        seed_p[0] ^= 0x11;
        slps_user_key_gen(pkp, skp, params, idp, seed_p);

        /* User-Sign */
        slps_user_sign(user_sig, m, mlen, params, skp, rnd);
        printf("User-Sign: sigma_len = %d (expected %d)\n",
               SLPS_USERSIGBYTES, CTILDEBYTES + L * POLYZ_PACKEDBYTES);

        /* User-Verify */
        ret = slps_user_verify(m, mlen, user_sig, params, pkp);
        if (ret == 0)
            printf("User-Verify: SUCCESS\n");
        else
            printf("User-Verify: FAILURE (ret=%d)\n", ret);
    }

    /*===============================================================
     * Step 4: Principal-Authorize-Agent - 授权代理凭证生成
     *===============================================================*/
    printf("\n========== Step 4: Principal-Authorize-Agent ==========\n");
    {
        uint8_t params[SLPS_PARAMSBYTES];
        uint8_t seed_p[SEEDBYTES];
        uint8_t rnd_p[SEEDBYTES];

        slps_setup(params, seed);
        memcpy(seed_p, seed, SEEDBYTES);
        seed_p[0] ^= 0x11;
        slps_user_key_gen(pkp, skp, params, idp, seed_p);

        /* 授权凭证生成 (Principal 为 Agent 授权) */
        memcpy(rnd_p, rnd, SEEDBYTES);
        rnd_p[0] ^= 0x33;
        slps_principal_authorize_agent(t_idp, params, skp, idp, ida, pka, rnd_p);
        printf("Principal-Authorize-Agent: T_IDp_len = %d (expected %d)\n",
               SLPS_TIDPBYTES, SLPS_TIDP_IDBYTES + SLPS_TIDP_IDABYTES +
               SLPS_CIDBYTES + L * POLYZ_PACKEDBYTES);
    }

    /*===============================================================
     * Step 5: Credential-Verify - 代理凭证验证
     *===============================================================*/
    printf("\n========== Step 5: Credential-Verify ==========\n");
    {
        uint8_t params[SLPS_PARAMSBYTES];
        uint8_t seed_p[SEEDBYTES];
        uint8_t seed_a[SEEDBYTES];
        uint8_t rnd_p[SEEDBYTES];

        slps_setup(params, seed);
        memcpy(seed_p, seed, SEEDBYTES);
        seed_p[0] ^= 0x11;
        slps_user_key_gen(pkp, skp, params, idp, seed_p);
        memcpy(seed_a, seed, SEEDBYTES);
        seed_a[0] ^= 0x22;
        slps_user_key_gen(pka, ska, params, ida, seed_a);

        memcpy(rnd_p, rnd, SEEDBYTES);
        rnd_p[0] ^= 0x33;
        slps_principal_authorize_agent(t_idp, params, skp, idp, ida, pka, rnd_p);

        /* Credential-Verify */
        ret = slps_credential_verify(t_idp, params, pkp, pka, idp, ida);
        if (ret == 0)
            printf("Credential-Verify: SUCCESS\n");
        else
            printf("Credential-Verify: FAILURE (ret=%d)\n", ret);
    }

    /*===============================================================
     * Step 6: Agent-Sign / Agent-Verify - 代理签名验证
     *===============================================================*/
    printf("\n========== Step 6: Agent-Sign / Agent-Verify ==========\n");
    {
        uint8_t params[SLPS_PARAMSBYTES];
        uint8_t seed_p[SEEDBYTES];
        uint8_t seed_a[SEEDBYTES];
        uint8_t rnd_p[SEEDBYTES];
        uint8_t rnd_a[SEEDBYTES];

        slps_setup(params, seed);
        memcpy(seed_p, seed, SEEDBYTES);
        seed_p[0] ^= 0x11;
        slps_user_key_gen(pkp, skp, params, idp, seed_p);
        memcpy(seed_a, seed, SEEDBYTES);
        seed_a[0] ^= 0x22;
        slps_user_key_gen(pka, ska, params, ida, seed_a);

        /* 授权凭证 */
        memcpy(rnd_p, rnd, SEEDBYTES);
        rnd_p[0] ^= 0x33;
        slps_principal_authorize_agent(t_idp, params, skp, idp, ida, pka, rnd_p);

        /* Agent-Sign */
        memcpy(rnd_a, rnd, SEEDBYTES);
        rnd_a[0] ^= 0x44;
        slps_agent_sign(agent_sig, m, mlen, params, t_idp, pkp, ska, rnd_a);
        printf("Agent-Sign: sig_len = %d (expected %d)\n",
               SLPS_SIGBYTES, SLPS_CIDBYTES + SLPS_CIDBYTES +
               L * SCLLS_POLYZ0_PACKEDBYTES + K * SCLLS_HWBYTES_PERPOLY);

        /* Agent-Verify */
        ret = slps_agent_verify(m, mlen, agent_sig, params, pkp, pka, ida, idp);
        if (ret == 0)
            printf("Agent-Verify: SUCCESS\n");
        else
            printf("Agent-Verify: FAILURE (ret=%d)\n", ret);
    }

    /*===============================================================
     * 打印各数据结构大小
     *===============================================================*/
    printf("\n========== Data Structure Sizes ==========\n");
    printf("SLPS_PARAMSBYTES    = %d (rho)\n", SLPS_PARAMSBYTES);
    printf("SLPS_PKIDBYTES     = %d (t vector)\n", SLPS_PKIDBYTES);
    printf("SLPS_SKIDBYTES     = %d (key||tr||s1||s2)\n", SLPS_SKIDBYTES);
    printf("SLPS_TIDPBYTES     = %d (IDp||IDa||cid||z)\n", SLPS_TIDPBYTES);
    printf("SLPS_USERSIGBYTES  = %d (~c||z)\n", SLPS_USERSIGBYTES);
    printf("SLPS_SIGBYTES      = %d (~c_p||~c_a||z_a||hw)\n", SLPS_SIGBYTES);

    printf("\n========== Test Complete ==========\n");
    return 0;
}
