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
#include <windows.h>
#include "params.h"
#include "slps.h"
#include "slps_packing.h"

/* 高精度计时辅助函数 (QueryPerformanceCounter) */
static int64_t get_time_us(void)
{
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (int64_t)(counter.QuadPart * 1000000 / freq.QuadPart);
}

/* 将微秒差值换算为毫秒并打印 */
static void print_time_ms(const char *name, int64_t start_us, int64_t end_us)
{
    printf("%s time: %.3f ms\n", name, (end_us - start_us) / 1000.0);
}

int main(void)
{
    /* 随机种子 */
    uint8_t seed[SEEDBYTES] = {
        0x56, 0xBE, 0xCD, 0xFA, 0x6C, 0x82, 0x7D, 0xD5,
        0xB2, 0xAC, 0xE7, 0x18, 0xAC, 0x8A, 0x71, 0xFD,
        0xB2, 0x25, 0x49, 0xFD, 0xA2, 0xDF, 0xAC, 0xC9,
        0xB0, 0xD4, 0x97, 0xCA, 0x8E, 0xFC, 0x12, 0xCE
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

    /* 计时 */
    int64_t t_start, t_end;

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

    /* 当前安全等级 (由 config.h 的 DILITHIUM_MODE 决定, 需重新编译生效) */
    printf("Security Level: DILITHIUM_MODE = %d (%s)\n", DILITHIUM_MODE, CRYPTO_ALGNAME);

    /* 初始化身份信息 */
    memset(idp, 0x01, SEEDBYTES);
    memset(ida, 0x02, SEEDBYTES);

    /*===============================================================
     * Step 1: Setup - 系统参数生成
     *===============================================================*/
    printf("\n========== Step 1: SLPS Setup ==========\n");
    {
        uint8_t params[SLPS_PARAMSBYTES];
        t_start = get_time_us();
        slps_setup(params, seed);
        t_end = get_time_us();
        printf("params_len = %d (expected %d)\n", SLPS_PARAMSBYTES, SEEDBYTES);
        print_time_ms("Setup", t_start, t_end);
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
        t_start = get_time_us();
        slps_user_key_gen(pkp, skp, params, idp, seed_p);
        t_end = get_time_us();
        printf("Principal:\n");
        printf("  pk_len = %d (expected %d)\n", SLPS_PKIDBYTES, K * SCLLS_POLYT_PACKEDBYTES);
        printf("  sk_len = %d (expected %d)\n", SLPS_SKIDBYTES,
               SEEDBYTES + TRBYTES + L * POLYETA_PACKEDBYTES + K * POLYETA_PACKEDBYTES);
        print_time_ms("  User-Key-Gen (Principal)", t_start, t_end);

        /* Agent 密钥对 */
        memcpy(seed_a, seed, SEEDBYTES);
        seed_a[0] ^= 0x22;  /* 区分 Agent 的种子 */
        t_start = get_time_us();
        slps_user_key_gen(pka, ska, params, ida, seed_a);
        t_end = get_time_us();
        printf("Agent:\n");
        printf("  pk_len = %d (expected %d)\n", SLPS_PKIDBYTES, K * SCLLS_POLYT_PACKEDBYTES);
        printf("  sk_len = %d (expected %d)\n", SLPS_SKIDBYTES,
               SEEDBYTES + TRBYTES + L * POLYETA_PACKEDBYTES + K * POLYETA_PACKEDBYTES);
        print_time_ms("  User-Key-Gen (Agent)", t_start, t_end);
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
        t_start = get_time_us();
        slps_user_sign(user_sig, m, mlen, params, skp, rnd);
        t_end = get_time_us();
        printf("User-Sign: sigma_len = %d (expected %d)\n",
               SLPS_USERSIGBYTES, CTILDEBYTES + L * POLYZ_PACKEDBYTES);
        print_time_ms("User-Sign", t_start, t_end);

        /* User-Verify */
        t_start = get_time_us();
        ret = slps_user_verify(m, mlen, user_sig, params, pkp);
        t_end = get_time_us();
        if (ret == 0)
            printf("User-Verify: SUCCESS\n");
        else
            printf("User-Verify: FAILURE (ret=%d)\n", ret);
        print_time_ms("User-Verify", t_start, t_end);
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
        t_start = get_time_us();
        slps_principal_authorize_agent(t_idp, params, skp, idp, ida, pka, rnd_p);
        t_end = get_time_us();
        printf("Principal-Authorize-Agent: T_IDp_len = %d (expected %d)\n",
               SLPS_TIDPBYTES, SLPS_TIDP_IDBYTES + SLPS_TIDP_IDABYTES +
               SLPS_CIDBYTES + L * POLYZ_PACKEDBYTES);
        print_time_ms("Principal-Authorize-Agent", t_start, t_end);
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
        t_start = get_time_us();
        ret = slps_credential_verify(t_idp, params, pkp, pka, idp, ida);
        t_end = get_time_us();
        if (ret == 0)
            printf("Credential-Verify: SUCCESS\n");
        else
            printf("Credential-Verify: FAILURE (ret=%d)\n", ret);
        print_time_ms("Credential-Verify", t_start, t_end);
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
        t_start = get_time_us();
        slps_agent_sign(agent_sig, m, mlen, params, t_idp, pkp, ska, rnd_a);
        t_end = get_time_us();
        printf("Agent-Sign: sig_len = %d (expected %d)\n",
               SLPS_SIGBYTES, SLPS_CIDBYTES + SLPS_CIDBYTES +
               L * SCLLS_POLYZ0_PACKEDBYTES + K * SCLLS_HWBYTES_PERPOLY);
        print_time_ms("Agent-Sign", t_start, t_end);

        /* Agent-Verify */
        t_start = get_time_us();
        ret = slps_agent_verify(m, mlen, agent_sig, params, pkp, pka, ida, idp);
        t_end = get_time_us();
        if (ret == 0)
            printf("Agent-Verify: SUCCESS\n");
        else
            printf("Agent-Verify: FAILURE (ret=%d)\n", ret);
        print_time_ms("Agent-Verify", t_start, t_end);
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
