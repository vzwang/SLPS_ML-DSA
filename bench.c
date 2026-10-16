/**
 * @file bench.c
 * @brief SLPS 方案基准测试驱动 (拒绝采样筛选 + 平均耗时统计)
 *
 * 用法:
 *   bench scan <start> <count> <rej_thresh> [verbose]
 *       从下标 start 开始连续检测 count 个随机数, 统计每个随机数驱动
 *       完整 SLPS 流程时三个拒绝采样循环的迭代次数, 输出:
 *         F,<idx>,<failmask>                          算法失败的随机数
 *         Q,<idx>,<rej0>,<rej1>,<rej2>,<total>,<fail> 各子算法迭代次数均<=thresh
 *         V,<idx>,<rej0>,<rej1>,<rej2>,<total>,<fail> verbose 模式逐条输出
 *         S,<scanned>,<fail>,<qualified>              汇总
 *
 *   bench time <idxlist_file> <reps>
 *       读取合格随机数下标列表(每行一个), 每个下标运行 reps 次并计时, 输出:
 *         T,<idx>,<avg_total_us>,<avg_rej_total>
 *         A,<runs>,<avg_total_us>,<avg_rej0_us>,<avg_rej1_us>,<avg_rej2_us>
 *
 * 随机数定义: 32 字节主随机数 R (由下标经 shake256 确定性派生);
 *   R 直接作为 Setup 的种子, 其余随机量由 R 经域标签派生,
 *   使得同一个随机数在两个方案/三个安全等级下都表示 "同一个随机数"。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

#include "params.h"
#include "slps.h"
#include "slps_packing.h"
#include "fips202.h"

/* 由 slps.c 导出的拒绝采样计数器 */
extern unsigned long long slps_rej_user_sign;
extern unsigned long long slps_rej_authorize;
extern unsigned long long slps_rej_agent_sign;

/*---------------------------------------------------------------
 * 计时
 *---------------------------------------------------------------*/
static int64_t now_us(void)
{
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (int64_t)(counter.QuadPart * 1000000 / freq.QuadPart);
}

/*---------------------------------------------------------------
 * 随机数派生
 *---------------------------------------------------------------*/
static void master_from_index(uint8_t master[SEEDBYTES], unsigned long long idx)
{
    uint8_t in[8 + 8];
    unsigned int i;
    for (i = 0; i < 8; ++i)
        in[i] = (uint8_t)((idx >> (8 * i)) & 0xFF);
    memcpy(in + 8, "masterRN", 8);
    shake256(master, SEEDBYTES, in, sizeof(in));
}

static void derive(uint8_t out[SEEDBYTES], const uint8_t master[SEEDBYTES], const char *tag)
{
    keccak_state st;
    shake256_init(&st);
    shake256_absorb(&st, master, SEEDBYTES);
    shake256_absorb(&st, (const uint8_t *)tag, (size_t)strlen(tag));
    shake256_finalize(&st);
    shake256_squeeze(out, SEEDBYTES, &st);
}

/*---------------------------------------------------------------
 * 单次运行统计
 *---------------------------------------------------------------*/
typedef struct {
    unsigned int rej[3];        /* UserSign / Authorize / AgentSign 迭代次数 */
    unsigned long long total;   /* 三者之和 */
    int fail;                   /* bit0: UserVerify 失败, bit1: CredentialVerify 失败,
                                 * bit2: AgentVerify 失败 */
    int64_t us[3];              /* 三个采样算法耗时(us) */
    int64_t us_total;           /* 全流程耗时(us) */
} stat_t;

static const uint8_t g_msg[SEEDBYTES] = {
    0xD5, 0xC2, 0x93, 0xCE, 0x6B, 0xDE, 0xD2, 0x1E,
    0x3A, 0xAD, 0x35, 0x61, 0x00, 0xCA, 0x8D, 0x6E,
    0x42, 0xE3, 0x94, 0x50, 0xCB, 0x1C, 0x43, 0x5B,
    0x7D, 0xD8, 0x02, 0xEA, 0x43, 0x74, 0x65, 0x32
};

static void run_once(const uint8_t master[SEEDBYTES], stat_t *st)
{
    uint8_t params[SLPS_PARAMSBYTES];
    uint8_t pkp[SLPS_PKIDBYTES], skp[SLPS_SKIDBYTES];
    uint8_t pka[SLPS_PKIDBYTES], ska[SLPS_SKIDBYTES];
    uint8_t seed_p[SEEDBYTES], seed_a[SEEDBYTES];
    uint8_t rnd[SEEDBYTES], rnd_p[SEEDBYTES], rnd_a[SEEDBYTES];
    uint8_t t_idp[SLPS_TIDPBYTES];
    uint8_t user_sig[SLPS_USERSIGBYTES];
    uint8_t agent_sig[SLPS_SIGBYTES];
    uint8_t idp[SEEDBYTES], ida[SEEDBYTES];
    int r;
    int64_t t0, t1, t2;

    memset(st, 0, sizeof(*st));

    memset(idp, 0x01, SEEDBYTES);
    memset(ida, 0x02, SEEDBYTES);
    derive(seed_p, master, "SLPS.seed_P");
    derive(seed_a, master, "SLPS.seed_A");
    derive(rnd,    master, "SLPS.rnd");
    derive(rnd_p,  master, "SLPS.rnd_P");
    derive(rnd_a,  master, "SLPS.rnd_A");

    /* 复位拒绝采样计数器 */
    slps_rej_user_sign  = 0;
    slps_rej_authorize  = 0;
    slps_rej_agent_sign = 0;

    t0 = now_us();

    slps_setup(params, master);
    slps_user_key_gen(pkp, skp, params, idp, seed_p);
    slps_user_key_gen(pka, ska, params, ida, seed_a);

    /* User-Sign / User-Verify */
    t1 = now_us();
    slps_user_sign(user_sig, g_msg, SEEDBYTES, params, skp, rnd);
    t2 = now_us();
    st->us[0] = t2 - t1;
    r = slps_user_verify(g_msg, SEEDBYTES, user_sig, params, pkp);
    if (r != 0)
        st->fail |= 0x01;

    /* Principal-Authorize-Agent / Credential-Verify */
    t1 = now_us();
    slps_principal_authorize_agent(t_idp, params, skp, idp, ida, pka, rnd_p);
    t2 = now_us();
    st->us[1] = t2 - t1;
    r = slps_credential_verify(t_idp, params, pkp, pka, idp, ida);
    if (r != 0)
        st->fail |= 0x02;

    /* Agent-Sign / Agent-Verify */
    t1 = now_us();
    slps_agent_sign(agent_sig, g_msg, SEEDBYTES, params, t_idp, pkp, ska, rnd_a);
    t2 = now_us();
    st->us[2] = t2 - t1;
    r = slps_agent_verify(g_msg, SEEDBYTES, agent_sig, params, pkp, pka, ida, idp);
    if (r != 0)
        st->fail |= 0x04;

    st->us_total = now_us() - t0;

    st->rej[0] = (unsigned int)slps_rej_user_sign;
    st->rej[1] = (unsigned int)slps_rej_authorize;
    st->rej[2] = (unsigned int)slps_rej_agent_sign;
    st->total  = (unsigned long long)st->rej[0] + st->rej[1] + st->rej[2];
}

/*---------------------------------------------------------------
 * scan 模式
 *---------------------------------------------------------------*/
static int do_scan(unsigned long long start, unsigned long long count,
                   unsigned long long thresh, int verbose)
{
    unsigned long long i;
    unsigned long long scanned = 0, nfail = 0, nqual = 0;
    uint8_t master[SEEDBYTES];
    stat_t st;

    printf("# mode=scan start=%llu count=%llu thresh=%llu level=%d\n",
           start, count, thresh, DILITHIUM_MODE);

    for (i = 0; i < count; ++i) {
        unsigned long long idx = start + i;
        master_from_index(master, idx);
        run_once(master, &st);
        scanned++;
        if (st.fail) {
            nfail++;
            printf("F,%llu,%d\n", idx, st.fail);
            fflush(stdout);
        }
        /* 合格判定: 验证成功(fail==0) 且 每个子算法的拒绝采样迭代次数都 <= thresh */
        if (st.fail == 0 && st.rej[0] <= thresh && st.rej[1] <= thresh && st.rej[2] <= thresh) {
            nqual++;
            printf("Q,%llu,%u,%u,%u,%llu,%d\n",
                   idx, st.rej[0], st.rej[1], st.rej[2], st.total, st.fail);
            fflush(stdout);
        } else if (verbose) {
            printf("V,%llu,%u,%u,%u,%llu,%d\n",
                   idx, st.rej[0], st.rej[1], st.rej[2], st.total, st.fail);
        }
    }

    printf("S,%llu,%llu,%llu\n", scanned, nfail, nqual);
    return 0;
}

/*---------------------------------------------------------------
 * time 模式
 *---------------------------------------------------------------*/
static int do_time(const char *listfile, int reps)
{
    FILE *fp = fopen(listfile, "r");
    unsigned long long idx;
    uint8_t master[SEEDBYTES];
    stat_t st;
    double sum_total = 0.0, sum_rej[3] = {0, 0, 0};
    unsigned long long runs = 0, nfail = 0;
    double sum_rejcnt = 0.0;
    char line[256];

    if (!fp) {
        fprintf(stderr, "cannot open %s\n", listfile);
        return 1;
    }

    printf("# mode=time list=%s reps=%d level=%d\n", listfile, reps, DILITHIUM_MODE);

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        idx = strtoull(line, NULL, 10);
        master_from_index(master, idx);

        {
            double avg_total = 0.0;
            double avg_rej = 0.0;
            int k;
            int64_t acc = 0;
            unsigned long long acc_rej = 0;
            for (k = 0; k < reps; ++k) {
                run_once(master, &st);
                acc += st.us_total;
                acc_rej += st.total;
                sum_total += (double)st.us_total;
                sum_rej[0] += (double)(int64_t)st.us[0];
                sum_rej[1] += (double)(int64_t)st.us[1];
                sum_rej[2] += (double)(int64_t)st.us[2];
                sum_rejcnt += (double)st.total;
                if (st.fail)
                    nfail++;
                runs++;
            }
            avg_total = (double)acc / reps;
            avg_rej = (double)acc_rej / reps;
            printf("T,%llu,%.2f,%.2f\n", idx, avg_total, avg_rej);
            fflush(stdout);
        }
    }
    fclose(fp);

    if (runs == 0) {
        printf("A,0,0,0,0,0\n");
        return 0;
    }

    printf("A,%llu,%.2f,%.2f,%.2f,%.2f,%.3f,%llu\n",
           runs,
           sum_total / runs,
           sum_rej[0] / runs,
           sum_rej[1] / runs,
           sum_rej[2] / runs,
           sum_rejcnt / runs,
           nfail);
    return 0;
}

/*---------------------------------------------------------------
 * main
 *---------------------------------------------------------------*/
int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr,
                "usage:\n"
                "  bench scan <start> <count> <thresh> [verbose]\n"
                "  bench time <idxlist_file> <reps>\n");
        return 2;
    }

    if (strcmp(argv[1], "scan") == 0) {
        unsigned long long start = 0, count = 0, thresh = 5;
        int verbose = 0;
        if (argc >= 5) {
            start  = strtoull(argv[2], NULL, 10);
            count  = strtoull(argv[3], NULL, 10);
            thresh = strtoull(argv[4], NULL, 10);
        }
        if (argc >= 6)
            verbose = atoi(argv[5]);
        return do_scan(start, count, thresh, verbose);
    }

    if (strcmp(argv[1], "time") == 0) {
        int reps = (argc >= 4) ? atoi(argv[3]) : 10;
        return do_time(argv[2], reps);
    }

    fprintf(stderr, "unknown mode: %s\n", argv[1]);
    return 2;
}
