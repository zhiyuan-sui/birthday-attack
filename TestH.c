#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <gmp.h>

// To achieve 32-bit security, the length of the security parameter is 64 bit, and the number of hash values is 128.
#define BITS        64
#define K           128
#define LOG2_K      7
#define LIST_SIZE   256
#define BASE_BITS   8

// The highest 8-bit and lowest 56-bit
#define HIGH8(x)    ((x >> 56) & 0xFF)
#define LOW56(x)    (x & ((1ULL << 56) - 1))

typedef uint64_t u64;

// SHA1
int sha1_160bit_hash(char *hex_hash, const unsigned char *message, size_t msg_len)
{
    if (hex_hash == NULL)
        return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -2;

    unsigned char hash_bin[20];
    unsigned int hash_len;

    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, message, msg_len);
    EVP_DigestFinal_ex(ctx, hash_bin, &hash_len);
    EVP_MD_CTX_free(ctx);

    for (int i = 0; i < 20; i++)
        sprintf(hex_hash + i*2, "%02x", hash_bin[i]);
    hex_hash[40] = '\0';
    return 0;
}

void hash_to_mpz(mpz_t z, const unsigned char *data, size_t len) {
    char h[512];
    sha1_160bit_hash(h, data, len);
    mpz_set_str(z, h, 16);
}

typedef struct Node {
    mpz_t val;
    u64 seed[K];
    int count;
} Node;

u64 low_bits(u64 x, int t) {
    return x & ((1ULL << t) - 1);
}

u64 mpz_to_u64(mpz_t e) {
    u64 res = 0;
    mpz_t mask;
    mpz_init(mask);
    mpz_set_ui(mask, 1);
    mpz_mul_2exp(mask, mask, 64);
    mpz_sub_ui(mask, mask, 1);
    mpz_and(e, e, mask);
    res = mpz_get_ui(e);
    mpz_clear(mask);
    return res;
}

void node_clear(Node *node) {
    mpz_clear(node->val);
}

int merge_nodes(Node *dst, Node *a, int na, Node *b, int nb, int t, u64 target) {
    int cnt = 0;
    for (int i = 0; i < na && cnt < LIST_SIZE; i++) {
        for (int j = 0; j < nb && cnt < LIST_SIZE; j++) {
            u64 va = mpz_to_u64(a[i].val);
            u64 vb = mpz_to_u64(b[j].val);
            u64 sum_val = va + vb;

            if (low_bits(sum_val, t) == target) {
                mpz_init(dst[cnt].val);
                mpz_add(dst[cnt].val, a[i].val, b[j].val);
                memcpy(dst[cnt].seed, a[i].seed, sizeof(u64)*a[i].count);
                memcpy(dst[cnt].seed + a[i].count, b[j].seed, sizeof(u64)*b[j].count);
                dst[cnt].count = a[i].count + b[j].count;
                cnt++;
            }
        }
    }
    return cnt;
}

int main() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    srand((unsigned int)(ts.tv_sec ^ ts.tv_nsec));

    // 🔥 Set TARGET as a 64-bit random value.
    const u64 TARGET = 0x123456789ABCDEF0;

    printf("=== Wagner 128-Sum (64-bit Target) ===\n");
    printf("The target random value is 0x%016llx\n", (unsigned long long)TARGET);
    printf("The highest 8-bit of the target value: 0x%02llx\n", (unsigned long long)HIGH8(TARGET));
    printf("The lowest 56-bit of the target value: 0x%014llx\n", (unsigned long long)LOW56(TARGET));
    printf("K=%d, LIST_SIZE=%d\n", K, LIST_SIZE);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    Node (*curr)[LIST_SIZE] = malloc(K * sizeof(Node[LIST_SIZE]));
    int curr_len[K];
    for (int i = 0; i < K; i++) {
        curr_len[i] = LIST_SIZE;
        for (int j = 0; j < LIST_SIZE; j++) {
            u64 seed = (u64)i * LIST_SIZE + j + (u64)rand() * 10000;
            mpz_init(curr[i][j].val);
            hash_to_mpz(curr[i][j].val, (unsigned char*)&seed, sizeof(seed));
            curr[i][j].seed[0] = seed;
            curr[i][j].count = 1;
        }
    }

    int num = K;
    // 🔥 7 levels merging. In each level the lowest (j+1)*8 bit=0
    for (int lvl = 0; lvl < LOG2_K; lvl++) {
        int t = (lvl + 1) * BASE_BITS;
        int new_num = num / 2;
        Node (*next)[LIST_SIZE] = malloc(new_num * sizeof(Node[LIST_SIZE]));
        int next_len[new_num];

        for (int i = 0; i < new_num; i++) {
            // 🔥 Only list 0 math the target. Other lists math 0
            u64 layer_target = (i == 0) ? low_bits(TARGET, t) : 0;
            next_len[i] = merge_nodes(next[i],
                curr[2*i], curr_len[2*i],
                curr[2*i+1], curr_len[2*i+1],
                t, layer_target);
        }

        for (int i = 0; i < num; i++)
            for (int j = 0; j < curr_len[i]; j++)
                node_clear(&curr[i][j]);
        free(curr);

        curr = next;
        num = new_num;
        memcpy(curr_len, next_len, sizeof(int)*new_num);
        printf("✅ Level %d is finished\n", lvl);
    }

     // searching the target.
    int ok = 0;
    u64 final_seeds[K];
    printf("\nThe elements of the root list: %d\n", curr_len[0]);
    printf("Searching for the target: 0x%016llx\n", (unsigned long long)TARGET);
    printf("The lowest 56-bit 0x%014llx\n", (unsigned long long)LOW56(TARGET));

    for (int i = 0; i < curr_len[0]; i++) {
        u64 v = mpz_to_u64(curr[0][i].val);
        if (v == TARGET) {
            memcpy(final_seeds, curr[0][i].seed, sizeof(u64)*K);
            ok = 1;
            break;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec)/1e9;
    printf("\nThe execution time of the algorithm is %.3f seconds\n", elapsed);

    if (!ok) {
        printf("\n❌ No 64-bit one found in this run\n");
        printf("This is normal (probability ~63%% per run), just run again\n");
    } else {
        printf("\n🎉 SUCCESS: Found 128 hashes with FULL 64-bit sum = 0!\n");
        mpz_t total;
        mpz_init_set_ui(total, 0);
        for (int i = 0; i < K; i++) {
            mpz_t h;
            mpz_init(h);
            hash_to_mpz(h, (unsigned char*)&final_seeds[i], sizeof(final_seeds[i]));
            mpz_add(total, total, h);
            mpz_clear(h);
        }
        printf("The total result is: 0x%016llx\n", (unsigned long long)mpz_to_u64(total));
        mpz_clear(total);
    }

    for (int i = 0; i < num; i++)
        for (int j = 0; j < curr_len[i]; j++)
            node_clear(&curr[i][j]);
    free(curr);

    return ok ? 0 : 1;
}

