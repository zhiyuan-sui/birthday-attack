#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <gmp.h>

// 🔥 To achieve 32-bit security, the length of the security parameter is 64 bit, and the number of hash values is 128.
#define BITS        64
#define K           128
#define LOG2_K      7
#define LIST_SIZE   256    // 2^8，
#define BASE_BITS   8      // 8*8=64

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

    if (EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -3;
    }

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

// Node with 128 seeds
typedef struct Node {
    mpz_t val;
    u64 seed[K];
    int count;
} Node;

u64 low_bits(u64 x, int t) {
    return x & ((1ULL << t) - 1);
}

// 64 bit value
u64 mpz_to_u64(mpz_t e) {
    u64 res = 0;
    if (mpz_sizeinbase(e, 2) > 0) {
        mpz_t mask;
        mpz_init(mask);
        mpz_set_ui(mask, 1);
        mpz_mul_2exp(mask, mask, 64);
        mpz_sub_ui(mask, mask, 1);
        mpz_and(e, e, mask);
        res = mpz_get_ui(e);
        mpz_clear(mask);
    }
    return res;
}

void node_clear(Node *node) {
    mpz_clear(node->val);
}

// 🔥 Merging：(j+1)*8bit=0 in the jth level
int merge_nodes(Node *dst, Node *a, int na, Node *b, int nb, int t, u64 target) {
    int cnt = 0;
    for (int i = 0; i < na && cnt < LIST_SIZE; i++) {
        for (int j = 0; j < nb && cnt < LIST_SIZE; j++) {
            u64 va = mpz_to_u64(a[i].val);
            u64 vb = mpz_to_u64(b[j].val);
            u64 sum_val = va + vb;

            // 🔥 the lowest t bit=0
            if (low_bits(sum_val, t) == target) {
                mpz_init(dst[cnt].val);
                mpz_add(dst[cnt].val, a[i].val, b[j].val);

                // Merging seeds
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

    const u64 TARGET = 0;
    printf("Original Wagner 128-sum = 0 (64-bit strict)\n");
    printf("Parameters: K=%d, LIST_SIZE=%d, BASE_BITS=%d\n", K, LIST_SIZE, BASE_BITS);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    // Initalize 128 lists
    Node (*curr)[LIST_SIZE] = malloc(K * sizeof(Node[LIST_SIZE]));
    if (!curr) {
        printf("❌ Malloc failed\n");
        return 1;
    }

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
    // 🔥 7 level merging. In each level the lowest (j+1)*8 bit=0
    for (int lvl = 0; lvl < LOG2_K; lvl++) {
        int t = (lvl + 1) * BASE_BITS; // the 0th level matches 8 bit，=the 1st level matches 16 bit...the 6 level matches 56 bit
        int new_num = num / 2;
        Node (*next)[LIST_SIZE] = malloc(new_num * sizeof(Node[LIST_SIZE]));
        if (!next) {
            printf("❌ Malloc failed at level %d\n", lvl);
            goto cleanup;
        }

        int next_len[new_num];
        printf("\n=== Level %d: matching low %d bits ===\n", lvl, t);
        for (int i = 0; i < new_num; i++) {
            next_len[i] = merge_nodes(next[i],
                curr[2*i], curr_len[2*i],
                curr[2*i+1], curr_len[2*i+1],
                t, TARGET);

            printf("Merged %d+%d → %d matches\n", 
                curr_len[2*i], curr_len[2*i+1], next_len[i]);

            if (!next_len[i]) {
                printf("❌ No matches found at level %d\n", lvl);
                for (int k = 0; k < i; k++)
                    for (int j = 0; j < next_len[k]; j++)
                        node_clear(&next[k][j]);
                free(next);
                goto cleanup;
            }
        }

        // free the last level
        for (int i = 0; i < num; i++)
            for (int j = 0; j < curr_len[i]; j++)
                node_clear(&curr[i][j]);
        free(curr);

        curr = next;
        num = new_num;
        memcpy(curr_len, next_len, sizeof(int)*new_num);
    }

    // 🔥 Searching 256 elements in the root list for a 64-bit element, which=0.
    int ok = 0;
    u64 final_seeds[K];
    printf("\n=== Searching root list for 64-bit zero ===\n");
    printf("Root list size: %d elements\n", curr_len[0]);
    
    for (int i = 0; i < curr_len[0]; i++) {
        u64 v = mpz_to_u64(curr[0][i].val);
        printf("  Candidate %d: 0x%016lx\n", i, v);
        
        if (v == TARGET) { // 64 bit=0
            memcpy(final_seeds, curr[0][i].seed, sizeof(u64)*K);
            ok = 1;
            break;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec)/1e9;
    printf("\n✅ Total execution time: %.3f seconds\n", elapsed);

    if (!ok) {
        printf("\n❌ No 64-bit zero found in this run\n");
        printf("This is normal (probability ~63%% per run), just run again\n");

    } else {
        printf("\n🎉 SUCCESS: Found 128 hashes with FULL 64-bit sum = 0!\n");

        // Checking
        mpz_t total;
        mpz_init_set_ui(total, 0);
        mpz_t hlist[K];
        for (int i = 0; i < K; i++)
            mpz_init(hlist[i]);

        printf("\n=== 128 Original Seeds ===\n");
        for (int i = 0; i < K; i++) {
            printf("%lu ", final_seeds[i]);
            hash_to_mpz(hlist[i], (unsigned char*)&final_seeds[i], sizeof(final_seeds[i]));
            mpz_add(total, total, hlist[i]);
        }
        printf("\n");

        u64 sum64 = mpz_to_u64(total);
        printf("\n=== Final Verification ===\n");
        printf("Full 64-bit sum: 0x%016lx\n", sum64); // Output the result if it is success.
        printf("Full sum (hex): ");
        mpz_out_str(stdout, 16, total);
        printf("\n");

        for (int i = 0; i < K; i++)
            mpz_clear(hlist[i]);
        mpz_clear(total);
    }

cleanup:
    // clear the nodes
    for (int i = 0; i < num; i++)
        for (int j = 0; j < curr_len[i]; j++)
            node_clear(&curr[i][j]);
    free(curr);

    return ok ? 0 : 1;
}

