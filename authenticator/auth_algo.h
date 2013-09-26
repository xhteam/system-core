#ifndef _AUTH_ALGO_H
#define _AUTH_ALGO_H

#if defined(__cplusplus)
extern "C" {
#endif


struct auth_algorithm;
typedef struct auth_algorithm* auth_algorithm_t;

int auth_algo_init(auth_algorithm_t* algo);
int auth_algo_challenge(auth_algorithm_t algo,uint64_t romid);
int auth_algo_dispose(auth_algorithm_t algo);

#if defined(__cplusplus)
}
#endif

#endif

