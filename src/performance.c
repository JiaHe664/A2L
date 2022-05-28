#include "relic/relic.h"
#include "pari/pari.h"
#include "../include/types.h"
#include "../include/utils.h"
#include "../include/performance.h"
#include<stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOOP_TIMES 100;

int RP_setUp(RP_t rp_params)
{
	int result_status = RLC_OK;

    if (generate_cl_params(rp_params->gp) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

	RLC_TRY {
	    // Compute CL encryption secret/public key pair for the tumbler.
		rp_params->td->sk = randomi(rp_params->gp->bound);
        printf("\nSize of sk : %d B\n",sizeof(*(rp_params->td->sk)));
        printf("\nSize of GEN : %d B\n",sizeof(*(rp_params->td->sk)));
		rp_params->pk->pk = nupow(rp_params->gp->g_q, rp_params->td->sk, NULL);
        printf("\n####################### cl_sk #######################\n");
        printf(GENtostr(rp_params->td->sk));
        printf("\n####################### cl_sk #######################\n");
        printf("\n####################### cl_pk #######################\n");
        printf(GENtostr(rp_params->pk->pk));
        printf("\n####################### cl_pk #######################\n");        
        // printf("\nRP params init sucessfully!\n");
    } RLC_CATCH_ANY {
		result_status = RLC_ERR;
	} RLC_FINALLY {
	}

	return result_status;

}

int RP_gen(puzzle_t puzzle,const RP_t rp_params){
    if (puzzle == NULL) {
        RLC_THROW(ERR_NO_VALID);
    }

    int result_status = RLC_OK;

    bn_t q,alpha;
    bn_null(q);
    bn_null(alpha);
    RLC_TRY {
        bn_new(q);
        bn_new(alpha);

        ec_curve_get_ord(q);
        bn_rand_mod(alpha, q);      // 为alpha随机赋值
        ec_mul_gen(puzzle->g_to_the_alpha, alpha);      // 计算g^alpha，即A

        const unsigned alpha_str_len = bn_size_str(alpha, 10);
        char alpha_str[alpha_str_len];
        bn_write_str(alpha_str, alpha_str_len, alpha, 10);
        // printf("\n####################### g_to_the_alpha #######################\n");
        // printf(puzzle->g_to_the_alpha);
        // printf("\n####################### plain of alpha #######################\n");
        // printf("%s",alpha_str);
        GEN plain_alpha = strtoi(alpha_str);
        if (cl_enc(puzzle->ctx_alpha, plain_alpha, rp_params->pk, rp_params->gp) != RLC_OK) {       // 使用cl同态加密方案加密alpha
        RLC_THROW(ERR_CAUGHT);
        }
        // printf("\n####################### cipher of alpha #######################\n");
        // printf("\n####################### c1 #######################\n");
        // printf(GENtostr(puzzle->ctx_alpha->c1));
        // printf("\n####################### c2 #######################\n");
        // printf(GENtostr(puzzle->ctx_alpha->c2));
        // printf("\nPuzzle generates sucessfully!\n");
    } RLC_CATCH_ANY {
        result_status = RLC_ERR;
    } RLC_FINALLY {
        bn_free(q);
        bn_free(alpha);
    }

    return result_status;

}

int RP_solve(const RP_t rp_params,const puzzle_t puzzle){
    if (rp_params == NULL || puzzle == NULL) {
        RLC_THROW(ERR_NO_VALID);
    }

    int result_status = RLC_OK;

    bn_t alpha;
    bn_null(alpha);

    RLC_TRY {
        bn_new(alpha);

        // Decrypt the ciphertext.
        GEN _alpha;
        if (cl_dec(&_alpha, puzzle->ctx_alpha, rp_params->td, rp_params->gp) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
        }
        bn_read_str(alpha, GENtostr(_alpha), strlen(GENtostr(_alpha)), 10);

        const unsigned alpha_str_len = bn_size_str(alpha, 10);
        char alpha_str[alpha_str_len];
        bn_write_str(alpha_str, alpha_str_len, alpha, 10);
        // printf("\n####################### plain of alpha #######################\n");
        // printf("%s",alpha_str);
        // printf("\nPuzzle solves sucessfully!\n");
    } RLC_CATCH_ANY {
        result_status = RLC_ERR;
    } RLC_FINALLY {
        bn_free(alpha);
    }

    return result_status;
}

int RP_rand(puzzle_t puzzle_rand,const RP_pp_t rp_pp,const puzzle_t puzzle){
    if (rp_pp == NULL || puzzle == NULL) {
        RLC_THROW(ERR_NO_VALID);
    }
    
    int result_status = RLC_OK;

    bn_t q,beta;
    printf("\n Size of beta: %d B\n",sizeof(*beta));

    bn_null(q);
    bn_null(beta);

    RLC_TRY {
        bn_new(q);
        bn_new(beta);
        ec_curve_get_ord(q);

        // Randomize the promise challenge.
        GEN beta_prime = randomi(rp_pp->gp->bound);
        printf("\n--------Size of gp : %d B\n",sizeof(cl_params_st));
        bn_read_str(beta, GENtostr(beta_prime), strlen(GENtostr(beta_prime)), 10);
        bn_mod(beta, beta, q);

        // 计算g^(alpha*beta)，即A'
        ec_mul(puzzle_rand->g_to_the_alpha, puzzle->g_to_the_alpha, beta);      
        ec_norm(puzzle_rand->g_to_the_alpha, puzzle_rand->g_to_the_alpha);      

        // Homomorphically randomize the challenge ciphertext.
        const unsigned beta_str_len = bn_size_str(beta, 10);
        char beta_str[beta_str_len];
        bn_write_str(beta_str, beta_str_len, beta, 10);

        GEN plain_beta = strtoi(beta_str);
        puzzle_rand->ctx_alpha->c1 = nupow(puzzle->ctx_alpha->c1, plain_beta, NULL);
        puzzle_rand->ctx_alpha->c2 = nupow(puzzle->ctx_alpha->c2, plain_beta, NULL);
        // printf("\n####################### g_to_the_alpha_times_beta #######################\n");
        // printf(puzzle_rand->g_to_the_alpha);
        // printf("\n####################### plain of beta #######################\n");
        // printf("%s",beta_str);
        // printf("\n####################### cipher of alpha_times_beta #######################\n");
        // printf("\n####################### c1 #######################\n");
        // printf(GENtostr(puzzle_rand->ctx_alpha->c1));
        // printf("\n####################### c2 #######################\n");
        // printf(GENtostr(puzzle_rand->ctx_alpha->c2));
        // printf("\nPuzzle randoms sucessfully!\n");
    } RLC_CATCH_ANY {
        result_status = RLC_ERR;
    } RLC_FINALLY {
        bn_free(beta);
        bn_free(q);
    }

    return result_status;
}

int main(void){
    clock_t start_time;
    clock_t finish_time;
    float total_time=0,run_time;
    init();
    int result_status = RLC_OK;
    RP_t rp_params;
    RP_pp_t rp_pp;
    puzzle_t puzzle,puzzle_rand;
    RP_null(rp_params);
    RP_pp_null(rp_pp);
    puzzle_null(puzzle);
    puzzle_null(puzzle_rand);    
    RLC_TRY {
        RP_new(rp_params);
        RP_pp_new(rp_pp);
        RP_setUp(rp_params);
        // for(int i=1;i<=LOOP_TIMES){
        //     start_time=clock();
        //     RP_setUp(rp_params);
        //     finish_time=clock();
        //     total_time+=(float)(finish_time-start_time)/CLOCKS_PER_SEC;
        //     i++;
        // }
        // run_time=total_time/LOOP_TIMES;
        // printf("\n####################### runtime of RP_setUp #######################\n");
        // printf("%f s",run_time);
        rp_pp->gp=rp_params->gp;
        rp_pp->pk=rp_params->pk;
        puzzle_new(puzzle);
        RP_gen(puzzle,rp_params);
        // total_time=0;
        // for(int i=1;i<=LOOP_TIMES){
        //     start_time=clock();
        //     RP_gen(puzzle,rp_params);
        //     finish_time=clock();
        //     total_time+=(float)(finish_time-start_time)/CLOCKS_PER_SEC;
        //     i++;
        // }
        // run_time=total_time/LOOP_TIMES;
        // printf("\n####################### runtime of RP_gen #######################\n");
        // printf("%f s",run_time);
        // total_time=0;
        RP_solve(rp_params,puzzle);
        // for(int i=1;i<=LOOP_TIMES){
        //     start_time=clock();
        //     RP_solve(rp_params,puzzle);
        //     finish_time=clock();
        //     total_time+=(float)(finish_time-start_time)/CLOCKS_PER_SEC;
        //     i++;
        // }
        // run_time=total_time/LOOP_TIMES;
        // printf("\n####################### runtime of RP_solve #######################\n");
        // printf("%f s",run_time); 
        puzzle_new(puzzle_rand);   
        RP_rand(puzzle_rand,rp_pp,puzzle);
        // total_time=0;
        // for(int i=1;i<=LOOP_TIMES){
        //     start_time=clock();
        //     RP_rand(puzzle_rand,rp_pp,puzzle);
        //     finish_time=clock();
        //     total_time+=(float)(finish_time-start_time)/CLOCKS_PER_SEC;
        //     i++;
        // }
        // run_time=total_time/LOOP_TIMES;
        // printf("\n####################### runtime of RP_rand #######################\n");
        // printf("%f s\n",run_time); 
        // printf("program exit\n");
    } RLC_CATCH_ANY {
        result_status = RLC_ERR;
    } RLC_FINALLY {
        RP_free(rp_params);
        RP_pp_free(rp_pp);
        puzzle_free(puzzle);
        puzzle_free(puzzle_rand);
    }
    clean();
    return result_status;
}