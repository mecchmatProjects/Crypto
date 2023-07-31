#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include "util.h"

#include "gmpecc.h"
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"


//mel.exe -p 0358ac33391b50608364883e762f290a50d9fd516ae60c6b276194ff2c1b3ec038 -s -n 300 -r 1:F0000
//#include "pubkeyslist1.h"
#include "hash_pk.h"
#include "hash_pk2.h"


const char *version = "v2.3";
const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";


const char *formats[3] = {"publickey","rmd160","address"};
const char *looks[2] = {"compress","uncompress"};
//const char *op[2] = {"add","sub"};


//200000000000000000000000000000000...3ffffffffffffffffffffffffffffffff

//#define MIN_DOM "200000000000000000000000000000000"
//#define MAX_DOM "3ffffffffffffffffffffffffffffffff"
//#define MIN_DOM "000000000000000000000000000100000"
//#define MAX_DOM "000000000000000000000000000ffffff"
//                   599999999999999999999999999a9
//                   60f4d11574f5deee49961d9609ac6

#define MIN_DOM "000000000000000000000000000001"
#define MAX_DOM "0000000000000000000000ffffffff"


//size_t SIZE_PK =  sizeof(RANGE_PK)/sizeof(RANGE_PK[0]);// 0xffff;// 0xffffffff;

size_t SIZE_HASH_PK =  sizeof(HASHES_PK)/sizeof(HASHES_PK[0]);//

int pstrcmp( const void* a, const void* b){
  return strcmp( *(const char**)a, *(const char**)b );
}

void sort_str_array(char* range_pk[], int size_array){
   qsort(range_pk, size_array, sizeof(range_pk[0]), pstrcmp);
}

unsigned RSHash(char* str)
{
    unsigned b      = 378551;
    unsigned a      = 63689;
    unsigned hash   = 0;
    unsigned H_SIZE = 0x7FFFFFF;

    for(size_t i = 0; i < strlen(str); i++)
    {
        unsigned val = (str[i]-'0');
        if (val>10){
            val = str[i] - 'a' + 10;
        }
        hash = (hash * a + val) % H_SIZE;
        a    = (a * b) % H_SIZE;
    }

    return hash;
 }

 int Hash2(char* s){

    long long hash_res = 0;
    long long H_SIZE = 0x3FFFFFF;

    int p = 31;
    for(int i=0; i<strlen(s);i++){
        int val = (s[i]-'0');
        if ((val>10) || (val<0)){
            val = s[i] - 'a' + 10;
        }
        hash_res *= p;
        hash_res %= H_SIZE;
        hash_res += val;
        hash_res %= H_SIZE;
        //fprintf(stderr,"r=%u\n",hash_res);
    }
    return (int)hash_res;
 }

  int Hash3(char* s){

    long long hash_res = 0;
    long long H_SIZE = 0x3FFFFFF;

    int p = 37;
    for(int i=0; i<strlen(s);i++){
        int val = (s[i]-'0');
        if ((val>10) || (val<0)){
            val = s[i] - 'a' + 10;
        }
        hash_res *= p;
        hash_res %= H_SIZE;
        hash_res += val;
        hash_res %= H_SIZE;
        //fprintf(stderr,"r=%u\n",hash_res);
    }
    return (int)hash_res;
 }

void showhelp();
void set_format(char *param);
void set_look(char *param);
void set_bit(char *param);
void set_publickey(char *param);
void set_range(char *param);
void generate_straddress(struct Point *publickey,bool compress,char *dst);
void generate_strrmd160(struct Point *publickey,bool compress,char *dst);
void generate_strpublickey(struct Point *publickey,bool compress,char *dst);
double_t calc_perc(uint64_t x, uint64_t max);

char *str_output = NULL;

char str_logout[140];


char str_publickey[131];
char str_rmd160[41];
char str_address[41];

struct Point target_publickey,base_publickey,sum_publickey,negated_publickey,dst_publickey;

int FLAG_RANGE = 0;
int FLAG_BIT = 0;
int FLAG_RANDOM = 0;
int FLAG_PUBLIC = 0;
int FLAG_FORMART = 0;
int FLAG_HIDECOMMENT = 0;
int FLAG_XPOINTONLY = 0;
int FLAG_LOOK = 0;
int FLAG_ADD = 0;
int FLAG_SUB = 0;
int FLAG_MODE = 0;
int FLAG_N;
uint64_t N = 0,M;

mpz_t min_range,max_range,diff,TWO,base_key,sum_key,dst_key;
gmp_randstate_t state;

void Point_Doubling(struct Point *P, struct Point *R)	{

   	//mp_snprintf(str_logout,131,"04%0.64Zx ; %0.64Zx",P->x,P->y);
	//fprintf(stderr,"\n Doubling P: %s \n",str_logout);

	mpz_t slope, temp;
	mpz_init(temp);
	mpz_init(slope);
	if(mpz_cmp_ui(P->y, 0) != 0) {
		mpz_mul_ui(temp, P->y, 2);
		mpz_invert(temp, temp, EC.p);
		mpz_mul(slope, P->x, P->x);
		mpz_mul_ui(slope, slope, 3);
		mpz_mul(slope, slope, temp);
		mpz_mod(slope, slope, EC.p);
		mpz_mul(R->x, slope, slope);
		mpz_sub(R->x, R->x, P->x);
		mpz_sub(R->x, R->x, P->x);
		mpz_mod(R->x, R->x, EC.p);
		mpz_sub(temp, P->x, R->x);
		mpz_mul(R->y, slope, temp);
		mpz_sub(R->y, R->y, P->y);
		mpz_mod(R->y, R->y, EC.p);
	} else {
		mpz_set_ui(R->x, 0);
		mpz_set_ui(R->y, 0);
	}
	mpz_clear(temp);
	mpz_clear(slope);

	//gmp_snprintf(str_logout,131,"04%0.64Zx ; %0.64Zx",R->x,R->y);
	//fprintf(stderr,"\nR: %s \n",str_logout);
}

void Point_Addition(struct Point *P, struct Point *Q, struct Point *R)	{
	mpz_t PA_temp,PA_slope;
	mpz_init(PA_temp);
	mpz_init(PA_slope);

	/*gmp_snprintf(str_logout,135,"04%0.64Zx ; %0.64Zx",P->x,P->y);
	fprintf(stderr,"\nP: %s \n",str_logout);

	gmp_snprintf(str_logout,135,"04%0.64Zx ; %0.64Zx",Q->x,Q->y);
	fprintf(stderr,"Q: %s \n",str_logout);*/

	if(mpz_cmp_ui(P->x, 0) == 0 && mpz_cmp_ui(P->y, 0) == 0) {
		mpz_set(R->x, Q->x);
		mpz_set(R->y, Q->y);
	}
	else	{
		if(mpz_cmp_ui(Q->x, 0) == 0 && mpz_cmp_ui(Q->y, 0) == 0) {
			mpz_set(R->x, P->x);
			mpz_set(R->y, P->y);
		}
		else	{
			if(mpz_cmp_ui(Q->y, 0) != 0) {
				mpz_sub(PA_temp, EC.p, Q->y);
				mpz_mod(PA_temp, PA_temp, EC.p);
			}
			else	{
				mpz_set_ui(PA_temp, 0);
			}
			if(mpz_cmp(P->y, PA_temp) == 0 && mpz_cmp(P->x, Q->x) == 0) {
				mpz_set_ui(R->x, 0);
				mpz_set_ui(R->y, 0);
			}
			else	{
				if(mpz_cmp(P->x, Q->x) == 0 && mpz_cmp(P->y, Q->y) == 0)	{
					Point_Doubling(P, R);
				}
				else {
					mpz_set_ui(PA_slope, 0);
					mpz_sub(PA_temp, P->x, Q->x);	//dx = B.x - A.x
					mpz_mod(PA_temp, PA_temp, EC.p);		///dx = dx % p
					mpz_invert(PA_temp, PA_temp, EC.p);	//gmpy2.invert(dx, p) % p
					mpz_sub(PA_slope, P->y, Q->y);
					mpz_mul(PA_slope, PA_slope, PA_temp);
					mpz_mod(PA_slope, PA_slope, EC.p);
					mpz_mul(R->x, PA_slope, PA_slope);	//c*c
					mpz_sub(R->x, R->x, P->x);	//	c*c - A.x
					mpz_sub(R->x, R->x, Q->x);	//(c*c - A.x) -	B.x
					mpz_mod(R->x, R->x, EC.p);	// Rx % p
					mpz_sub(PA_temp, P->x, R->x);
					mpz_mul(R->y, PA_slope, PA_temp);
					mpz_sub(R->y, R->y, P->y);
					mpz_mod(R->y, R->y, EC.p);
				}
			}
		}
	}
	mpz_clear(PA_temp);
	mpz_clear(PA_slope);

    //gmp_snprintf(str_logout,135,"04%0.64Zx ; %0.64Zx",R->x,R->y);
	//fprintf(stderr,"R: %s \n\n",str_logout);

}

void Scalar_Multiplication(struct Point P, struct Point *R, mpz_t m)	{
	struct Point SM_T,SM_Q;
	int no_of_bits, i;
	no_of_bits = mpz_sizeinbase(m, 2);
	mpz_init_set_ui(SM_Q.x,0);
	mpz_init_set_ui(SM_Q.y,0);
	mpz_init_set_ui(SM_T.x,0);
	mpz_init_set_ui(SM_T.y,0);
	mpz_set_ui(R->x, 0);
	mpz_set_ui(R->y, 0);
	if(mpz_cmp_ui(m, 0) != 0)	{
		mpz_set(SM_Q.x, P.x);
		mpz_set(SM_Q.y, P.y);
		for(i = 0; i < no_of_bits; i++) {
			if(mpz_tstbit(m, i))	{
				mpz_set(SM_T.x, R->x);
				mpz_set(SM_T.y, R->y);
				mpz_set(SM_Q.x,DoublingG[i].x);
				mpz_set(SM_Q.y,DoublingG[i].y);
				Point_Addition(&SM_T, &SM_Q, R);
			}
		}
	}
	mpz_clear(SM_T.x);
	mpz_clear(SM_T.y);
	mpz_clear(SM_Q.x);
	mpz_clear(SM_Q.y);
}

void Point_Negation(struct Point *A, struct Point *S)	{

	mpz_sub(S->y, EC.p, A->y);
	mpz_set(S->x, A->x);

}

// return 0 if A>B else 1
int Compare_Points(struct Point *A, struct Point *B){

    struct Point C, D;
    fprintf(stderr,"\n\n\nCompare\n");

    gmp_snprintf(str_logout,135,"04%0.64Zx ; %0.64Zx",A->x,A->y);
	fprintf(stderr,"A: %s \n\n",str_logout);
	gmp_snprintf(str_logout,135,"04%0.64Zx ; %0.64Zx",B->x,B->y);
	fprintf(stderr,"B: %s \n\n",str_logout);

    int res_cmp = mpz_tstbit(A->y,0);
    mpz_init(C.x);
	mpz_init(C.y);
	mpz_init(D.x);
	mpz_init(D.y);


    Point_Negation(B,&C);
    gmp_snprintf(str_logout,135,"04%0.64Zx ; %0.64Zx",C.x,C.y);
	fprintf(stderr,"Negate: %s \n\n",str_logout);
    Point_Addition(A,&C,&D);
    gmp_snprintf(str_logout,135,"04%0.64Zx ; %0.64Zx",D.x,D.y);
	fprintf(stderr,"Subtra: %s \n\n",str_logout);
    fprintf(stderr,"A.y=%d ",res_cmp);
    res_cmp ^= mpz_tstbit(D.y,0);
    mpz_clear(C.x);
	mpz_clear(C.y);
	mpz_clear(D.x);
	mpz_clear(D.y);
    fprintf(stderr,"D=%d\n",mpz_tstbit(D.y,0));
    return res_cmp;
}


//-1 if pub_key is not present in array,
// index>0 - index of pub_key in array
int look_up_pk(char* pub_key, char* range_pk[], size_t size_array){

    int i = 0;
    int j = size_array-1;
    for(;i<=j;i++,j--){

        if(strcmp(range_pk[i],pub_key)==0){
            return i;
        }
        if(strcmp(range_pk[j],pub_key)==0){
            return j;
        }
    }
    return -1;
}


//-1 if pub_key is not present in array,
// index>0 - index of pub_key in array
int look_up_pk_binary(char* pub_key, char* sorted_pk[], size_t size_array){

 size_t low=0;
 size_t high=size_array-1;
 size_t mid;
 while(low<=high) {

    mid=(low+high)>>1;
    int res = strcmp(pub_key,sorted_pk[mid]);
    if (res==0){
        return mid;
    }
    else if(res>0) {
        low = mid + 1;
    }
    else{
        high = mid - 1;
    }
 }

    return -1;
}



/*
	Precalculate G Doublings for Scalar_Multiplication
*/
void init_doublingG(struct Point *P)	{
	int i = 0;
	mpz_init(DoublingG[i].x);
	mpz_init(DoublingG[i].y);
	mpz_set(DoublingG[i].x,P->x);
	mpz_set(DoublingG[i].y,P->y);
	i = 1;
	while(i < 256){
		mpz_init(DoublingG[i].x);
		mpz_init(DoublingG[i].y);
		Point_Doubling(&DoublingG[i-1] ,&DoublingG[i]);
		mpz_mod(DoublingG[i].x, DoublingG[i].x, EC.p);
		mpz_mod(DoublingG[i].y, DoublingG[i].y, EC.p);
		i++;
	}
}

int main(int argc, char **argv)  {
	FILE *OUTPUT;
	char c;
	uint64_t i = 0;
	mpz_init_set_str(EC.p, EC_constant_P, 16);
	mpz_init_set_str(EC.n, EC_constant_N, 16);
	mpz_init_set_str(G.x , EC_constant_Gx, 16);
	mpz_init_set_str(G.y , EC_constant_Gy, 16);
	init_doublingG(&G);

	mpz_init(min_range);
	mpz_init(max_range);
	mpz_init(diff);
	mpz_init_set_ui(TWO,2);
	mpz_init(target_publickey.x);
	mpz_init_set_ui(target_publickey.y,0);

    //fprintf(stderr,"N=%zu\n",SIZE_PK);
     unsigned hv = Hash2("024e43a408f189bf803c60bf993f6604ecd6211c77e27ded87764111dc5d5127fb");
    fprintf(stderr,"HW=%u\n",hv);

	while ((c = getopt(argc, argv, "hvaszxRb:n:o:p:r:f:l:")) != -1) {


		switch(c) {
			case 'x':
				FLAG_HIDECOMMENT = 1;
			break;
			case 'z':
				FLAG_XPOINTONLY = 1;
			break;
			case 'a':
				FLAG_ADD = 1;
			break;
			case 's':
				FLAG_SUB = 1;
			break;
			case 'h':
				showhelp();
				exit(0);
			break;
			case 'b':
				set_bit((char *)optarg);
				FLAG_BIT = 1;
			break;
			case 'n':
				N = strtol((char *)optarg,NULL,10);
				if(N<= 0)	{
					fprintf(stderr,"[E] invalid bit N number %s\n",optarg);
					exit(0);
				}
				FLAG_N = 1;
			break;
			case 'o':
				str_output = (char *)optarg;
			break;
			case 'p':
				set_publickey((char *)optarg);
				FLAG_PUBLIC = 1;
			break;
			case 'r':
				set_range((char *)optarg);
				FLAG_RANGE = 1;
			break;
			case 'R':
				FLAG_RANDOM = 1;
			break;
			case 'v':
				printf("Version %s\n",version);
				exit(0);
			break;
			case 'l':
				set_look((char *)optarg);
			break;

			case 'f':
				set_format((char *)optarg);
			break;

		}
	}


    //fprintf(stderr,"\n start working\n");

	if((FLAG_BIT || FLAG_RANGE) && FLAG_PUBLIC && FLAG_N)	{
		if(str_output)	{
			OUTPUT = fopen(str_output,"a");
			if(OUTPUT == NULL)	{
				fprintf(stderr,"can't opent file %s\n",str_output);
				OUTPUT = stdout;
			}
		}
		else	{
			OUTPUT = stdout;
		}
		if(N % 2 == 1)	{
			N++;
		}
		//M = N /2;
		if(FLAG_SUB && FLAG_ADD) {
			M = N / 2;
		}
		else if(FLAG_ADD) {
			M = N;
		}
		else if(FLAG_SUB) {
			M = N;
		}
		else {
			M = N /2;
		}

		mpz_sub(diff,max_range,min_range);
		mpz_init(base_publickey.x);
		mpz_init(base_publickey.y);
		mpz_init(sum_publickey.x);
		mpz_init(sum_publickey.y);
		mpz_init(negated_publickey.x);
		mpz_init(negated_publickey.y);
		mpz_init(dst_publickey.x);
		mpz_init(dst_publickey.y);
		mpz_init(base_key);
		mpz_init(sum_key);

		if(FLAG_RANDOM)	{
			gmp_randinit_mt(state);
			gmp_randseed_ui(state, ((int)clock()) + ((int)time(NULL)) );

     		//sort_str_array(RANGE_PK, SIZE_PK);
			fprintf(stderr,"install hash;\n");
			HASHES_PK = install_hash();

			if(!HASHES_PK){
                fprintf(stderr,"error!!!");
                return -1;
			}

			modify_array();

        	HASHES_PK2 = install_hash();

			if(!HASHES_PK2){
                fprintf(stderr,"error!!!");
                return -1;
			}

			modify_array2();


			int looked_up_val = -1;


			for(i = 0; i < M;i++)	{
				mpz_urandomm(base_key,state,diff);
				Scalar_Multiplication(G,&base_publickey,base_key);
				Point_Negation(&base_publickey,&negated_publickey);
				Point_Addition(&base_publickey,&target_publickey,&dst_publickey);



				switch(FLAG_FORMART)	{
					case 0: //Publickey
					if(FLAG_ADD) {
						generate_strpublickey(&dst_publickey,FLAG_LOOK == 0,str_publickey);


                         //looked_up_val = look_up_pk(str_publickey, RANGE_PK, SIZE_PK);
 						//looked_up_val = look_up_pk_binary(str_publickey, RANGE_PK, SIZE_PK);
						int hash_val =  Hash2(str_publickey);//

						looked_up_val = HASHES_PK[hash_val]-1;
						//fprintf(OUTPUT,"%s\n",str_publickey);
						if (looked_up_val>=0){
                          int looked_up_val2 = HASHES_PK2[Hash3(str_publickey)]-1; ; //  recheck collision
                          if(looked_up_val2!=looked_up_val){
                            looked_up_val = -1;
                          }
						}


						if(FLAG_HIDECOMMENT && FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx\n", dst_publickey.x);
						}
						else if(FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx # - %Zx\n", dst_publickey.x, base_key);
						}
						else if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_publickey);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_publickey,base_key);
							gmp_fprintf(OUTPUT, "%s # - %Zx\n", str_publickey, base_key);
						}
					}
						if(FLAG_SUB) {
						Point_Addition(&negated_publickey,&target_publickey,&dst_publickey);
						generate_strpublickey(&dst_publickey,FLAG_LOOK == 0,str_publickey);


                         //looked_up_val = look_up_pk(str_publickey, RANGE_PK, SIZE_PK);
 						//looked_up_val = look_up_pk_binary(str_publickey, RANGE_PK, SIZE_PK);
						int hash_val =  Hash2(str_publickey);//

						looked_up_val = HASHES_PK[hash_val]-1;
						//fprintf(OUTPUT,"%s\n",str_publickey);
						if (looked_up_val>=0){
                          int looked_up_val2 = HASHES_PK2[Hash3(str_publickey)]-1; ; //  recheck collision
                          if(looked_up_val2!=looked_up_val){
                            looked_up_val = -1;
                          }
						}


						if(FLAG_HIDECOMMENT && FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx\n", dst_publickey.x);
						}
						else if(FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx # + %Zx\n", dst_publickey.x, base_key);
						}
						else if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_publickey);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_publickey,base_key);
							gmp_fprintf(OUTPUT, "%s # + %Zx\n", str_publickey, base_key);
						}
						}
					break;
					case 1: //rmd160
					if(FLAG_ADD) {
						generate_strrmd160(&dst_publickey,FLAG_LOOK == 0,str_rmd160);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_rmd160);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_rmd160,base_key);

							gmp_fprintf(OUTPUT, "%s # - %Zx\n", str_rmd160, base_key);
						}

					}
						if(FLAG_SUB) {
						Point_Addition(&negated_publickey,&target_publickey,&dst_publickey);
						generate_strrmd160(&dst_publickey,FLAG_LOOK == 0,str_rmd160);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_rmd160);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # + %Zd\n",str_rmd160,base_key);
							if(1000<i && i<10000){
							gmp_fprintf(OUTPUT, "%s # + %Zx\n", str_rmd160, base_key);
						}
						}
						}
					break;
					case 2:	//address
					if(FLAG_ADD) {
						generate_straddress(&dst_publickey,FLAG_LOOK == 0,str_address);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_address);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_address,base_key);
							gmp_fprintf(OUTPUT, "%s # - %Zx\n", str_address, base_key);
						}
					}
						if(FLAG_SUB) {
						Point_Addition(&negated_publickey,&target_publickey,&dst_publickey);
						generate_straddress(&dst_publickey,FLAG_LOOK == 0,str_address);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_address);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # + %Zd\n",str_address,base_key);
							gmp_fprintf(OUTPUT, "%s # + %Zx\n", str_address, base_key);
						}
						}
					break;
				}
				if (i % 10000 == 0) {
                    double_t perc = calc_perc(i, M);
                    printf("\r[+] Percent Complete: %0.2lf", perc);
                    fflush(stdout);
                }
                if(looked_up_val>=0){
                    break;
                }
			}

			switch(FLAG_FORMART)	{
				case 0: //Publickey

					generate_strpublickey(&target_publickey,FLAG_LOOK == 0,str_publickey);
					if(FLAG_HIDECOMMENT && FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx\n", target_publickey.x);
						}
					else if(FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx # target\n", target_publickey.x);
						}
					else if(FLAG_HIDECOMMENT)	{
						fprintf(OUTPUT,"%s\n",str_publickey);
					}

					else	{
						fprintf(OUTPUT,"%s # target\n",str_publickey);
					}
				break;
				case 1: //rmd160
					generate_strrmd160(&target_publickey,FLAG_LOOK == 0,str_rmd160);
					if(FLAG_HIDECOMMENT)	{
						fprintf(OUTPUT,"%s\n",str_rmd160);
					}
					else	{
						fprintf(OUTPUT,"%s # target\n",str_rmd160);
					}
				break;
				case 2:	//address
					generate_straddress(&target_publickey,FLAG_LOOK == 0,str_address);
					if(FLAG_HIDECOMMENT)	{
						fprintf(OUTPUT,"%s\n",str_address);
					}
					else	{
						fprintf(OUTPUT,"%s # target\n",str_address);
					}
				break;
			}
			if (i = M) {// ???
                    double_t perc = calc_perc(i, M);
                    //printf("\r[+] Percent Complete: %0.6lf", perc);
					printf("\r[+] Percent Complete: Finished");
                    fflush(stdout);
                }


		}
		else	{

			mpz_cdiv_q_ui(base_key,diff,M);
			//mpz_cdiv_q_ui(base_key,min_range,1);

			Scalar_Multiplication(G,&base_publickey,base_key);
			mpz_set(sum_publickey.x,base_publickey.x);
			mpz_set(sum_publickey.y,base_publickey.y);
			mpz_set(sum_key,base_key);

			//?? should not we do the add/sub of min_range????
			/*Scalar_Multiplication(G,&diff_publickey,min_range);
			  mpz_add(sum_key,min_range);
                          mpz_add(sum_publickey.x,diff_publickey.x);
			  mpz_add(sum_publickey.y,diff_publickey.y);
			*/

			// sort the array of keys
			//sort_str_array(RANGE_PK, SIZE_PK);
			fprintf(stderr,"install hash;\n");
			HASHES_PK = install_hash();

			if(!HASHES_PK){
               			 fprintf(stderr,"error!!!");
                		return -1;
			}

			modify_array();

			HASHES_PK2 = install_hash2();
			if(!HASHES_PK2){
           			 fprintf(stderr,"error!!!");
               		return -1;
			}
			modify_array2();

			int looked_up_val = -1;

			for(i = 0; i < M;i++)	{
                //fprintf(stderr,"iter %d %d, negation:\n",i,FLAG_ADD);
				Point_Negation(&sum_publickey,&negated_publickey);

				//fprintf(stderr,"add \n");
				Point_Addition(&sum_publickey,&target_publickey,&dst_publickey);


				switch(FLAG_FORMART)	{
					case 0: //Publickey
						if(FLAG_ADD) {

						generate_strpublickey(&dst_publickey,FLAG_LOOK == 0,str_publickey);

                         //looked_up_val = look_up_pk(str_publickey, RANGE_PK, SIZE_PK);
 						//looked_up_val = look_up_pk_binary(str_publickey, RANGE_PK, SIZE_PK);
						int hash_val =  Hash2(str_publickey);//

						looked_up_val = HASHES_PK[hash_val]-1;
						//fprintf(OUTPUT,"%s\n",str_publickey);
						if (looked_up_val>=0){
                          int looked_up_val2 = HASHES_PK2[Hash3(str_publickey)]-1; ; //  recheck collision
                          if(looked_up_val2!=looked_up_val){
                            looked_up_val = -1;
                          }
						}



						if(FLAG_HIDECOMMENT && FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx\n", dst_publickey.x);
						}
						else if(FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx # - %Zx\n", dst_publickey.x, sum_key);
						}
						else if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_publickey);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_publickey,base_key);
							gmp_fprintf(OUTPUT, "%s # - %Zx\n", str_publickey, sum_key);
						}
						}

						if(FLAG_SUB) {

						Point_Addition(&negated_publickey,&target_publickey,&dst_publickey);

						generate_strpublickey(&dst_publickey,FLAG_LOOK == 0,str_publickey);
						//	fprintf(OUTPUT,"%s\n",str_publickey);

 						//looked_up_val = look_up_pk(str_publickey, RANGE_PK, SIZE_PK);
 						//looked_up_val = look_up_pk_binary(str_publickey, RANGE_PK, SIZE_PK);
						int hash_val =  Hash2(str_publickey);//

						looked_up_val = HASHES_PK[hash_val]-1;
						//fprintf(OUTPUT,"%s\n",str_publickey);
						if (looked_up_val>=0){
                          int looked_up_val2 = HASHES_PK2[Hash3(str_publickey)]-1; ; //  recheck collision
                          if(looked_up_val2!=looked_up_val){
                            looked_up_val = -1;
                          }
						}

						if(FLAG_HIDECOMMENT && FLAG_XPOINTONLY)	{
							fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx\n", dst_publickey.x);
						}
						else if(FLAG_XPOINTONLY)	{
							fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx # - %Zx\n", dst_publickey.x, sum_key);
						}
						else if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_publickey);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_publickey,base_key);
							gmp_fprintf(OUTPUT, "%s # - %Zx\n", str_publickey, sum_key);
						}

						if (looked_up_val>=0){
                            				fprintf(stderr,"Our Private Key is located in the Interval, we break the loop\n");
                            				fprintf(stderr,"Item Number %d, hashcode: %u \n",looked_up_val,hash_val);

				       		  }
					}

					break;
					case 1: //rmd160
					if(FLAG_ADD) {
						generate_strrmd160(&dst_publickey,FLAG_LOOK == 0,str_rmd160);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_rmd160);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_rmd160,sum_key);
							gmp_fprintf(OUTPUT, "%s # - %Zx\n", str_rmd160, sum_key);
						}
					}
						if(FLAG_SUB) {
						Point_Addition(&negated_publickey,&target_publickey,&dst_publickey);
						generate_strrmd160(&dst_publickey,FLAG_LOOK == 0,str_rmd160);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_rmd160);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # + %Zd\n",str_rmd160,sum_key);
							gmp_fprintf(OUTPUT, "%s # + %Zx\n", str_rmd160, sum_key);
						}
						}
					break;
					case 2:	//address
					if(FLAG_ADD) {
						generate_straddress(&dst_publickey,FLAG_LOOK == 0,str_address);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_address);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_address,sum_key);
							gmp_fprintf(OUTPUT, "%s # - %Zx\n", str_address, sum_key);
						}
					}
						if(FLAG_SUB) {
						Point_Addition(&negated_publickey,&target_publickey,&dst_publickey);
						generate_straddress(&dst_publickey,FLAG_LOOK == 0,str_address);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_address);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # + %Zd\n",str_address,sum_key);
							gmp_fprintf(OUTPUT, "%s # + %Zx\n", str_address, sum_key);
						}
						}
					break;
				}

				Point_Addition(&sum_publickey,&base_publickey,&dst_publickey);
				mpz_set(sum_publickey.x,dst_publickey.x);
				mpz_set(sum_publickey.y,dst_publickey.y);
				mpz_add(sum_key,sum_key,base_key);
				if (i % 10000 == 0) {
                    double_t perc = calc_perc(i, M);
                    fprintf(stderr,"\r[+] Percent Complete: %0.2lf", perc);
                    fflush(stdout);
                }

                if(looked_up_val>=0){
                    break;
                }
			}

			fprintf(stderr,"Final Output:\n ");
			switch(FLAG_FORMART)	{
				case 0: //Publickey
					generate_strpublickey(&target_publickey,FLAG_LOOK == 0,str_publickey);
					if(FLAG_HIDECOMMENT && FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx\n", target_publickey.x);
						}
					else if(FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx # target\n", target_publickey.x);
						}
					else if(FLAG_HIDECOMMENT)	{
						fprintf(OUTPUT,"%s\n",str_publickey);
					}

					else	{
						fprintf(OUTPUT,"%s # target\n",str_publickey);
					}
				break;
				case 1: //rmd160
					generate_strrmd160(&target_publickey,FLAG_LOOK == 0,str_rmd160);
					if(FLAG_HIDECOMMENT)	{
						fprintf(OUTPUT,"%s\n",str_rmd160);
					}
					else	{
						fprintf(OUTPUT,"%s # target\n",str_rmd160);
					}
				break;
				case 2:	//address
					generate_straddress(&target_publickey,FLAG_LOOK == 0,str_address);
					if(FLAG_HIDECOMMENT)	{
						fprintf(OUTPUT,"%s\n",str_address);
					}
					else	{
						fprintf(OUTPUT,"%s # target\n",str_address);
					}
				break;
			}
			if (i == M) {
                    double_t perc = calc_perc(i, M);
                    //printf("\r[+] Percent Complete: %0.6lf", perc);
					printf("\r[+] Percent Complete: Finished");
                    fflush(stdout);
                }
		}

		mpz_clear(base_publickey.x);
		mpz_clear(base_publickey.y);
		mpz_clear(sum_publickey.x);
		mpz_clear(sum_publickey.y);
		mpz_clear(negated_publickey.x);
		mpz_clear(negated_publickey.y);
		mpz_clear(dst_publickey.x);
		mpz_clear(dst_publickey.y);
		mpz_clear(base_key);
		mpz_clear(sum_key);
		if(HASHES_PK) free(HASHES_PK);
		if(HASHES_PK2) free(HASHES_PK2);
	}
	else	{
#ifdef DEBUG
        for(int j=0;j<argc;j++){
            fprintf(stderr,"%s ", argv[j]);
        }
        fprintf(stderr, "%d, %d, %d,%d", FLAG_BIT, FLAG_RANGE, FLAG_PUBLIC, FLAG_N);
#endif
		fprintf(stderr,"\nVersion: %s\n",version);
		fprintf(stderr,"[E] There are some missing parameter(s)\n");
		showhelp();
	}
	return 0;
}

void showhelp()	{
	printf("\nUsage:\n-h\t\tShow this help screen.\n");
	printf("-b bits\t\tFor subtracting and addition enter a bit range.\n");
	printf("-f format\tOutput format <publickey, rmd160, address>. Default: publickey\n");
	printf("-l look\t\tOutput <compressed, uncompressed>. Default: compress\n");
	printf("-n number\tNumber of public keys to generate. This number needs to be even.\n");
	printf("-o file\t\tOutput file. If you omit this option, results will be printed on screen.\n");
	printf("-p key\t\tPublickey to be added/subtracted; can be compressed or uncompressed.\n");
	printf("-r A:B\t\tRange A to B; ex: -r 2000000000:3000000000\n");
	printf("-R\t\tRandom addition/subtraction publickey instead of sequential.\n");
	printf("-a\t\tAddition only to the public key.\n");
	printf("-s\t\tSubtraction only to the public key.\n");
	printf("NOTE:\n\t\tIf you want to add and subtract from public key, use the -s and -a flags at the same time.\n\n");
	printf("-z\t\tX Point only. It will exclude the even (02) and odd (03) parity of the Y coord.\n");
	printf("-x\t\tExclude comments; the + and/or - columns. You need the comments if using Random mode.\n");
	printf("NOTE:\n\t\tThe + or - comments are telling you what to add or subtract from found key.\n\t\tIf you use -s, subtraction only, you need to add + the number to found key,\n\t\tto equal the actual key you are looking for.\n\n");
	printf("Property of SSD pvt\n\n");
}

void set_bit(char *param)	{
	mpz_t MPZAUX;
	int bitrange = strtol(param,NULL,10);
	if(bitrange > 0 && bitrange <=256 )	{
		mpz_init(MPZAUX);
		mpz_pow_ui(MPZAUX,TWO,bitrange-1);
		mpz_set(min_range,MPZAUX);
		mpz_pow_ui(MPZAUX,TWO,bitrange);
		mpz_sub_ui(MPZAUX,MPZAUX,1);
		mpz_set(max_range,MPZAUX);
		printf("[+] KeySubtractor\n");
		printf("[+] Version %s\n",version);
		fprintf(stderr, "[+] Keys to Generate: %d\n", N);
		gmp_fprintf(stderr,"[+] Min range: %Zx\n",min_range);
		gmp_fprintf(stderr,"[+] Max range: %Zx\n",max_range);
		mpz_clear(MPZAUX);
	}
	else	{
		fprintf(stderr,"[E] Invalid bit paramaters: %s\n",param);
		exit(0);
	}
}

void set_publickey(char *param)	{
	char hexvalue[65];
	char *dest;
	int len;
	len = strlen(param);
	dest = (char*) calloc(len+1,1);
	if(dest == NULL)	{
		fprintf(stderr,"[E] Error calloc\n");
		exit(0);
	}
	memset(hexvalue,0,65);
	memcpy(dest,param,len);
	trim(dest," \t\n\r");
	len = strlen(dest);
	switch(len)	{
		case 66:
			mpz_set_str(target_publickey.x,dest+2,16);
		break;
		case 130:
			memcpy(hexvalue,dest+2,64);
			mpz_set_str(target_publickey.x,hexvalue,16);
			memcpy(hexvalue,dest+66,64);
			mpz_set_str(target_publickey.y,hexvalue,16);
		break;
	}
	if(mpz_cmp_ui(target_publickey.y,0) == 0)	{
		mpz_t mpz_aux,mpz_aux2,Ysquared;
		mpz_init(mpz_aux);
		mpz_init(mpz_aux2);
		mpz_init(Ysquared);
		mpz_pow_ui(mpz_aux,target_publickey.x,3);
		mpz_add_ui(mpz_aux2,mpz_aux,7);
		mpz_mod(Ysquared,mpz_aux2,EC.p);
		mpz_add_ui(mpz_aux,EC.p,1);
		mpz_fdiv_q_ui(mpz_aux2,mpz_aux,4);
		mpz_powm(target_publickey.y,Ysquared,mpz_aux2,EC.p);
		mpz_sub(mpz_aux, EC.p,target_publickey.y);
		switch(dest[1])	{
			case '2':
				if(mpz_tstbit(target_publickey.y, 0) == 1)	{
					mpz_set(target_publickey.y,mpz_aux);
				}
			break;
			case '3':
				if(mpz_tstbit(target_publickey.y, 0) == 0)	{
					mpz_set(target_publickey.y,mpz_aux);
				}
			break;
			default:
				fprintf(stderr,"[E] Some invalid bit in the publickey: %s\n",dest);
				exit(0);
			break;
		}
		mpz_clear(mpz_aux);
		mpz_clear(mpz_aux2);
		mpz_clear(Ysquared);
	}
	free(dest);
}

void set_range(char *param)	{
	Tokenizer tk;
	char *dest;
	int len;
	len = strlen(param);
	dest = (char*) calloc(len+1,1);
	if(dest == NULL)	{
		fprintf(stderr,"[E] Error calloc\n");
		exit(0);
	}
	memcpy(dest,param,len);
	dest[len] = '\0';
	stringtokenizer(dest,&tk);
	if(tk.n == 2)	{
		mpz_init_set_str(min_range,nextToken(&tk),16);
		mpz_init_set_str(max_range,nextToken(&tk),16);
		/*printf("[+] Version %s\n",version);
		printf("[+] KeySubtractor\n");
		fprintf(stderr, "[+] Keys to Generate: %d\n", N);
		gmp_fprintf(stderr, "[+] Min range: %Zx\n", min_range);
        gmp_fprintf(stderr, "[+] Max range: %Zx\n", max_range);*/
	}
	else	{
		fprintf(stderr,"%i\n",tk.n);
		fprintf(stderr,"[E] Invalid range. Expected format A:B\n");
		exit(0);
	}
	freetokenizer(&tk);
	free(dest);
}

double_t calc_perc(uint64_t x, uint64_t max)
{
    return (double_t)(((double_t)x) / ((double_t)max) * 100.0 /*+ 0.5*/);
}

void set_format(char *param)	{
	int index = indexOf(param,formats,3);
	if(index == -1)	{
		fprintf(stderr,"[E] Unknown format: %s\n",param);
	}
	else	{
		FLAG_FORMART = index;
	}
}

void set_look(char *param)	{
	int index = indexOf(param,looks,2);
	if(index == -1)	{
		fprintf(stderr,"[E] Unknown look: %s\n",param);
	}
	else	{
		FLAG_LOOK = index;
	}
}




void generate_strpublickey(struct Point *publickey,bool compress,char *dst)	{
	memset(dst,0,132);
	if(compress)	{
		if(mpz_tstbit(publickey->y, 0) == 0)	{	// Even
			gmp_snprintf (dst,67,"02%0.64Zx",publickey->x);
		}
		else	{
			gmp_snprintf(dst,67,"03%0.64Zx",publickey->x);
		}
	}
	else	{
		gmp_snprintf(dst,131,"04%0.64Zx%0.64Zx",publickey->x,publickey->y);
	}
}

void generate_strrmd160(struct Point *publickey,bool compress,char *dst)	{
	char str_publickey[131];
	char bin_publickey[65];
	char bin_sha256[32];
	char bin_rmd160[20];
	memset(dst,0,42);
	if(compress)	{
		if(mpz_tstbit(publickey->y, 0) == 0)	{	// Even
			gmp_snprintf (str_publickey,67,"02%0.64Zx",publickey->x);
		}
		else	{
			gmp_snprintf(str_publickey,67,"03%0.64Zx",publickey->x);
		}
		hexs2bin(str_publickey,bin_publickey);
		sha256(bin_publickey, 33, bin_sha256);
	}
	else	{
		gmp_snprintf(str_publickey,131,"04%0.64Zx%0.64Zx",publickey->x,publickey->y);
		hexs2bin(str_publickey,bin_publickey);
		sha256(bin_publickey, 65, bin_sha256);
	}
	RMD160Data((const unsigned char*)bin_sha256,32, bin_rmd160);
	tohex_dst(bin_rmd160,20,dst);
}

void generate_straddress(struct Point *publickey,bool compress,char *dst)	{
	char str_publickey[131];
	char bin_publickey[65];
	char bin_sha256[32];
	char bin_digest[60];
	size_t pubaddress_size = 42;
	memset(dst,0,42);
	if(compress)	{
		if(mpz_tstbit(publickey->y, 0) == 0)	{	// Even
			gmp_snprintf (str_publickey,67,"02%0.64Zx",publickey->x);
		}
		else	{
			gmp_snprintf(str_publickey,67,"03%0.64Zx",publickey->x);
		}
		hexs2bin(str_publickey,bin_publickey);
		sha256(bin_publickey, 33, bin_sha256);
	}
	else	{
		gmp_snprintf(str_publickey,131,"04%0.64Zx%0.64Zx",publickey->x,publickey->y);
		hexs2bin(str_publickey,bin_publickey);
		sha256(bin_publickey, 65, bin_sha256);
	}
	RMD160Data((const unsigned char*)bin_sha256,32, bin_digest+1);

	/* Firts byte 0, this is for the Address begining with 1.... */

	bin_digest[0] = 0;

	/* Double sha256 checksum */
	sha256(bin_digest, 21, bin_digest+21);
	sha256(bin_digest+21, 32, bin_digest+21);

	/* Get the address */
	if(!b58enc(dst,&pubaddress_size,bin_digest,25)){
		fprintf(stderr,"error b58enc\n");
	}
}
