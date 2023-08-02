#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "util.h"

//#include "gmpecc.h"
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"

long long H_SIZE = 0x3FFFFFF; // Size of Hash to keep the data
int size_chunk = 0x3FFFFF; // size of DB

// names of files
char NAME_FILE_PK[255] = "Private_key.txt\0";
char NAME_FILE_MEL[255] = "mel.txt\0";

// simple hash to keep the data
int hash(char* s){

    long long hash_res = 0;

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


 // simple hash to keep the data
int hash_second(char* s){

    long long hash_res = 0;

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


 // simple hash to keep the data
int hash_general(char* s, int p){

    long long hash_res = 0;

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

 /*
 * >>>make search
 * 1) search.exe  -- look for common in "Private_key.txt" and "mel.txt" - not more then 1000
 * 2) search.exe <file1> <file2> <max keys>.
      Example:
      >>>search.exe Private_key.txt mel.txt 10000
 *
 */

int main(int argc, char **argv)  {

  if (argc != 4 && argc != 1) {
        fprintf(stderr, "Invalid number of parameters. Usage: %s <file1> <file2> <max_number_of_keys>\n", argv[0]);
  }

  int resulting_keys = 1000;
  if (argc == 4){
    int rs = sscanf(argv[3], "%d", &resulting_keys);
    if(rs!=1){
       fprintf(stderr, "Invalid integerkey %s", argv[3]);
       return -5;
    }

    int set_file_pk = snprintf(NAME_FILE_PK, 255, "%s\n", argv[1]);
    if(set_file_pk<=0){
       fprintf(stderr, "Invalid first file name", argv[1]);
       return -1;
    }
    int set_file_mel = snprintf(NAME_FILE_MEL, 255, "%s\n", argv[2]);
    if(set_file_mel<=0){
        fprintf(stderr, "Invalid second file name", argv[2]);
        return -2;
    }
  }


  int* answers = (int*) malloc(resulting_keys * sizeof(answers[0]));
  int  answers_count = 0;



  FILE * f_pk = fopen(NAME_FILE_PK,"rt");
  if(!f_pk){
        fprintf(stderr, "Invalid first file", argv[1]);
        return -3;
  }

  int pk_count = 0;
  int loop_count = 0;

  int* hash_database  = (int*) calloc(H_SIZE,sizeof(hash_database[0]));
  int* hash_database2 = (int*) calloc(H_SIZE,sizeof(hash_database2[0]));


  while(f_pk){

      char str_row[250];
      char* res_f = fgets(str_row,250,f_pk);
      if(!res_f){
        break;
      }
      char priv_key[70];
      char pub_key[70];
      int ret_pk = sscanf(str_row,"P: %s C: %s", priv_key, pub_key);
      if(ret_pk!=2){
        continue;
      }
      //fprintf(stderr,"Key %s\n", pub_key);
      pk_count++;

      int hash_val = hash(pub_key);
      int hash_val2 = hash_second(pub_key);

      hash_database[hash_val] = pk_count;
      hash_database2[hash_val] = pk_count;


      if(pk_count>size_chunk){
            FILE * f_mel = fopen(NAME_FILE_MEL,"rt");
            if(!f_mel){
                fprintf(stderr, "Invalid second file", argv[2]);
                return -4;
            }

            while(f_mel){
                char str_row2[250];
                char* res_g = fgets(str_row2,250,f_mel);
                if(!res_g){
                    break;
                }
                char pub_key2[70];
                char diff[70];
                int ret_mel = sscanf(str_row2,"%s # + %s", pub_key2, diff);
                // fprintf(stderr,"Key 2:%s\n", pub_key2);

                if(ret_mel!=2){
                    continue;
                }

                int hash_mel = hash(pub_key2);
                int num_hash = hash_database[hash_mel];
                int hash_mel2 = hash_second(pub_key2);
                int num_hash2 = hash_database[hash_mel];

                if(num_hash>0 && num_hash2==num_hash){
                    fprintf(stderr,"Public key %s gives hash %d of index %d", pub_key2, hash_mel, num_hash);
                    answers[answers_count++] = num_hash-1 + loop_count;
                }
            }

            fclose(f_mel);

            loop_count += size_chunk;
            pk_count = 0;
      }


  }

   FILE * f_mel = fopen(NAME_FILE_MEL,"rt");
   if(!f_mel){
           fprintf(stderr, "Invalid second file", argv[2]);
           return -4;
   }

   while(f_mel){
           char str_row2[250];
           char* res_g = fgets(str_row2,250,f_mel);
           if(!res_g){
                    break;
           }
           char pub_key2[70];
           char diff[70];
           int ret_mel = sscanf(str_row2,"%s # + %s", pub_key2, diff);
           // fprintf(stderr,"Key 2:%s\n", pub_key2);

           if(ret_mel!=2){
                 continue;
           }

           int hash_mel = hash(pub_key2);
           int num_hash = hash_database[hash_mel];

           if(num_hash>0){
               fprintf(stderr,"Public key %s gives hash %d of index %d", pub_key2, hash_mel, num_hash);
               answers[answers_count++] = num_hash - 1 + loop_count;
           }
   }

   fclose(f_mel);

   loop_count += size_chunk;
   pk_count = 0;

   fclose(f_pk);

   free(hash_database);
   free(hash_database2);

   if(answers_count>0){
       fprintf(stdout,"\nAnswer's indice:\n");
       for(int j=0;j<answers_count;j++){
          fprintf(stdout,"Index %d from %s is used\n", answers[j], NAME_FILE_PK);
       }
   }
    else{
        fprintf(stdout," No keys are found.");
    }
}
