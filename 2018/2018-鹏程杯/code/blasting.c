#include<stdio.h>
#include<stdlib.h>

char char_set[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

long long angr_hash(char *str){
    __int64_t v0;
    int v2;
    int i;
    __int64_t v4;
    v4=0;
    v2=strlen(str);
    for(i=0;i<v2;++i){
        v0=117*v4+str[i];
        v4 = (v0
       - 2018110700000LL
       * (((__int64_t)(((__uint128_t)(-8396547321047930811LL * v0) >> 64) + v0) >> 40)
        - (v0 >> 63)));
    }
    return v4;
}

void incre_key(char *key_idx,int key_len){
    while(1){
        key_idx[key_len-1]++;
        for(int i=key_len-1;i>=0;i--){
            if(key_idx[i]==52){
                key_idx[i-1]++;
                key_idx[i]=0;
            }
            else{
                return;
            }
        }

    }
}

int main(){
    int key_len=1;

    while(1){
        int total=1;
        for(int i=0;i<key_len;i++){
            total*=52;
        }
        char *key_idx=malloc(key_len);   
        char *key=malloc(key_len+1);
        key[key_len]='\x00';

        memset(key_idx,key_len,'\x00');

        for(int i=0;i<total;i++){
            for(int j=0;j<key_len;j++){
                key[j]=char_set[key_idx[j]];
            }               // gen key

            // printf("%s\n",key);
            if(angr_hash(key)==0x53CBEB035LL){
                // puts('==========================');
                puts(key);
                exit(0);
            }
            incre_key(key_idx,key_len);
        }

        key_len++;
    }

}