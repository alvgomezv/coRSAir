#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <math.h>
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/pem.h"

//void leaks(void)
//{
//    system("leaks -q corsair.out");
//}

RSA *load_rsa_from_file(char *file)
{
    BIO *pem_data;
    RSA *public_key;

    if (strstr(file, "pem") != NULL) 
    {
        pem_data = BIO_new_file(file, "rb");
        if (pem_data == 0) 
        {
            printf("Failed to open file: %s\n", file);
            BIO_free(pem_data);
            exit(1);
        }
        public_key = PEM_read_bio_RSA_PUBKEY(pem_data, NULL, NULL, NULL);
        BIO_free(pem_data);
        return public_key;
    }
    else
    {
        printf("Public keys must be '.pem' files\n");
        printf("Arguments: 1)First public key, 2)Second public key, 3)Message");
        exit(1);
    }
}

RSA *Construct_private_key(BIGNUM *p, BIGNUM *n1, BIGNUM *e1, BN_CTX *ctx)
{
    RSA *private_key;
    BIGNUM *q1; 
    BIGNUM *d1;
    BIGNUM *one;
    BIGNUM *total;      
    BIGNUM *fi1;      
    BIGNUM *fi2;   
    
    q1 = BN_new();
    BN_div(q1, NULL, n1, p, ctx);

    one = BN_new();
    BN_dec2bn(&one, "1");

    total = BN_new();
    fi1 = BN_new();
    fi2 = BN_new();
    BN_sub(fi1, q1, one);
    BN_sub(fi2, p, one); 
    BN_mul(total, fi1, fi2, ctx);

    d1 = BN_new();
    BN_mod_inverse(d1, e1, total, ctx);

    private_key = RSA_new();
    RSA_set0_key(private_key, n1, e1, d1);

    printf("Private key:\n\n");
    PEM_write_RSAPrivateKey(stdout, private_key, NULL, NULL, 0, NULL, NULL);
    printf("\n");
    BN_free(q1);
    BN_free(one);
    BN_free(total);
    BN_free(fi1);
    BN_free(fi2);
    return private_key;
}

void decrypt_message(RSA *private_key, char *message)
{
    unsigned char *enc_msg;
    unsigned char *dec_msg;
    int fd;
    int bytes_read;
    int dec_len;
    
    if (strstr(message, "bin") != NULL) 
    {
        fd = open(message, O_RDONLY);
        if (fd < 0) 
        {
            printf("Failed to open file: %s\n", message);
            return ;
        }
        enc_msg = (unsigned char *)malloc((1024 + 1) * sizeof(unsigned char));
        dec_msg = (unsigned char *)malloc((1024 + 1) * sizeof(unsigned char));
        bytes_read = read(fd, enc_msg, 1024);
        if (bytes_read == -1) 
        {
            printf("Failed to read file: %s\n", message);
            close(fd);
            free(enc_msg);
            free(dec_msg);
            return ;
        }
        enc_msg[bytes_read] = '\0';
        close(fd);
    
        dec_len = RSA_private_decrypt(bytes_read, enc_msg, dec_msg, private_key, RSA_PKCS1_PADDING);
        if (dec_len < 0)
        {
            printf("Failed to decrypt file: %s\n", message);
            free(enc_msg);
            free(dec_msg);
        }
        else
        {
            printf("Encrypted msg: %s\n", enc_msg);
            printf("Decrypted msg: %s\n", dec_msg);
            free(enc_msg);
            free(dec_msg);
        }
    }
    else
    {
        printf("Message must be '.bin' file\n");
        printf("Arguments: 1)First public key, 2)Second public key, 3)Message");
        return ;
    }
}

int main(int argc, char **argv)
{
    RSA *public_key1;
    RSA *public_key2;
    RSA *private_key;
    BIGNUM *n1;
    BIGNUM *n1_aux;
    BIGNUM *n2; 
    BIGNUM *e1;
    BIGNUM *e1_aux;
    BIGNUM *p;
    BN_CTX *ctx;
    

    if (argc == 4)
    {
        public_key1 = load_rsa_from_file(argv[1]);
        public_key2 = load_rsa_from_file(argv[2]);

        n1_aux = (BIGNUM*) RSA_get0_n(public_key1);
        n2 = (BIGNUM*) RSA_get0_n(public_key2);

        e1_aux = (BIGNUM*) RSA_get0_e(public_key1);

        n1 = BN_dup(n1_aux);
        e1 = BN_dup(e1_aux);
        
        if (BN_cmp(n1, n2) > 0) 
        {
            p = BN_new();
            ctx = BN_CTX_new();
            BN_gcd(p, n1, n2, ctx);
        } 
        else 
        {
            p = BN_new();
            ctx = BN_CTX_new();
            BN_gcd(p, n2, n1, ctx);
        }
        if (!BN_is_one(p)) 
        {
            printf("\nMatch found!\n\n");
            private_key = Construct_private_key(p, n1, e1, ctx);
            decrypt_message(private_key, argv[3]);
            RSA_free(private_key);
        }
        else
        {
            printf("Can't find the private key with this two public keys");
            BN_free(n1);
            BN_free(e1);
        }
        RSA_free(public_key1);
        RSA_free(public_key2);
        BN_CTX_free(ctx);
        BN_free(p);
    }
    else
    {
        printf("Arguments: 1)First public key, 2)Second public key, 3)Message");
    }
    //atexit(leaks);
    return 0;
}