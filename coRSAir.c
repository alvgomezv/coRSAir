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
#include "openssl/x509.h"

RSA *load_rsa_from_file(char *file)
{
    BIO *pem_data;
    RSA *public_key;

    
    //write(1, "hola\n", 5);
    if (strstr(file, "pem") != NULL) 
    {
        pem_data = BIO_new_file(file, "rb");
        if (pem_data == 0) 
        {
            printf("Failed to open file: %s\n", file);
            exit(1);
        }
        public_key = PEM_read_bio_RSA_PUBKEY(pem_data, NULL, NULL, NULL);
        BIO_free(pem_data);
        return public_key;
    }
    else
    {
        printf("Arguments: public_key1.pem, public_key2.pem, message.bin");
        exit(1);
    }
}

RSA *Construct_private_key(BIGNUM *p, BIGNUM *n1, BIGNUM *e1, BN_CTX *ctx)
{
    RSA *private_key;
    BIGNUM *q1; 
    BIGNUM *d1;
    BIGNUM *one;
    BIGNUM *total;      // Número total de los dos certificados
    BIGNUM *fi1;        // Número de factores primos de 'n'
    BIGNUM *fi2;   
    
    q1 = BN_new();
    BN_div(q1, NULL, n1, p, ctx); // q = n / p

    one = BN_new();
    BN_dec2bn(&one, "1"); // Inicializar 'one' a '1'

    total = BN_new();
    fi1 = BN_new();
    fi2 = BN_new();
    BN_sub(fi1, q1, one); // Calcular 'fi1' = 'q1' - '1'
    BN_sub(fi2, p, one);  // Calcular 'fi2' = 'p' - '1'
    BN_mul(total, fi1, fi2, ctx); // Calcular 'total' = 'fi1' * 'fi2'

    //write(1, "hola\n", 5);
    d1 = BN_new();
    BN_mod_inverse(d1, e1, total, ctx); // d = e^-1 mod q

    private_key = RSA_new();
    RSA_set0_key(private_key, n1, e1, d1);

    int valid = RSA_check_key(private_key);
    printf("if 0 then is not valid: %d\n\n", valid);

    printf("Private key:\n");
    PEM_write_RSAPrivateKey(stdout, private_key, NULL, NULL, 0, NULL, NULL);
    printf("\n");
    return private_key;
}

//unsigned char *decrypt_message(char *message)
//{
//    int fd;
//    int bytes_read;
//
//    file_size = 1024;
//    if (strstr(message, "bin") != NULL) 
//    {
//        fd = open(message, O_RDONLY);
//        if (fd < 0) 
//        {
//            printf("Failed to open file: %s\n", message);
//            exit(1);
//        }
//        enc_msg = (unsigned char *)malloc((file_size + 1) * sizeof(unsigned char));
//        if (!enc_msg)
//        {
//            printf("Failed to allocate memory for file data\n");
//            close(fd);
//            exit(1);
//        }
//        bytes_read = read(fd, enc_msg, file_size);
//        if (bytes_read == -1) 
//        {
//            printf("Failed to read");
//            close(fd);
//            free(enc_msg);
//            //free(dec_msg);
//            exit(1);
//        }
//        enc_msg[file_size] = '\0';
//        if (close(fd) == -1) 
//        {
//            printf("Failed to close");
//            free(enc_msg);
//            //free(dec_msg);
//            exit(1);
//        }
//        //PEM_write_RSAPrivateKey(stdout, private_key, NULL, NULL, 0, NULL, NULL);
//        //RSA_private_decrypt(bytes_read, enc_msg, dec_msg, private_key, RSA_PKCS1_PADDING);
//        //printf("Encrypted msg: %s\n", enc_msg);
//        //printf("Decrypted msg: %s", dec_msg);
//        //free(enc_msg);
//        //free(dec_msg);
//        return enc_msg;
//    }
//    else
//    {
//        printf("Arguments: public_key1.pem, public_key2.pem, message.bin");
//        exit(1);
//    }
//}
//
int main(int argc, char **argv)
{
    RSA *public_key1;
    RSA *public_key2;
    RSA *private_key;
    BIGNUM *n1;
    BIGNUM *n2; 
    BIGNUM *e1;
    BIGNUM *e2;  
    BIGNUM *p;
    BN_CTX *ctx;
    unsigned char *enc_msg;
    unsigned char *dec_msg;
    int fd;
    int bytes_read;

    if (argc == 4)
    {
        public_key1 = load_rsa_from_file(argv[1]);
        public_key2 = load_rsa_from_file(argv[2]);

        n1 = (BIGNUM*) RSA_get0_n(public_key1);
        n2 = (BIGNUM*) RSA_get0_n(public_key2);

        e1 = (BIGNUM*) RSA_get0_e(public_key1);
        e2 = (BIGNUM*) RSA_get0_e(public_key2);

        //write(1, "hola\n", 5);

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
            //private_key = RSA_new();
            private_key = Construct_private_key(p, n1, e1, ctx);

            int valid = RSA_check_key(private_key);
            printf("if 0 then is not valid: %d\n\n", valid);
        

            if (strstr(argv[3], "bin") != NULL) 
            {
                fd = open(argv[3], O_RDONLY);
                if (fd < 0) 
                {
                    printf("Failed to open file: %s\n", argv[3]);
                    exit(1);
                }
                enc_msg = (unsigned char *)malloc((1024 + 1) * sizeof(unsigned char));
                dec_msg = (unsigned char *)malloc((1024 + 1) * sizeof(unsigned char));
                bytes_read = read(fd, enc_msg, 1024);
                if (bytes_read == -1) 
                {
                    printf("Failed to read");
                    close(fd);
                    free(enc_msg);
                    free(dec_msg);
                    exit(1);
                }
                enc_msg[bytes_read] = '\0';
                close(fd);
            
                //PEM_write_RSAPrivateKey(stdout, private_key, NULL, NULL, 0, NULL, NULL);
                int dec_len = RSA_private_decrypt(bytes_read, enc_msg, dec_msg, private_key, RSA_PKCS1_PADDING);
                printf("%d, %d\n", bytes_read, dec_len);
                printf("Encrypted msg: %s\n", enc_msg);
                printf("Decrypted msg: %s\n", dec_msg);

                //RSA_free(public_key1);
                //RSA_free(public_key2);
                //BN_CTX_free(ctx);
                //BN_free(p);
                //free(enc_msg);
                //free(dec_msg);
            }
            else
            {
                printf("Arguments: public_key1.pem, public_key2.pem, message.bin");
            }
            
        }
        else
        {
            printf("Can't find the private key with this two public keys");
            exit(1);
        }

    }
    else
    {
        printf("Arguments: public_key1.pem, public_key2.pem, message.bin");
    }
}