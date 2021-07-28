#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#define NBITS 256

void printBN(const char *msg, BIGNUM *a) {
	char *number_str = BN_bn2dec(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}

void BN_one_line_operation (BIGNUM *n, BIGNUM *n_1, BIGNUM * n_2, BIGNUM * q, BN_CTX *ctx);
void BN_one_line_copy (BIGNUM *n, BIGNUM *n_1, BIGNUM * n_2);

void printInit();
void printLevel(BIGNUM *q, BIGNUM *r, BIGNUM *r_1, BIGNUM *r_2
              , BIGNUM *x, BIGNUM *x_1, BIGNUM *x_2
              , BIGNUM *y, BIGNUM *y_1, BIGNUM *y_2, int flag);

BIGNUM *XEuclid (BIGNUM *x, BIGNUM *y, BIGNUM * input_a, BIGNUM * input_b) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *q = BN_new();
    BIGNUM *r_1 = BN_new();
    BIGNUM *r_2 = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *x_1 = BN_new();
    BIGNUM *x_2 = BN_new();
    BIGNUM *y_1 = BN_new();
    BIGNUM *y_2 = BN_new();
    
    BIGNUM *s = BN_new();
    BIGNUM *t;
    int swapFlag = 0;

    BN_copy(r_1, input_a);
    BN_copy(r_2, input_b);

    if(BN_cmp(r_1, r_2) < 0){
        t = r_1;
        r_1 = r_2;
        r_2 = t;
        swapFlag = 1;
    }

    BN_one(x_1); BN_zero(x_2);
    BN_zero(y_1); BN_one(y_2); 

    if(!BN_div(q, r, r_1, r_2, ctx))
            goto err;

    // printInit();

    BN_one_line_operation(r, r_1, r_2, q, ctx);
    BN_one_line_operation(x, x_1, x_2, q, ctx);
    BN_one_line_operation(y, y_1, y_2, q, ctx);
    
    // printLevel(q, r, r_1, r_2, x, x_1, x_2, y, y_1, y_2, 1);

    while(!BN_is_zero(r)) {
        BN_one_line_copy(r, r_1, r_2);
        BN_one_line_copy(x, x_1, x_2);
        BN_one_line_copy(y, y_1, y_2);

        if(!BN_div(q, r, r_1, r_2, ctx))
            goto err;

        BN_one_line_operation(r, r_1, r_2, q, ctx);
        BN_one_line_operation(x, x_1, x_2, q, ctx);
        BN_one_line_operation(y, y_1, y_2, q, ctx);
        
        // printLevel(q, r, r_1, r_2, x, x_1, x_2, y, y_1, y_2, 2);
    }

    if(swapFlag == 1) {
        t = x_1;
        x_1 = y_1;
        y_1 = t;
    }

    BN_copy(x, x_1);
    BN_copy(y, y_1);
    BN_copy(r, r_1);

    if(ctx != NULL) BN_CTX_free(ctx);
    if(r_1 != NULL) BN_free(r_1);
	if(r_2 != NULL) BN_free(r_2);
    if(x_1 != NULL) BN_free(x_1);
	if(y_1 != NULL) BN_free(y_1);
    if(x_2 != NULL) BN_free(x_2);
	if(y_2 != NULL) BN_free(y_2);
	if(s != NULL) BN_free(s);

    return r;

err:
    return NULL;
}

int main (int argc, char *argv[]) {
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *res;

    if(argc != 3) {
        fprintf(stderr, "usage : mygcd num1 num2\n");
        return -1;
    }

    BN_dec2bn(&a, argv[1]);
    BN_dec2bn(&b, argv[2]);
    res = XEuclid(x, y, a, b);

	printBN("(a, b) = ", res);
    printBN("a = ", a);
	printBN("b = ", b);
    printBN("x = ", x);
	printBN("y = ", y);
    printf("%s * (%s) + %s * (%s) = %s\n", BN_bn2dec(a), BN_bn2dec(x), BN_bn2dec(b), BN_bn2dec(y), BN_bn2dec(res));

	if(a != NULL) BN_free(a);
	if(b != NULL) BN_free(b);
    if(x != NULL) BN_free(x);
	if(y != NULL) BN_free(y);

    return 0;
} 

// For Debug

void printLevel(BIGNUM *q, BIGNUM *r, BIGNUM *r_1, BIGNUM *r_2
              , BIGNUM *x, BIGNUM *x_1, BIGNUM *x_2
              , BIGNUM *y, BIGNUM *y_1, BIGNUM *y_2, int flag) {

	char *_q = BN_bn2dec(q);
	char *_r = BN_bn2dec(r);
	char *_r_1 = BN_bn2dec(r_1);
	char *_r_2 = BN_bn2dec(r_2);
	char *_x = BN_bn2dec(x);
	char *_x_1 = BN_bn2dec(x_1);
	char *_x_2 = BN_bn2dec(x_2);
	char *_y = BN_bn2dec(y);
	char *_y_1 = BN_bn2dec(y_1);
	char *_y_2 = BN_bn2dec(y_2);

    if(flag == 1) {
        printf("| %3s | %3s | %3s | %3s | %3s | %3s | %3s | %3s | %3s | %3s |  <=  Init\n"
                ,  _q, _r_1, _r_2, _r, _x_1, _x_2, _x, _y_1, _y_2, _y);
    } 
    else if(flag == 2 && !strcmp(_r, "0")){
        printf("| %3s | %3s | %3s | %3s | %3s | %3s | %3s | %3s | %3s | %3s |  <=  Finished\n"
                ,  _q, _r_1, _r_2, _r, _x_1, _x_2, _x, _y_1, _y_2, _y);
    }
    else {
        printf("| %3s | %3s | %3s | %3s | %3s | %3s | %3s | %3s | %3s | %3s |\n"
                ,  _q, _r_1, _r_2, _r, _x_1, _x_2, _x, _y_1, _y_2, _y);
    }
    
    printf("=-----------------------------------------------------------=\n");
}

void printInit() {
    printf("=-----------------------------------------------------------=\n");
    printf("|                       X-Euclid-Table                      |\n");
    printf("=-----------------------------------------------------------=\n");
    printf("|  q  | r_1 | r_2 |  r  | x_1 | x_2 |  x  | y_1 | y_2 |  y  |\n");
    printf("=-----------------------------------------------------------=\n");
}

void BN_one_line_copy (BIGNUM *n, BIGNUM *n_1, BIGNUM * n_2) {
    BN_copy(n_1, n_2);
    BN_copy(n_2, n);
}

void BN_one_line_operation (BIGNUM *n, BIGNUM *n_1, BIGNUM * n_2, BIGNUM * q, BN_CTX *ctx) {
    BIGNUM *tempMul = BN_new();

    BN_mul(tempMul, n_2, q, ctx);
    BN_sub(n, n_1, tempMul);

	if(tempMul != NULL) BN_free(tempMul);
}