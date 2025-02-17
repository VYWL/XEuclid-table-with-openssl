#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256

void printBN(const char *msg, BIGNUM *a) {
	char *number_str = BN_bn2dec(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}

BIGNUM *XEuclid (BIGNUM *x, BIGNUM *y, BIGNUM *a, BIGNUM *b);

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