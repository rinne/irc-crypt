#include <stdio.h>
#include <stdlib.h>

struct rc4_context {
    unsigned int i;
    unsigned int j;
    unsigned int *s;
    unsigned int domain;
};

#define RC4_SWAP(x, y) (((x)=(x)^(y)),((y)=(x)^(y)),((x)=(x)^(y)))

void *rc4_allocate(char *key, int keylen, unsigned int domain)
{
    struct rc4_context *s;
    unsigned int i, j;

    if (domain == 0)
	domain = 256;
    if (!key)
	key = "";
    if (keylen < 0)
	keylen = strlen(key);

    s = calloc(1, sizeof (struct rc4_context));
    if (!s)
	return NULL;
    s->s = calloc(1, sizeof (unsigned int));
    if (!s->s) {
	free(s);
	return NULL;
    }
    s->domain = domain;
    for (i = 0; i < domain; i++)
	s->s[i] = i;
    for (i = 0; i < domain; i++) {
	j = (j + s->s[i] + key[i % keylen]) % domain;
	RC4_SWAP(s->s[i], s->s[j]);
    }
    s->i = s->j = 0;

    for(i = 0; i < domain; i++)
	printf("%u ", s->s[i]);

    return (void *)s;
}

void *rc4_free(void *ctx)
{
    struct rc4_context *s = (struct rc4_context *)ctx;
    free(s->s);
    free(s);
}

unsigned int rc4_random(void *ctx)
{
    struct rc4_context *s = (struct rc4_context *)ctx;

    s->i++;
    s->j = (s->j + s->s[s->i]) % s->domain;
    RC4_SWAP(s->s[s->i], s->s[s->j]);

    return (s->s[(s->s[s->i] + s->s[s->j]) % s->domain]);
}

main(int argc, char **argv)
{
    int i;
    void *c;
    
    c = rc4_allocate((argc > 1) ? argv[1] : "", -1, 256);
/*    for (i = 0; i < 100; i++)
	printf("%u ", rc4_random(c));*/
    exit(0);
}
