#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>

#include <crypto/hash.h>

#if 1 /* edward, alg */
    char *g_hash_alg_name = "sha1";
#else
    char *g_hash_alg_name = "sha1-padlock-nano";
#endif

struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    sdesc->shash.flags = 0x0;
    return sdesc;
}

static int calc_hash(struct crypto_shash *alg,
             const unsigned char *data, unsigned int datalen,
             unsigned char *digest)
{
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}

static int test_hash(const unsigned char *data, unsigned int datalen,
             unsigned char *digest)
{
    struct crypto_shash *alg;
#if 1 /* edward, alg */
    char *hash_alg_name = g_hash_alg_name;
#else
    char *hash_alg_name = "sha1-padlock-nano";
#endif
    int ret;

    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if (IS_ERR(alg)) {
            pr_info("can't alloc alg %s\n", hash_alg_name);
            return PTR_ERR(alg);
    }
    ret = calc_hash(alg, data, datalen, digest);
    crypto_free_shash(alg);
    return ret;
}

static int __init thash_init(void)
{
    char *src = "The quick brown fox jumps over the lazy dog";
    // result: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
    unsigned char digest[20];
    int i;
    int ret;

	printk("test %s loaded\n", g_hash_alg_name);	

    ret = test_hash(src, strlen(src), digest);

    if (ret == 0)
    {
        for (i=0; i < sizeof(digest); i++)
            printk("%02x", digest[i]);
    }
    else
    {
        pr_err("test_hash error ret = %d", ret);
    }
	return 0;
}

static void __exit thash_exit(void)
{
	printk("test %s unloaded\n", g_hash_alg_name);
}

module_init(thash_init);
module_exit(thash_exit);

MODULE_DESCRIPTION("Test shash");
MODULE_LICENSE("GPL");

