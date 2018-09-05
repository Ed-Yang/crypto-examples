#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/random.h>

#include <crypto/rng.h>

static int get_random_numbers(u8 *buf, unsigned int len)
{
    struct crypto_rng *rng = NULL;
    char *drbg = "drbg_nopr_sha256"; /* Hash DRBG with SHA-256, no PR */
    int ret;

    if (!buf || !len) {
        pr_debug("No output buffer provided\n");
        return -EINVAL;
    }

    rng = crypto_alloc_rng(drbg, 0, 0);
    if (IS_ERR(rng)) {
        pr_info("could not allocate RNG handle for %s\n", drbg);
        return PTR_ERR(rng);
    }

    ret = crypto_rng_get_bytes(rng, buf, len);
    if (ret < 0)
        pr_info("generation of random numbers failed\n");
    else if (ret == 0)
        pr_info("RNG returned no data");
    else
        pr_info("RNG returned %d bytes of data\n", ret);

out:
    crypto_free_rng(rng);
    return ret;
}

static int __init trand_init(void)
{
    u8 num[16];
    int i;
    int ret;

	printk("test rand loaded\n");	

    ret = get_random_numbers(num, sizeof(num));

    printk("get_random_numbers return %d\n", ret);	
	
    if (ret == 0)
    {
        for (i=0; i < sizeof(num); i++)
        {
            printk("%02x", num[i]);
        }
    }
    
	return 0;
}

static void __exit trand_exit(void)
{
	printk("test rand unloaded\n");
}

module_init(trand_init);
module_exit(trand_exit);

MODULE_DESCRIPTION("Test Rand");
MODULE_LICENSE("GPL");

