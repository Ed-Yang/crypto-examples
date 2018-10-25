#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/random.h>
#include <crypto/rng.h>

#include <linux/fs.h>		// for basic filesystem
#include <linux/proc_fs.h>	// for the proc filesystem
#include <linux/seq_file.h>	// for sequence files

//#define RNG_INIT_OPEN   1 // open on init

#define DRBG_NAME   (char *)"drbg_pr_hmac_sha256"

static struct crypto_rng *rng = NULL;
static struct proc_dir_entry* trand_file;


static int _rng_open(char *rng_name)
{
    int ret;
    
    rng = crypto_alloc_rng(rng_name, 0, 0);
    if (IS_ERR(rng)) {
        pr_info("could not allocate RNG handle for %s\n", rng_name);
        return PTR_ERR(rng);
    }

    pr_info("seed size = %d\n", crypto_rng_seedsize(rng));

    ret = crypto_rng_reset(rng, NULL, 0);
    pr_info("reset result = %d\n", ret);

    return ret;
}

static int _rng_close(void)
{
    if (rng)
        crypto_free_rng(rng);   

    return 0; 
}

/* get_random_numbers: return 0 is success */
static int _rng_bytes(u8 *buf, unsigned int len)
{
    int ret;

    if (!buf || !len) {
        pr_err("No output buffer provided\n");
        return -EINVAL;
    }

    ret = crypto_rng_get_bytes(rng, buf, len);
    if (ret < 0)
        pr_err("generation of random numbers failed\n");

    return ret;
}

static int 
trand_show(struct seq_file *m, void *v)
{
    int i;
    int ret;
    u8 num[16];

#ifndef RNG_INIT_OPEN
    _rng_open(DRBG_NAME);
#endif

    ret = _rng_bytes(num, sizeof(num));

    seq_printf(m, "_rng_bytes return %s\n", (ret == 0) ? "Success":"Failed !!!");
    printk("_rng_bytes return %s\n", (ret == 0) ? "Success":"Failed !!!");	
	
    if (ret == 0)
    {
        for (i=0; i < sizeof(num); i++)
        {
            seq_printf(m, "%02x ", num[i]);
        }
    }
    else
    {
        pr_err("_rng_bytes failed, ret = %d\n", ret);
    }

#ifndef RNG_INIT_OPEN
    _rng_close();
#endif

    seq_printf(m, "\n");

    return 0;
}

 static int
 trand_open(struct inode *inode, struct file *file)
 {
     return single_open(file, trand_show, NULL);
 }

 static const struct file_operations trand_fops = {
     .owner	= THIS_MODULE,
     .open	= trand_open,
     .read	= seq_read,
     .llseek	= seq_lseek,
     .release	= single_release,
 };


static int __init trand_init(void)
{
	printk("test rand loaded\n");	

#ifdef RNG_INIT_OPEN
    _rng_open(DRBG_NAME);
#endif
    
    trand_file = proc_create("trand", 0, NULL, &trand_fops);
    if (!trand_file) {
        pr_err("proc_create failed !!!\n");
    }

	return 0;
}

static void __exit trand_exit(void)
{
	printk("test rand unloaded\n");

#ifdef RNG_INIT_OPEN
    _rng_close();
#endif

    remove_proc_entry("trand", NULL);
}

module_init(trand_init);
module_exit(trand_exit);

MODULE_DESCRIPTION("Test Rand");
MODULE_LICENSE("GPL");

