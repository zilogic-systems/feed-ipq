// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/key.h>
#include <linux/kobject.h>
#include <linux/moduleparam.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/sysfs.h>
#include <linux/tmelcom_ipc.h>

#define MAX_COMPONENT		30
#define MAX_ARG_SIZE		MAX_COMPONENT * 2
#define MAX_LOG_SIZE		4096
#define QTI_CLASS_KEY_ID			0x8
#define OEM_PRODUCT_SEED_KEY_ID			0xC
#define TMEL_ECDH_IP_KEY_MAX_SIZE		0x60
#define TMEL_ECC_MAX_KEY_LEN			((TMEL_ECDH_IP_KEY_MAX_SIZE * 2) + 1)

static int log_level[MAX_ARG_SIZE] = {-1};
static int argc = 0;
struct kobject *tmelcom_kobj;

static ssize_t tmel_log_read(struct file *fp, char __user *user_buffer,
				size_t count, loff_t *position)
{
	char *log;
	uint32_t size;
	int ret = 0;

	log = kzalloc(MAX_LOG_SIZE, GFP_KERNEL);
	if (!log)
		return -ENOMEM;

	ret = tmelcom_get_tmel_log(log, MAX_LOG_SIZE, &size);
        if (ret) {
		pr_err("%s : Get TMEL LOG is failed\n", __func__);
		return ret;
	}
	pr_info("TMEL Log buffer size : %x\n", size);

	return simple_read_from_buffer(user_buffer, count, position,
					log, size);
}

static const struct file_operations tmel_log_fops = {
	.read = tmel_log_read,
};

static ssize_t
store_tmel_get_ecc_public_key(struct device *dev,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
	int ret, index;
	u32 type, len;
	void *resp_buf;
	char key_buf[TMEL_ECC_MAX_KEY_LEN] = {0};

	if (kstrtouint(buf, 0, &type))
		return -EINVAL;

	if (type != OEM_PRODUCT_SEED_KEY_ID && type != QTI_CLASS_KEY_ID) {
		pr_err("Invalid Key ID. Valid key IDs are 0x8(QTI), 0xC(OEM)\n");
		return -EINVAL;
	}

	resp_buf = kzalloc(TMEL_ECDH_IP_KEY_MAX_SIZE, GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	ret = tmelcomm_get_ecc_public_key(type, resp_buf,
					  TMEL_ECDH_IP_KEY_MAX_SIZE, &len);
	if (ret)
		goto out;

	for (index = 0; index < len; index++) {
		snprintf(key_buf + strlen(key_buf),
			 (TMEL_ECC_MAX_KEY_LEN - strlen(key_buf)),
			 "%02X", *(u8 *)(resp_buf + index));
	}
	/* Printing ECC Public Key */
	pr_info("%s\n", key_buf);

out:
	kfree(resp_buf);
	return count;
}

static struct device_attribute tmel_attr =
	__ATTR(get_ecc_public_key, 0200, NULL, store_tmel_get_ecc_public_key);

static int tmel_log_probe(struct platform_device *pdev)
{
	struct tmel_log_config *log_config;
	struct dentry *file;
	uint32_t count = 0;
	int i, ret = 0;

	tmelcom_kobj = kobject_create_and_add("tmelcom", NULL);
	if (!tmelcom_kobj)
		dev_err(&pdev->dev, "Failed to register tmelcom sysfs\n");

	ret = sysfs_create_file(tmelcom_kobj, &tmel_attr.attr);
	if (ret)
		dev_err(&pdev->dev, "Failed to register get_ecc_public_key sysfs\n");

	file  = debugfs_create_file("tmel_log", 0444, NULL,
					NULL, &tmel_log_fops);
	if (IS_ERR_OR_NULL(file)) {
		dev_err(&pdev->dev, "unable to create tmel_log debugfs\n");
		return -EIO;
	}
	if (!argc)
		return ret;

	/* argc will have component id and loglevel, 2 for each entry, so
	   checks argc % 2 != 0
	 */
	if (argc % 2 != 0 || argc > MAX_ARG_SIZE) {
		dev_err(&pdev->dev,
			"Invalid arguments to parse component and log level\n");
		return ret;
	}

	log_config = kzalloc((argc / 2) * sizeof(*log_config), GFP_KERNEL);
	if (!log_config)
		return -ENOMEM;

	for (i = 0; i < argc; i = i + 2) {
		dev_info(&pdev->dev,
			"component ID : Log Level = %d : %d\n",
			log_level[i], log_level[i+1]);
		log_config[count].component_id = log_level[i];
		log_config[count].log_level = log_level[i+1];
		count++;
	}

	ret = tmelcom_set_tmel_log_config(log_config,
			(argc / 2) * sizeof(log_config));
	if (ret) {
		dev_err(&pdev->dev,
			"failed to set the config, ret = %d\n", ret);
	}

	return ret;
}

static const struct of_device_id tmel_log_match_tbl[] = {
	{.compatible = "qcom,tmel-log"},
	{},
};
MODULE_DEVICE_TABLE(of, tmel_log_match_tbl);

static struct platform_driver tmel_log_driver = {
	.probe	= tmel_log_probe,
	.driver	= {
		.name = "tmel-log",
		.of_match_table = tmel_log_match_tbl,
	},
};
module_platform_driver(tmel_log_driver);

module_param_array(log_level, int, &argc, 0000);
MODULE_PARM_DESC(log_level, "An array of components and log level");

MODULE_DESCRIPTION("Collect TMEL LOG using component and log level id's");
MODULE_LICENSE("GPL");
