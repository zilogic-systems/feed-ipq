// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#define pr_fmt(fmt)	"tmelcom: %s: %d: " fmt, __func__, __LINE__

#include <linux/delay.h>
#include <linux/dma-direction.h>
#include <linux/dma-mapping.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mailbox_client.h>
#include <linux/mailbox_controller.h>
#include <linux/mailbox/tmel_qmp.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/uaccess.h>
#include <linux/of_platform.h>

#include "tmelcom.h"
#include "tmelcom_message_uids.h"

struct tmelcom {
	struct device *dev;
	struct mbox_client cl;
	struct mbox_chan *chan;
	/* Mutex to ensure only one IPC transaction at a time */
	struct mutex lock;
	struct qmp_pkt pkt;
	struct tmel_ipc_pkt *ipc_pkt;
	dma_addr_t sram_dma_addr;
	wait_queue_head_t waitq;
	bool rx_done;
};

static struct tmelcom *tmeldev;

struct device *tmelcom_get_device(void)
{
	struct tmelcom *tdev = tmeldev;

	if (!tdev)
		return NULL;

	return tdev->dev;
}

static int tmelcom_prepare_msg(struct tmelcom *tdev, u32 msg_uid,
			       void *msg_buf, size_t msg_size)
{
	struct tmel_ipc_pkt *ipc_pkt = tdev->ipc_pkt;
	struct ipc_header *msg_hdr = &ipc_pkt->msg_hdr;
	struct mbox_payload *mbox_payload = &ipc_pkt->payload.mbox_payload;
	struct sram_payload *sram_payload = &ipc_pkt->payload.sram_payload;
	int ret;

	memset(ipc_pkt, 0, sizeof(struct tmel_ipc_pkt));

	msg_hdr->msg_type = TMEL_MSG_UID_MSG_TYPE(msg_uid);
	msg_hdr->action_id = TMEL_MSG_UID_ACTION_ID(msg_uid);

	pr_debug("uid: %d, msg_size: %zu msg_type:%d, action_id:%d\n",
		 msg_uid, msg_size, msg_hdr->msg_type, msg_hdr->action_id);

	if (sizeof(struct ipc_header) + msg_size <= MBOX_IPC_PACKET_SIZE) {
		/* Mbox only */
		msg_hdr->ipc_type = IPC_MBOX_ONLY;
		msg_hdr->msg_len = msg_size;
		memcpy((void *)mbox_payload, msg_buf, msg_size);
	} else if (msg_size <= SRAM_IPC_MAX_BUF_SIZE) {
		/* SRAM */
		msg_hdr->ipc_type = IPC_MBOX_SRAM;
		msg_hdr->msg_len = 8; //payload_ptr + payload_len

		tdev->sram_dma_addr = dma_map_single(tdev->dev, msg_buf,
						     msg_size,
						     DMA_BIDIRECTIONAL);
		ret = dma_mapping_error(tdev->dev, tdev->sram_dma_addr);
		if (ret != 0) {
			pr_err("SRAM DMA mapping error: %d\n", ret);
			return ret;
		}

		sram_payload->payload_ptr = tdev->sram_dma_addr;
		sram_payload->payload_len = msg_size;
	} else {
		pr_err("Invalid payload length: %zu\n", msg_size);
	}

	pr_debug("ipc_type: %d msg_len: %d\n",
		 msg_hdr->ipc_type, msg_hdr->msg_len);
	return 0;
}

static void tmelcom_unprepare_message(struct tmelcom *tdev,
				      void *msg_buf, size_t msg_size)
{
	struct tmel_ipc_pkt *ipc_pkt = (struct tmel_ipc_pkt *)tdev->pkt.data;
	struct mbox_payload *mbox_payload = &ipc_pkt->payload.mbox_payload;

	if (ipc_pkt->msg_hdr.ipc_type == IPC_MBOX_ONLY) {
		memcpy(msg_buf, (void *)mbox_payload, msg_size);
	} else if (ipc_pkt->msg_hdr.ipc_type == IPC_MBOX_SRAM) {
		dma_unmap_single(tdev->dev, tdev->sram_dma_addr, msg_size,
				 DMA_BIDIRECTIONAL);
		tdev->sram_dma_addr = 0;
	}
}

static bool tmelcom_check_rx_done(struct tmelcom *tdev)
{
	return tdev->rx_done;
}

enum tmelcom_resp tmelcom_process_request(u32 msg_uid, void *msg_buf,
					  size_t msg_size)
{
	struct tmelcom *tdev = tmeldev;
	struct tmel_ipc_pkt *resp_ipc_pkt;
	long time_left = 0;
	int ret = 0;

	/*
	 * Check to handle if probe is not successful or not completed yet
	 */
	if (!tdev) {
		pr_err("tmelcom dev is NULL\n");
		return -ENODEV;
	}

	if (!msg_buf || !msg_size) {
		pr_err("Invalid msg_buf or msg_size\n");
		return -EINVAL;
	}

	mutex_lock(&tdev->lock);
	tdev->rx_done = false;

	ret = tmelcom_prepare_msg(tdev, msg_uid, msg_buf, msg_size);
	if (ret)
		return ret;

	tdev->pkt.size = sizeof(struct tmel_ipc_pkt);
	tdev->pkt.data = (void *)tdev->ipc_pkt;

	print_hex_dump_bytes("tmelcom sending bytes : ", DUMP_PREFIX_ADDRESS,
			     tdev->pkt.data, tdev->pkt.size);

	if (mbox_send_message(tdev->chan, &tdev->pkt) < 0) {
		pr_err("Failed to send qmp message\n");
		ret = -EAGAIN;
		goto err_exit;
	}

	time_left = wait_event_interruptible_timeout(tdev->waitq,
			tmelcom_check_rx_done(tdev),
			msecs_to_jiffies(tdev->cl.tx_tout));

	if (!time_left) {
		pr_err("Request timed out\n");
		ret = -ETIMEDOUT;
		goto err_exit;
	}

	if (tdev->pkt.size != sizeof(struct tmel_ipc_pkt)) {
		pr_err("Invalid pkt.size received size: %d, expected: %zu\n",
		       tdev->pkt.size, sizeof(struct tmel_ipc_pkt));
		ret = -EPROTO;
		goto err_exit;
	}

	resp_ipc_pkt = (struct tmel_ipc_pkt *)tdev->pkt.data;

	pr_debug("Response received: %d\n", resp_ipc_pkt->msg_hdr.response);
	print_hex_dump_bytes("tmelcom received bytes : ", DUMP_PREFIX_ADDRESS,
			     tdev->pkt.data, tdev->pkt.size);

	tmelcom_unprepare_message(tdev, msg_buf, msg_size);

	tdev->rx_done = false;

	ret = resp_ipc_pkt->msg_hdr.response;

err_exit:
	mutex_unlock(&tdev->lock);
	return ret;
}

static void tmelcom_receive_message(struct mbox_client *client, void *message)
{
	struct tmelcom *tdev = dev_get_drvdata(client->dev);
	struct qmp_pkt *pkt = NULL;

	if (!message) {
		pr_err("spurious message received\n");
		goto tmelcom_receive_end;
	}

	if (tdev->rx_done) {
		pr_err("tmelcom response pending\n");
		goto tmelcom_receive_end;
	}
	pkt = (struct qmp_pkt *)message;
	tdev->pkt.size = pkt->size;
	tdev->pkt.data = pkt->data;
	tdev->rx_done = true;

tmelcom_receive_end:
	wake_up_interruptible(&tdev->waitq);
}

static int tmelcom_probe(struct platform_device *pdev)
{
	struct tmelcom *tdev;
	tdev = devm_kzalloc(&pdev->dev, sizeof(*tdev), GFP_KERNEL);
	if (!tdev)
		return -ENOMEM;

	tdev->cl.dev = &pdev->dev;
	tdev->cl.tx_block = true;
	/* IPC timeout of 30s for emulation. To be reduced to 3s post-silicon */
	tdev->cl.tx_tout = 30000;
	tdev->cl.knows_txdone = false;
	tdev->cl.rx_callback = tmelcom_receive_message;

	/* mbox_request_chan can fail if tmel_qmp mailbox driver is not yet
	 * probed, defer and retry here.
	 */
	tdev->chan = mbox_request_channel(&tdev->cl, 0);
	if (IS_ERR(tdev->chan)) {
		pr_err("failed to get mbox channel, ret: %ld\n",
		       PTR_ERR(tdev->chan));
		return PTR_ERR(tdev->chan);
	}

	mutex_init(&tdev->lock);

	tdev->ipc_pkt = devm_kzalloc(&pdev->dev, sizeof(struct tmel_ipc_pkt),
				     GFP_KERNEL);
	if (!tdev->ipc_pkt)
		return -ENOMEM;

	init_waitqueue_head(&tdev->waitq);

	tdev->rx_done = false;
	tdev->dev = &pdev->dev;
	dev_set_drvdata(&pdev->dev, tdev);

	tmeldev = tdev;

	if (of_platform_populate(pdev->dev.of_node, NULL, NULL, &pdev->dev))
		dev_err(&pdev->dev, "tmel_log populate failed!!\n");

	pr_info("tmelcom probe success\n");
	return 0;
}

static int tmelcom_remove(struct platform_device *pdev)
{
	struct tmelcom *tdev = platform_get_drvdata(pdev);

	if (tdev->chan)
		mbox_free_channel(tdev->chan);

	pr_info("Tmelcom remove success\n");
	return 0;
}

static const struct of_device_id tmelcom_match_tbl[] = {
	{.compatible = "qcom,tmelcom-qmp-client"},
	{},
};

static struct platform_driver tmelcom_driver = {
	.probe = tmelcom_probe,
	.remove = tmelcom_remove,
	.driver = {
		.name = "tmelcom-qmp-client",
		.suppress_bind_attrs = true,
		.of_match_table = tmelcom_match_tbl,
	},
};
module_platform_driver(tmelcom_driver);

MODULE_DESCRIPTION("QCOM TME-LCom mailbox protocol client");
MODULE_LICENSE("GPL");
