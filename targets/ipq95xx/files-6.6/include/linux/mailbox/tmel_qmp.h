/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2017-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _TMEL_QMP_H_
#define _TMEL_QMP_H_

#include <linux/types.h>

/**
 * struct qmp_pkt - Packet structure to be used for TX and RX with QMP
 * @size	size of data
 * @data	Buffer holding data of this packet
 */
struct qmp_pkt {
	u32 size;
	void *data;
};

#endif /* _TMEL_QMP_H_ */
