// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023-2024, Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/of.h>
#include <linux/regmap.h>

#include <dt-bindings/clock/qcom,ipq5424-nsscc.h>
#include <dt-bindings/reset/qcom,ipq5424-nsscc.h>

#include "clk-alpha-pll.h"
#include "clk-branch.h"
#include "clk-pll.h"
#include "clk-rcg.h"
#include "clk-regmap.h"
#include "clk-regmap-divider.h"
#include "clk-regmap-mux.h"
#include "common.h"
#include "reset.h"


enum {
	P_CMN_PLL_NSS_CLK_375M,
	P_CMN_PLL_NSS_CLK_300M,
	P_CORE_BI_PLL_TEST_SE,
	P_GCC_GPLL0_OUT_AUX,
	P_UNIPHY0_GCC_RX_CLK,
	P_UNIPHY0_GCC_TX_CLK,
	P_UNIPHY1_GCC_RX_CLK,
	P_UNIPHY1_GCC_TX_CLK,
	P_UNIPHY2_GCC_RX_CLK,
	P_UNIPHY2_GCC_TX_CLK,
	P_XO,
};

static const struct parent_map nss_cc_parent_map_0[] = {
	{ P_XO, 0 },
	{ P_GCC_GPLL0_OUT_AUX, 2 },
	{ P_CMN_PLL_NSS_CLK_300M, 5 },
	{ P_CMN_PLL_NSS_CLK_375M, 6 },
	{ P_CORE_BI_PLL_TEST_SE, 7 },
};

static const struct clk_parent_data nss_cc_parent_data_0[] = {
	{ .fw_name = "xo" },
	{ .fw_name = "gcc_gpll0_out_aux" },
	{ .fw_name = "cmn_pll_nss_clk_300m" },
	{ .fw_name = "cmn_pll_nss_clk_375m" },
	{ .fw_name = "core_bi_pll_test_se" },
};

static const struct parent_map nss_cc_parent_map_1[] = {
	{ P_XO, 0 },
	{ P_GCC_GPLL0_OUT_AUX, 2 },
	{ P_UNIPHY0_GCC_RX_CLK, 3 },
	{ P_UNIPHY0_GCC_TX_CLK, 4 },
	{ P_CMN_PLL_NSS_CLK_300M, 5 },
	{ P_CMN_PLL_NSS_CLK_375M, 6 },
	{ P_CORE_BI_PLL_TEST_SE, 7 },
};

static const struct clk_parent_data nss_cc_parent_data_1[] = {
	{ .fw_name = "xo" },
	{ .fw_name = "gcc_gpll0_out_aux" },
	{ .fw_name = "uniphy0_gcc_rx_clk" },
	{ .fw_name = "uniphy0_gcc_tx_clk" },
	{ .fw_name = "cmn_pll_nss_clk_300m" },
	{ .fw_name = "cmn_pll_nss_clk_375m" },
	{ .fw_name = "core_bi_pll_test_se" },
};

static const char * const gcc_xo_gcc_gpll0_out_aux_uniphy0_gcc_rx_tx_cmn_pll_nss_clk_300m_375m_core_bi_pll_test_se[] = {
	"xo",
	"gcc_gpll0_out_aux",
	"uniphy0_gcc_rx_clk",
	"uniphy0_gcc_tx_clk",
	"cmn_pll_nss_clk_300m",
	"cmn_pll_nss_clk_375m",
	"core_bi_pll_test_se",
};

static const struct parent_map nss_cc_parent_map_2[] = {
	{ P_XO, 0 },
	{ P_GCC_GPLL0_OUT_AUX, 2 },
	{ P_UNIPHY1_GCC_RX_CLK, 3 },
	{ P_UNIPHY1_GCC_TX_CLK, 4 },
	{ P_CMN_PLL_NSS_CLK_300M, 5 },
	{ P_CMN_PLL_NSS_CLK_375M, 6 },
	{ P_CORE_BI_PLL_TEST_SE, 7 },
};

static const struct clk_parent_data nss_cc_parent_data_2[] = {
	{ .fw_name = "xo" },
	{ .fw_name = "gcc_gpll0_out_aux" },
	{ .fw_name = "uniphy1_gcc_rx_clk" },
	{ .fw_name = "uniphy1_gcc_tx_clk" },
	{ .fw_name = "cmn_pll_nss_clk_300m" },
	{ .fw_name = "cmn_pll_nss_clk_375m" },
	{ .fw_name = "core_bi_pll_test_se" },
};

static const char * const gcc_xo_gcc_gpll0_out_aux_uniphy1_gcc_rx_tx_cmn_pll_nss_clk_300m_375m_core_bi_pll_test_se[] = {
	"xo",
	"gcc_gpll0_out_aux",
	"uniphy1_gcc_rx_clk",
	"uniphy1_gcc_tx_clk",
	"cmn_pll_nss_clk_300m",
	"cmn_pll_nss_clk_375m",
	"core_bi_pll_test_se",
};

static const struct parent_map nss_cc_parent_map_3[] = {
	{ P_XO, 0 },
	{ P_GCC_GPLL0_OUT_AUX, 2 },
	{ P_UNIPHY2_GCC_RX_CLK, 3 },
	{ P_UNIPHY2_GCC_TX_CLK, 4 },
	{ P_CMN_PLL_NSS_CLK_300M, 5 },
	{ P_CMN_PLL_NSS_CLK_375M, 6 },
	{ P_CORE_BI_PLL_TEST_SE, 7 },
};

static const struct clk_parent_data nss_cc_parent_data_3[] = {
	{ .fw_name = "xo" },
	{ .fw_name = "gcc_gpll0_out_aux" },
	{ .fw_name = "uniphy2_gcc_rx_clk" },
	{ .fw_name = "uniphy2_gcc_tx_clk" },
	{ .fw_name = "cmn_pll_nss_clk_300m" },
	{ .fw_name = "cmn_pll_nss_clk_375m" },
	{ .fw_name = "core_bi_pll_test_se" },
};

static const char * const gcc_xo_gcc_gpll0_out_aux_uniphy2_gcc_rx_tx_cmn_pll_nss_clk_300m_375m_core_bi_pll_test_se[] = {
	"xo",
	"gcc_gpll0_out_aux",
	"uniphy2_gcc_rx_clk",
	"uniphy2_gcc_tx_clk",
	"cmn_pll_nss_clk_300m",
	"cmn_pll_nss_clk_375m",
	"core_bi_pll_test_se",
};

static const struct freq_tbl ftbl_nss_cc_ce_clk_src[] = {
	F(24000000, P_XO, 1, 0, 0),
	F(375000000, P_CMN_PLL_NSS_CLK_375M, 1, 0, 0),
	{ }
};

static struct clk_rcg2 nss_cc_ce_clk_src = {
	.cmd_rcgr = 0x5e0,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = nss_cc_parent_map_0,
	.freq_tbl = ftbl_nss_cc_ce_clk_src,
	.clkr.hw.init = &(const struct clk_init_data){
		.name = "nss_cc_ce_clk_src",
		.parent_data = nss_cc_parent_data_0,
		.num_parents = ARRAY_SIZE(nss_cc_parent_data_0),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
};

static const struct freq_tbl ftbl_nss_cc_cfg_clk_src[] = {
	F(100000000, P_GCC_GPLL0_OUT_AUX, 8, 0, 0),
	{ }
};

static struct clk_rcg2 nss_cc_cfg_clk_src = {
	.cmd_rcgr = 0x6a8,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = nss_cc_parent_map_0,
	.freq_tbl = ftbl_nss_cc_cfg_clk_src,
	.clkr.hw.init = &(const struct clk_init_data){
		.name = "nss_cc_cfg_clk_src",
		.parent_data = nss_cc_parent_data_0,
		.num_parents = ARRAY_SIZE(nss_cc_parent_data_0),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
};

static const struct freq_tbl ftbl_nss_cc_eip_bfdcd_clk_src[] = {
	F(300000000, P_CMN_PLL_NSS_CLK_300M, 1, 0, 0),
	F(375000000, P_CMN_PLL_NSS_CLK_375M, 1, 0, 0),
	{ }
};

static struct clk_rcg2 nss_cc_eip_bfdcd_clk_src = {
	.cmd_rcgr = 0x644,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = nss_cc_parent_map_0,
	.freq_tbl = ftbl_nss_cc_eip_bfdcd_clk_src,
	.clkr.hw.init = &(const struct clk_init_data){
		.name = "nss_cc_eip_bfdcd_clk_src",
		.parent_data = nss_cc_parent_data_0,
		.num_parents = ARRAY_SIZE(nss_cc_parent_data_0),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
};

static const struct freq_tbl ftbl_nss_cc_port1_rx_clk_src[] = {
	F(24000000, P_XO, 1, 0, 0),
	F(25000000, P_UNIPHY0_GCC_RX_CLK, 12.5, 0, 0),
	F(25000000, P_UNIPHY0_GCC_RX_CLK, 5, 0, 0),
	F(78125000, P_UNIPHY0_GCC_RX_CLK, 4, 0, 0),
	F(125000000, P_UNIPHY0_GCC_RX_CLK, 2.5, 0, 0),
	F(125000000, P_UNIPHY0_GCC_RX_CLK, 1, 0, 0),
	F(156250000, P_UNIPHY0_GCC_RX_CLK, 2, 0, 0),
	F(312500000, P_UNIPHY0_GCC_RX_CLK, 1, 0, 0),
	{ }
};

static struct clk_rcg2 nss_cc_port1_rx_clk_src = {
	.cmd_rcgr = 0x4b4,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = nss_cc_parent_map_1,
	.freq_tbl = ftbl_nss_cc_port1_rx_clk_src,
	.clkr.hw.init = &(const struct clk_init_data){
		.name = "nss_cc_port1_rx_clk_src",
		.parent_names = gcc_xo_gcc_gpll0_out_aux_uniphy0_gcc_rx_tx_cmn_pll_nss_clk_300m_375m_core_bi_pll_test_se,
		.num_parents = ARRAY_SIZE(gcc_xo_gcc_gpll0_out_aux_uniphy0_gcc_rx_tx_cmn_pll_nss_clk_300m_375m_core_bi_pll_test_se),
		.ops = &clk_rcg2_ops,
	},
};

static const struct freq_tbl ftbl_nss_cc_port1_tx_clk_src[] = {
	F(24000000, P_XO, 1, 0, 0),
	F(25000000, P_UNIPHY0_GCC_TX_CLK, 12.5, 0, 0),
	F(25000000, P_UNIPHY0_GCC_TX_CLK, 5, 0, 0),
	F(78125000, P_UNIPHY0_GCC_TX_CLK, 4, 0, 0),
	F(125000000, P_UNIPHY0_GCC_TX_CLK, 2.5, 0, 0),
	F(125000000, P_UNIPHY0_GCC_TX_CLK, 1, 0, 0),
	F(156250000, P_UNIPHY0_GCC_TX_CLK, 2, 0, 0),
	F(312500000, P_UNIPHY0_GCC_TX_CLK, 1, 0, 0),
	{ }
};

static struct clk_rcg2 nss_cc_port1_tx_clk_src = {
	.cmd_rcgr = 0x4c0,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = nss_cc_parent_map_1,
	.freq_tbl = ftbl_nss_cc_port1_tx_clk_src,
	.clkr.hw.init = &(const struct clk_init_data){
		.name = "nss_cc_port1_tx_clk_src",
		.parent_names = gcc_xo_gcc_gpll0_out_aux_uniphy0_gcc_rx_tx_cmn_pll_nss_clk_300m_375m_core_bi_pll_test_se,
		.num_parents = ARRAY_SIZE(gcc_xo_gcc_gpll0_out_aux_uniphy0_gcc_rx_tx_cmn_pll_nss_clk_300m_375m_core_bi_pll_test_se),
		.ops = &clk_rcg2_ops,
	},
};

static const struct freq_tbl ftbl_nss_cc_port2_rx_clk_src[] = {
	F(24000000, P_XO, 1, 0, 0),
	F(25000000, P_UNIPHY1_GCC_RX_CLK, 12.5, 0, 0),
	F(25000000, P_UNIPHY1_GCC_RX_CLK, 5, 0, 0),
	F(78125000, P_UNIPHY1_GCC_RX_CLK, 4, 0, 0),
	F(125000000, P_UNIPHY1_GCC_RX_CLK, 2.5, 0, 0),
	F(125000000, P_UNIPHY1_GCC_RX_CLK, 1, 0, 0),
	F(156250000, P_UNIPHY1_GCC_RX_CLK, 2, 0, 0),
	F(312500000, P_UNIPHY1_GCC_RX_CLK, 1, 0, 0),
	{ }
};

static struct clk_rcg2 nss_cc_port2_rx_clk_src = {
	.cmd_rcgr = 0x4cc,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = nss_cc_parent_map_2,
	.freq_tbl = ftbl_nss_cc_port2_rx_clk_src,
	.clkr.hw.init = &(const struct clk_init_data){
		.name = "nss_cc_port2_rx_clk_src",
		.parent_names = gcc_xo_gcc_gpll0_out_aux_uniphy1_gcc_rx_tx_cmn_pll_nss_clk_300m_375m_core_bi_pll_test_se,
		.num_parents = ARRAY_SIZE(gcc_xo_gcc_gpll0_out_aux_uniphy1_gcc_rx_tx_cmn_pll_nss_clk_300m_375m_core_bi_pll_test_se),
		.ops = &clk_rcg2_ops,
	},
};

static const struct freq_tbl ftbl_nss_cc_port2_tx_clk_src[] = {
	F(24000000, P_XO, 1, 0, 0),
	F(25000000, P_UNIPHY1_GCC_TX_CLK, 12.5, 0, 0),
	F(25000000, P_UNIPHY1_GCC_TX_CLK, 5, 0, 0),
	F(78125000, P_UNIPHY1_GCC_TX_CLK, 4, 0, 0),
	F(125000000, P_UNIPHY1_GCC_TX_CLK, 2.5, 0, 0),
	F(125000000, P_UNIPHY1_GCC_TX_CLK, 1, 0, 0),
	F(156250000, P_UNIPHY1_GCC_TX_CLK, 2, 0, 0),
	F(312500000, P_UNIPHY1_GCC_TX_CLK, 1, 0, 0),
	{ }
};

static struct clk_rcg2 nss_cc_port2_tx_clk_src = {
	.cmd_rcgr = 0x4d8,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = nss_cc_parent_map_2,
	.freq_tbl = ftbl_nss_cc_port2_tx_clk_src,
	.clkr.hw.init = &(const struct clk_init_data){
		.name = "nss_cc_port2_tx_clk_src",
		.parent_names = gcc_xo_gcc_gpll0_out_aux_uniphy1_gcc_rx_tx_cmn_pll_nss_clk_300m_375m_core_bi_pll_test_se,
		.num_parents = ARRAY_SIZE(gcc_xo_gcc_gpll0_out_aux_uniphy1_gcc_rx_tx_cmn_pll_nss_clk_300m_375m_core_bi_pll_test_se),
		.ops = &clk_rcg2_ops,
	},
};

static const struct freq_tbl ftbl_nss_cc_port3_rx_clk_src[] = {
	F(24000000, P_XO, 1, 0, 0),
	F(25000000, P_UNIPHY2_GCC_RX_CLK, 12.5, 0, 0),
	F(25000000, P_UNIPHY2_GCC_RX_CLK, 5, 0, 0),
	F(78125000, P_UNIPHY2_GCC_RX_CLK, 4, 0, 0),
	F(125000000, P_UNIPHY2_GCC_RX_CLK, 2.5, 0, 0),
	F(125000000, P_UNIPHY2_GCC_RX_CLK, 1, 0, 0),
	F(156250000, P_UNIPHY2_GCC_RX_CLK, 2, 0, 0),
	F(312500000, P_UNIPHY2_GCC_RX_CLK, 1, 0, 0),
	{ }
};

static struct clk_rcg2 nss_cc_port3_rx_clk_src = {
	.cmd_rcgr = 0x4e4,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = nss_cc_parent_map_3,
	.freq_tbl = ftbl_nss_cc_port3_rx_clk_src,
	.clkr.hw.init = &(const struct clk_init_data){
		.name = "nss_cc_port3_rx_clk_src",
		.parent_names = gcc_xo_gcc_gpll0_out_aux_uniphy2_gcc_rx_tx_cmn_pll_nss_clk_300m_375m_core_bi_pll_test_se,
		.num_parents = ARRAY_SIZE(gcc_xo_gcc_gpll0_out_aux_uniphy2_gcc_rx_tx_cmn_pll_nss_clk_300m_375m_core_bi_pll_test_se),
		.ops = &clk_rcg2_ops,
	},
};

static const struct freq_tbl ftbl_nss_cc_port3_tx_clk_src[] = {
	F(24000000, P_XO, 1, 0, 0),
	F(25000000, P_UNIPHY2_GCC_TX_CLK, 12.5, 0, 0),
	F(25000000, P_UNIPHY2_GCC_TX_CLK, 5, 0, 0),
	F(78125000, P_UNIPHY2_GCC_TX_CLK, 4, 0, 0),
	F(125000000, P_UNIPHY2_GCC_TX_CLK, 2.5, 0, 0),
	F(125000000, P_UNIPHY2_GCC_TX_CLK, 1, 0, 0),
	F(156250000, P_UNIPHY2_GCC_TX_CLK, 2, 0, 0),
	F(312500000, P_UNIPHY2_GCC_TX_CLK, 1, 0, 0),
	{ }
};

static struct clk_rcg2 nss_cc_port3_tx_clk_src = {
	.cmd_rcgr = 0x4f0,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = nss_cc_parent_map_3,
	.freq_tbl = ftbl_nss_cc_port3_tx_clk_src,
	.clkr.hw.init = &(const struct clk_init_data){
		.name = "nss_cc_port3_tx_clk_src",
		.parent_names = gcc_xo_gcc_gpll0_out_aux_uniphy2_gcc_rx_tx_cmn_pll_nss_clk_300m_375m_core_bi_pll_test_se,
		.num_parents = ARRAY_SIZE(gcc_xo_gcc_gpll0_out_aux_uniphy2_gcc_rx_tx_cmn_pll_nss_clk_300m_375m_core_bi_pll_test_se),
		.ops = &clk_rcg2_ops,
	},
};

static struct clk_rcg2 nss_cc_ppe_clk_src = {
	.cmd_rcgr = 0x3ec,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = nss_cc_parent_map_0,
	.freq_tbl = ftbl_nss_cc_ce_clk_src,
	.clkr.hw.init = &(const struct clk_init_data){
		.name = "nss_cc_ppe_clk_src",
		.parent_data = nss_cc_parent_data_0,
		.num_parents = ARRAY_SIZE(nss_cc_parent_data_0),
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_rcg2_ops,
	},
};

static struct clk_regmap_div nss_cc_port1_rx_div_clk_src = {
	.reg = 0x4bc,
	.shift = 0,
	.width = 9,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "nss_cc_port1_rx_div_clk_src",
		.parent_hws = (const struct clk_hw*[]){
			&nss_cc_port1_rx_clk_src.clkr.hw,
		},
		.num_parents = 1,
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_regmap_div_ops,
	},
};

static struct clk_regmap_div nss_cc_port1_tx_div_clk_src = {
	.reg = 0x4c8,
	.shift = 0,
	.width = 9,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "nss_cc_port1_tx_div_clk_src",
		.parent_hws = (const struct clk_hw*[]){
			&nss_cc_port1_tx_clk_src.clkr.hw,
		},
		.num_parents = 1,
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_regmap_div_ops,
	},
};

static struct clk_regmap_div nss_cc_port2_rx_div_clk_src = {
	.reg = 0x4d4,
	.shift = 0,
	.width = 9,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "nss_cc_port2_rx_div_clk_src",
		.parent_hws = (const struct clk_hw*[]){
			&nss_cc_port2_rx_clk_src.clkr.hw,
		},
		.num_parents = 1,
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_regmap_div_ops,
	},
};

static struct clk_regmap_div nss_cc_port2_tx_div_clk_src = {
	.reg = 0x4e0,
	.shift = 0,
	.width = 9,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "nss_cc_port2_tx_div_clk_src",
		.parent_hws = (const struct clk_hw*[]){
			&nss_cc_port2_tx_clk_src.clkr.hw,
		},
		.num_parents = 1,
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_regmap_div_ops,
	},
};

static struct clk_regmap_div nss_cc_port3_rx_div_clk_src = {
	.reg = 0x4ec,
	.shift = 0,
	.width = 9,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "nss_cc_port3_rx_div_clk_src",
		.parent_hws = (const struct clk_hw*[]){
			&nss_cc_port3_rx_clk_src.clkr.hw,
		},
		.num_parents = 1,
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_regmap_div_ops,
	},
};

static struct clk_regmap_div nss_cc_port3_tx_div_clk_src = {
	.reg = 0x4f8,
	.shift = 0,
	.width = 9,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "nss_cc_port3_tx_div_clk_src",
		.parent_hws = (const struct clk_hw*[]){
			&nss_cc_port3_tx_clk_src.clkr.hw,
		},
		.num_parents = 1,
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_regmap_div_ops,
	},
};

static struct clk_regmap_div nss_cc_xgmac0_ptp_ref_div_clk_src = {
	.reg = 0x3f4,
	.shift = 0,
	.width = 4,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "nss_cc_xgmac0_ptp_ref_div_clk_src",
		.parent_hws = (const struct clk_hw*[]){
			&nss_cc_ppe_clk_src.clkr.hw,
		},
		.num_parents = 1,
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_regmap_div_ro_ops,
	},
};

static struct clk_regmap_div nss_cc_xgmac1_ptp_ref_div_clk_src = {
	.reg = 0x3f8,
	.shift = 0,
	.width = 4,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "nss_cc_xgmac1_ptp_ref_div_clk_src",
		.parent_hws = (const struct clk_hw*[]){
			&nss_cc_ppe_clk_src.clkr.hw,
		},
		.num_parents = 1,
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_regmap_div_ro_ops,
	},
};

static struct clk_regmap_div nss_cc_xgmac2_ptp_ref_div_clk_src = {
	.reg = 0x3fc,
	.shift = 0,
	.width = 4,
	.clkr.hw.init = &(const struct clk_init_data) {
		.name = "nss_cc_xgmac2_ptp_ref_div_clk_src",
		.parent_hws = (const struct clk_hw*[]){
			&nss_cc_ppe_clk_src.clkr.hw,
		},
		.num_parents = 1,
		.flags = CLK_SET_RATE_PARENT,
		.ops = &clk_regmap_div_ro_ops,
	},
};

static struct clk_branch nss_cc_ce_apb_clk = {
	.halt_reg = 0x5e8,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x5e8,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_ce_apb_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_ce_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_ce_axi_clk = {
	.halt_reg = 0x5ec,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x5ec,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_ce_axi_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_ce_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_debug_clk = {
	.halt_reg = 0x70c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x70c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_debug_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_eip_clk = {
	.halt_reg = 0x658,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x658,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_eip_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_eip_bfdcd_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_nss_csr_clk = {
	.halt_reg = 0x6b0,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x6b0,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_nss_csr_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_cfg_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_nssnoc_ce_apb_clk = {
	.halt_reg = 0x5f4,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x5f4,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_nssnoc_ce_apb_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_ce_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_nssnoc_ce_axi_clk = {
	.halt_reg = 0x5f8,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x5f8,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_nssnoc_ce_axi_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_ce_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_nssnoc_eip_clk = {
	.halt_reg = 0x660,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x660,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_nssnoc_eip_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_eip_bfdcd_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_nssnoc_nss_csr_clk = {
	.halt_reg = 0x6b4,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x6b4,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_nssnoc_nss_csr_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_cfg_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_nssnoc_ppe_cfg_clk = {
	.halt_reg = 0x444,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x444,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_nssnoc_ppe_cfg_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_ppe_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_nssnoc_ppe_clk = {
	.halt_reg = 0x440,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x440,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_nssnoc_ppe_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_ppe_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_port1_mac_clk = {
	.halt_reg = 0x428,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x428,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_port1_mac_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_ppe_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_port1_rx_clk = {
	.halt_reg = 0x4fc,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x4fc,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_port1_rx_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_port1_rx_div_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_port1_tx_clk = {
	.halt_reg = 0x504,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x504,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_port1_tx_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_port1_tx_div_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_port2_mac_clk = {
	.halt_reg = 0x430,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x430,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_port2_mac_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_ppe_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_port2_rx_clk = {
	.halt_reg = 0x50c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x50c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_port2_rx_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_port2_rx_div_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_port2_tx_clk = {
	.halt_reg = 0x514,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x514,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_port2_tx_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_port2_tx_div_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_port3_mac_clk = {
	.halt_reg = 0x438,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x438,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_port3_mac_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_ppe_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_port3_rx_clk = {
	.halt_reg = 0x51c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x51c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_port3_rx_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_port3_rx_div_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_port3_tx_clk = {
	.halt_reg = 0x524,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x524,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_port3_tx_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_port3_tx_div_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};


static struct clk_branch nss_cc_ppe_edma_cfg_clk = {
	.halt_reg = 0x424,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x424,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_ppe_edma_cfg_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_ppe_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_ppe_edma_clk = {
	.halt_reg = 0x41c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x41c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_ppe_edma_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_ppe_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_ppe_switch_btq_clk = {
	.halt_reg = 0x408,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x408,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_ppe_switch_btq_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_ppe_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_ppe_switch_cfg_clk = {
	.halt_reg = 0x418,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x418,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_ppe_switch_cfg_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_ppe_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_ppe_switch_clk = {
	.halt_reg = 0x410,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x410,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_ppe_switch_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_ppe_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_ppe_switch_ipe_clk = {
	.halt_reg = 0x400,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x400,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_ppe_switch_ipe_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_ppe_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_uniphy_port1_rx_clk = {
	.halt_reg = 0x57c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x57c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_uniphy_port1_rx_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_port1_rx_div_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_uniphy_port1_tx_clk = {
	.halt_reg = 0x580,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x580,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_uniphy_port1_tx_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_port1_tx_div_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_uniphy_port2_rx_clk = {
	.halt_reg = 0x584,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x584,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_uniphy_port2_rx_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_port2_rx_div_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_uniphy_port2_tx_clk = {
	.halt_reg = 0x588,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x588,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_uniphy_port2_tx_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_port2_tx_div_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_uniphy_port3_rx_clk = {
	.halt_reg = 0x58c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x58c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_uniphy_port3_rx_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_port3_rx_div_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_uniphy_port3_tx_clk = {
	.halt_reg = 0x590,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x590,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_uniphy_port3_tx_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_port3_tx_div_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_xgmac0_ptp_ref_clk = {
	.halt_reg = 0x448,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x448,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_xgmac0_ptp_ref_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_xgmac0_ptp_ref_div_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_xgmac1_ptp_ref_clk = {
	.halt_reg = 0x44c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x44c,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_xgmac1_ptp_ref_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_xgmac1_ptp_ref_div_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch nss_cc_xgmac2_ptp_ref_clk = {
	.halt_reg = 0x450,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x450,
		.enable_mask = BIT(0),
		.hw.init = &(const struct clk_init_data){
			.name = "nss_cc_xgmac2_ptp_ref_clk",
			.parent_hws = (const struct clk_hw*[]){
				&nss_cc_xgmac2_ptp_ref_div_clk_src.clkr.hw,
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static int clk_dummy_is_enabled(struct clk_hw *hw)
{
	return 1;
};

static int clk_dummy_enable(struct clk_hw *hw)
{
	return 0;
};

static void clk_dummy_disable(struct clk_hw *hw)
{
	return;
};

static u8 clk_dummy_get_parent(struct clk_hw *hw)
{
	return 0;
};

static int clk_dummy_set_parent(struct clk_hw *hw, u8 index)
{
	return 0;
};

static int clk_dummy_set_rate(struct clk_hw *hw, unsigned long rate,
			      unsigned long parent_rate)
{
	return 0;
};

static int clk_dummy_determine_rate(struct clk_hw *hw,
				struct clk_rate_request *req)
{
	return 0;
};

static unsigned long clk_dummy_recalc_rate(struct clk_hw *hw,
					   unsigned long parent_rate)
{
	return parent_rate;
};

static const struct clk_ops clk_dummy_ops = {
	.is_enabled = clk_dummy_is_enabled,
	.enable = clk_dummy_enable,
	.disable = clk_dummy_disable,
	.get_parent = clk_dummy_get_parent,
	.set_parent = clk_dummy_set_parent,
	.set_rate = clk_dummy_set_rate,
	.recalc_rate = clk_dummy_recalc_rate,
	.determine_rate = clk_dummy_determine_rate,
};

#define DEFINE_DUMMY_CLK(clk_name)				\
(&(struct clk_regmap) {						\
	.hw.init = &(struct clk_init_data){			\
		.name = #clk_name,				\
		.parent_names = (const char *[]){ "xo"},	\
		.num_parents = 1,				\
		.ops = &clk_dummy_ops,				\
	},							\
})

static struct clk_regmap *nss_cc_ipq54xx_dummy_clocks[] = {
	[NSS_CC_CE_APB_CLK] = DEFINE_DUMMY_CLK(nss_cc_ce_apb_clk),
	[NSS_CC_CE_AXI_CLK] = DEFINE_DUMMY_CLK(nss_cc_ce_axi_clk),
	[NSS_CC_CE_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_ce_clk_src),
	[NSS_CC_CFG_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_cfg_clk_src),
	[NSS_CC_DEBUG_CLK] = DEFINE_DUMMY_CLK(nss_cc_debug_clk),
	[NSS_CC_EIP_BFDCD_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_eip_bfdcd_clk_src),
	[NSS_CC_EIP_CLK] = DEFINE_DUMMY_CLK(nss_cc_eip_clk),
	[NSS_CC_NSS_CSR_CLK] = DEFINE_DUMMY_CLK(nss_cc_nss_csr_clk),
	[NSS_CC_NSSNOC_CE_APB_CLK] = DEFINE_DUMMY_CLK(nss_cc_nssnoc_ce_apb_clk),
	[NSS_CC_NSSNOC_CE_AXI_CLK] = DEFINE_DUMMY_CLK(nss_cc_nssnoc_ce_axi_clk),
	[NSS_CC_NSSNOC_EIP_CLK] = DEFINE_DUMMY_CLK(nss_cc_nssnoc_eip_clk),
	[NSS_CC_NSSNOC_NSS_CSR_CLK] = DEFINE_DUMMY_CLK(nss_cc_nssnoc_nss_csr_clk),
	[NSS_CC_NSSNOC_PPE_CFG_CLK] = DEFINE_DUMMY_CLK(nss_cc_nssnoc_ppe_cfg_clk),
	[NSS_CC_NSSNOC_PPE_CLK] = DEFINE_DUMMY_CLK(nss_cc_nssnoc_ppe_clk),
	[NSS_CC_PORT1_MAC_CLK] = DEFINE_DUMMY_CLK(nss_cc_port1_mac_clk),
	[NSS_CC_PORT1_RX_CLK] = DEFINE_DUMMY_CLK(nss_cc_port1_rx_clk),
	[NSS_CC_PORT1_RX_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_port1_rx_clk_src),
	[NSS_CC_PORT1_RX_DIV_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_port1_rx_div_clk_src),
	[NSS_CC_PORT1_TX_CLK] = DEFINE_DUMMY_CLK(nss_cc_port1_tx_clk),
	[NSS_CC_PORT1_TX_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_port1_tx_clk_src),
	[NSS_CC_PORT1_TX_DIV_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_port1_tx_div_clk_src),
	[NSS_CC_PORT2_MAC_CLK] = DEFINE_DUMMY_CLK(nss_cc_port2_mac_clk),
	[NSS_CC_PORT2_RX_CLK] = DEFINE_DUMMY_CLK(nss_cc_port2_rx_clk),
	[NSS_CC_PORT2_RX_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_port2_rx_clk_src),
	[NSS_CC_PORT2_RX_DIV_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_port2_rx_div_clk_src),
	[NSS_CC_PORT2_TX_CLK] = DEFINE_DUMMY_CLK(nss_cc_port2_tx_clk),
	[NSS_CC_PORT2_TX_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_port2_tx_clk_src),
	[NSS_CC_PORT2_TX_DIV_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_port2_tx_div_clk_src),
	[NSS_CC_PORT3_MAC_CLK] = DEFINE_DUMMY_CLK(nss_cc_port3_mac_clk),
	[NSS_CC_PORT3_RX_CLK] = DEFINE_DUMMY_CLK(nss_cc_port3_rx_clk),
	[NSS_CC_PORT3_RX_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_port3_rx_clk_src),
	[NSS_CC_PORT3_RX_DIV_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_port3_rx_div_clk_src),
	[NSS_CC_PORT3_TX_CLK] = DEFINE_DUMMY_CLK(nss_cc_port3_tx_clk),
	[NSS_CC_PORT3_TX_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_port3_tx_clk_src),
	[NSS_CC_PORT3_TX_DIV_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_port3_tx_div_clk_src),
	[NSS_CC_PPE_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_ppe_clk_src),
	[NSS_CC_PPE_EDMA_CFG_CLK] = DEFINE_DUMMY_CLK(nss_cc_ppe_edma_cfg_clk),
	[NSS_CC_PPE_EDMA_CLK] = DEFINE_DUMMY_CLK(nss_cc_ppe_edma_clk),
	[NSS_CC_PPE_SWITCH_BTQ_CLK] = DEFINE_DUMMY_CLK(nss_cc_ppe_switch_btq_clk),
	[NSS_CC_PPE_SWITCH_CFG_CLK] = DEFINE_DUMMY_CLK(nss_cc_ppe_switch_cfg_clk),
	[NSS_CC_PPE_SWITCH_CLK] = DEFINE_DUMMY_CLK(nss_cc_ppe_switch_clk),
	[NSS_CC_PPE_SWITCH_IPE_CLK] = DEFINE_DUMMY_CLK(nss_cc_ppe_switch_ipe_clk),
	[NSS_CC_UNIPHY_PORT1_RX_CLK] = DEFINE_DUMMY_CLK(nss_cc_uniphy_port1_rx_clk),
	[NSS_CC_UNIPHY_PORT1_TX_CLK] = DEFINE_DUMMY_CLK(nss_cc_uniphy_port1_tx_clk),
	[NSS_CC_UNIPHY_PORT2_RX_CLK] = DEFINE_DUMMY_CLK(nss_cc_uniphy_port2_rx_clk),
	[NSS_CC_UNIPHY_PORT2_TX_CLK] = DEFINE_DUMMY_CLK(nss_cc_uniphy_port2_tx_clk),
	[NSS_CC_UNIPHY_PORT3_RX_CLK] = DEFINE_DUMMY_CLK(nss_cc_uniphy_port3_rx_clk),
	[NSS_CC_UNIPHY_PORT3_TX_CLK] = DEFINE_DUMMY_CLK(nss_cc_uniphy_port3_tx_clk),
	[NSS_CC_XGMAC0_PTP_REF_CLK] = DEFINE_DUMMY_CLK(nss_cc_xgmac0_ptp_ref_clk),
	[NSS_CC_XGMAC0_PTP_REF_DIV_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_xgmac0_ptp_ref_div_clk_src),
	[NSS_CC_XGMAC1_PTP_REF_CLK] = DEFINE_DUMMY_CLK(nss_cc_xgmac1_ptp_ref_clk),
	[NSS_CC_XGMAC1_PTP_REF_DIV_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_xgmac1_ptp_ref_div_clk_src),
	[NSS_CC_XGMAC2_PTP_REF_CLK] = DEFINE_DUMMY_CLK(nss_cc_xgmac2_ptp_ref_clk),
	[NSS_CC_XGMAC2_PTP_REF_DIV_CLK_SRC] = DEFINE_DUMMY_CLK(nss_cc_xgmac2_ptp_ref_div_clk_src),
};

static struct clk_regmap *nss_cc_ipq54xx_clocks[] = {
	[NSS_CC_CE_APB_CLK] = &nss_cc_ce_apb_clk.clkr,
	[NSS_CC_CE_AXI_CLK] = &nss_cc_ce_axi_clk.clkr,
	[NSS_CC_CE_CLK_SRC] = &nss_cc_ce_clk_src.clkr,
	[NSS_CC_CFG_CLK_SRC] = &nss_cc_cfg_clk_src.clkr,
	[NSS_CC_DEBUG_CLK] = &nss_cc_debug_clk.clkr,
	[NSS_CC_EIP_BFDCD_CLK_SRC] = &nss_cc_eip_bfdcd_clk_src.clkr,
	[NSS_CC_EIP_CLK] = &nss_cc_eip_clk.clkr,
	[NSS_CC_NSS_CSR_CLK] = &nss_cc_nss_csr_clk.clkr,
	[NSS_CC_NSSNOC_CE_APB_CLK] = &nss_cc_nssnoc_ce_apb_clk.clkr,
	[NSS_CC_NSSNOC_CE_AXI_CLK] = &nss_cc_nssnoc_ce_axi_clk.clkr,
	[NSS_CC_NSSNOC_EIP_CLK] = &nss_cc_nssnoc_eip_clk.clkr,
	[NSS_CC_NSSNOC_NSS_CSR_CLK] = &nss_cc_nssnoc_nss_csr_clk.clkr,
	[NSS_CC_NSSNOC_PPE_CFG_CLK] = &nss_cc_nssnoc_ppe_cfg_clk.clkr,
	[NSS_CC_NSSNOC_PPE_CLK] = &nss_cc_nssnoc_ppe_clk.clkr,
	[NSS_CC_PORT1_MAC_CLK] = &nss_cc_port1_mac_clk.clkr,
	[NSS_CC_PORT1_RX_CLK] = &nss_cc_port1_rx_clk.clkr,
	[NSS_CC_PORT1_RX_CLK_SRC] = &nss_cc_port1_rx_clk_src.clkr,
	[NSS_CC_PORT1_RX_DIV_CLK_SRC] = &nss_cc_port1_rx_div_clk_src.clkr,
	[NSS_CC_PORT1_TX_CLK] = &nss_cc_port1_tx_clk.clkr,
	[NSS_CC_PORT1_TX_CLK_SRC] = &nss_cc_port1_tx_clk_src.clkr,
	[NSS_CC_PORT1_TX_DIV_CLK_SRC] = &nss_cc_port1_tx_div_clk_src.clkr,
	[NSS_CC_PORT2_MAC_CLK] = &nss_cc_port2_mac_clk.clkr,
	[NSS_CC_PORT2_RX_CLK] = &nss_cc_port2_rx_clk.clkr,
	[NSS_CC_PORT2_RX_CLK_SRC] = &nss_cc_port2_rx_clk_src.clkr,
	[NSS_CC_PORT2_RX_DIV_CLK_SRC] = &nss_cc_port2_rx_div_clk_src.clkr,
	[NSS_CC_PORT2_TX_CLK] = &nss_cc_port2_tx_clk.clkr,
	[NSS_CC_PORT2_TX_CLK_SRC] = &nss_cc_port2_tx_clk_src.clkr,
	[NSS_CC_PORT2_TX_DIV_CLK_SRC] = &nss_cc_port2_tx_div_clk_src.clkr,
	[NSS_CC_PORT3_MAC_CLK] = &nss_cc_port3_mac_clk.clkr,
	[NSS_CC_PORT3_RX_CLK] = &nss_cc_port3_rx_clk.clkr,
	[NSS_CC_PORT3_RX_CLK_SRC] = &nss_cc_port3_rx_clk_src.clkr,
	[NSS_CC_PORT3_RX_DIV_CLK_SRC] = &nss_cc_port3_rx_div_clk_src.clkr,
	[NSS_CC_PORT3_TX_CLK] = &nss_cc_port3_tx_clk.clkr,
	[NSS_CC_PORT3_TX_CLK_SRC] = &nss_cc_port3_tx_clk_src.clkr,
	[NSS_CC_PORT3_TX_DIV_CLK_SRC] = &nss_cc_port3_tx_div_clk_src.clkr,
	[NSS_CC_PPE_CLK_SRC] = &nss_cc_ppe_clk_src.clkr,
	[NSS_CC_PPE_EDMA_CFG_CLK] = &nss_cc_ppe_edma_cfg_clk.clkr,
	[NSS_CC_PPE_EDMA_CLK] = &nss_cc_ppe_edma_clk.clkr,
	[NSS_CC_PPE_SWITCH_BTQ_CLK] = &nss_cc_ppe_switch_btq_clk.clkr,
	[NSS_CC_PPE_SWITCH_CFG_CLK] = &nss_cc_ppe_switch_cfg_clk.clkr,
	[NSS_CC_PPE_SWITCH_CLK] = &nss_cc_ppe_switch_clk.clkr,
	[NSS_CC_PPE_SWITCH_IPE_CLK] = &nss_cc_ppe_switch_ipe_clk.clkr,
	[NSS_CC_UNIPHY_PORT1_RX_CLK] = &nss_cc_uniphy_port1_rx_clk.clkr,
	[NSS_CC_UNIPHY_PORT1_TX_CLK] = &nss_cc_uniphy_port1_tx_clk.clkr,
	[NSS_CC_UNIPHY_PORT2_RX_CLK] = &nss_cc_uniphy_port2_rx_clk.clkr,
	[NSS_CC_UNIPHY_PORT2_TX_CLK] = &nss_cc_uniphy_port2_tx_clk.clkr,
	[NSS_CC_UNIPHY_PORT3_RX_CLK] = &nss_cc_uniphy_port3_rx_clk.clkr,
	[NSS_CC_UNIPHY_PORT3_TX_CLK] = &nss_cc_uniphy_port3_tx_clk.clkr,
	[NSS_CC_XGMAC0_PTP_REF_CLK] = &nss_cc_xgmac0_ptp_ref_clk.clkr,
	[NSS_CC_XGMAC0_PTP_REF_DIV_CLK_SRC] = &nss_cc_xgmac0_ptp_ref_div_clk_src.clkr,
	[NSS_CC_XGMAC1_PTP_REF_CLK] = &nss_cc_xgmac1_ptp_ref_clk.clkr,
	[NSS_CC_XGMAC1_PTP_REF_DIV_CLK_SRC] = &nss_cc_xgmac1_ptp_ref_div_clk_src.clkr,
	[NSS_CC_XGMAC2_PTP_REF_CLK] = &nss_cc_xgmac2_ptp_ref_clk.clkr,
	[NSS_CC_XGMAC2_PTP_REF_DIV_CLK_SRC] = &nss_cc_xgmac2_ptp_ref_div_clk_src.clkr,
};

static const struct qcom_reset_map nss_cc_ipq54xx_resets[] = {
	[NSS_CC_CE_APB_CLK_ARES] = { 0x5e8, 2 },
	[NSS_CC_CE_AXI_CLK_ARES] = { 0x5ec, 2 },
	[NSS_CC_DEBUG_CLK_ARES] = { 0x70c, 2 },
	[NSS_CC_EIP_CLK_ARES] = { 0x658, 2 },
	[NSS_CC_NSS_CSR_CLK_ARES] = { 0x6b0, 2 },
	[NSS_CC_NSSNOC_CE_APB_CLK_ARES] = { 0x5f4, 2 },
	[NSS_CC_NSSNOC_CE_AXI_CLK_ARES] = { 0x5f8, 2 },
	[NSS_CC_NSSNOC_EIP_CLK_ARES] = { 0x660, 2 },
	[NSS_CC_NSSNOC_NSS_CSR_CLK_ARES] = { 0x6b4, 2 },
	[NSS_CC_NSSNOC_PPE_CLK_ARES] = { 0x440, 2 },
	[NSS_CC_NSSNOC_PPE_CFG_CLK_ARES] = { 0x444, 2 },
	[NSS_CC_PORT1_MAC_CLK_ARES] = { 0x428, 2 },
	[NSS_CC_PORT1_RX_CLK_ARES] = { 0x4fc, 2 },
	[NSS_CC_PORT1_TX_CLK_ARES] = { 0x504, 2 },
	[NSS_CC_PORT2_MAC_CLK_ARES] = { 0x430, 2 },
	[NSS_CC_PORT2_RX_CLK_ARES] = { 0x50c, 2 },
	[NSS_CC_PORT2_TX_CLK_ARES] = { 0x514, 2 },
	[NSS_CC_PORT3_MAC_CLK_ARES] = { 0x438, 2 },
	[NSS_CC_PORT3_RX_CLK_ARES] = { 0x51c, 2 },
	[NSS_CC_PORT3_TX_CLK_ARES] = { 0x524, 2 },
	[NSS_CC_PPE_BCR] = { 0x3e8 },
	[NSS_CC_PPE_EDMA_CLK_ARES] = { 0x41c, 2 },
	[NSS_CC_PPE_EDMA_CFG_CLK_ARES] = { 0x424, 2 },
	[NSS_CC_PPE_SWITCH_BTQ_CLK_ARES] = { 0x408, 2 },
	[NSS_CC_PPE_SWITCH_CLK_ARES] = { 0x410, 2 },
	[NSS_CC_PPE_SWITCH_CFG_CLK_ARES] = { 0x418, 2 },
	[NSS_CC_PPE_SWITCH_IPE_CLK_ARES] = { 0x400, 2 },
	[NSS_CC_UNIPHY_PORT1_RX_CLK_ARES] = { 0x57c, 2 },
	[NSS_CC_UNIPHY_PORT1_TX_CLK_ARES] = { 0x580, 2 },
	[NSS_CC_UNIPHY_PORT2_RX_CLK_ARES] = { 0x584, 2 },
	[NSS_CC_UNIPHY_PORT2_TX_CLK_ARES] = { 0x588, 2 },
	[NSS_CC_UNIPHY_PORT3_RX_CLK_ARES] = { 0x58c, 2 },
	[NSS_CC_UNIPHY_PORT3_TX_CLK_ARES] = { 0x590, 2 },
	[NSS_CC_XGMAC0_PTP_REF_CLK_ARES] = { 0x448, 2 },
	[NSS_CC_XGMAC1_PTP_REF_CLK_ARES] = { 0x44c, 2 },
	[NSS_CC_XGMAC2_PTP_REF_CLK_ARES] = { 0x450, 2 },
};

static const struct regmap_config nss_cc_ipq54xx_regmap_config = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
	.max_register = 0x800,
	.fast_io = true,
};

static const struct qcom_cc_desc nss_cc_ipq54xx_desc = {
	.config = &nss_cc_ipq54xx_regmap_config,
	.clks = nss_cc_ipq54xx_clocks,
	.num_clks = ARRAY_SIZE(nss_cc_ipq54xx_clocks),
	.resets = nss_cc_ipq54xx_resets,
	.num_resets = ARRAY_SIZE(nss_cc_ipq54xx_resets),
};

static const struct qcom_cc_desc nss_cc_ipq54xx_dummy_desc = {
	.config = &nss_cc_ipq54xx_regmap_config,
	.clks = nss_cc_ipq54xx_dummy_clocks,
	.num_clks = ARRAY_SIZE(nss_cc_ipq54xx_dummy_clocks),
	.resets = nss_cc_ipq54xx_resets,
	.num_resets = ARRAY_SIZE(nss_cc_ipq54xx_resets),
};

static const struct of_device_id nss_cc_ipq54xx_match_table[] = {
	{ .compatible = "qcom,ipq54xx-nsscc" },
	{ }
};
MODULE_DEVICE_TABLE(of, nss_cc_ipq54xx_match_table);

static int nss_cc_ipq54xx_probe(struct platform_device *pdev)
{
	struct qcom_cc_desc desc = nss_cc_ipq54xx_desc;
	struct device_node *np = (&pdev->dev)->of_node;
	struct regmap *regmap;
	int ret;

	if (of_property_read_bool(np, "nsscc-use-dummy"))
		desc = nss_cc_ipq54xx_dummy_desc;

	regmap = qcom_cc_map(pdev, &desc);
	if (IS_ERR(regmap))
		return PTR_ERR(regmap);


	ret = qcom_cc_really_probe(pdev, &desc, regmap);
	if (ret) {
		dev_err(&pdev->dev, "Failed to register NSS CC clocks\n");
		return ret;
	}

	dev_info(&pdev->dev, "Registered NSS CC clocks\n");

	return ret;
}

static struct platform_driver nss_cc_ipq54xx_driver = {
	.probe = nss_cc_ipq54xx_probe,
	.driver = {
		.name = "qcom,ipq54xx-nsscc",
		.of_match_table = nss_cc_ipq54xx_match_table,
	},
};

static int __init nss_cc_ipq54xx_init(void)
{
	return platform_driver_register(&nss_cc_ipq54xx_driver);
}
core_initcall(nss_cc_ipq54xx_init);

static void __exit nss_cc_ipq54xx_exit(void)
{
	platform_driver_unregister(&nss_cc_ipq54xx_driver);
}
module_exit(nss_cc_ipq54xx_exit);

MODULE_DESCRIPTION("Qualcomm Technologies, Inc. NSSCC IPQ5424 Driver");
MODULE_LICENSE("GPL v2");
