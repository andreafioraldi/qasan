#ifndef __XSCOM_P9_REGS_H__
#define __XSCOM_P9_REGS_H__

/* EX (core pair) registers, use XSCOM_ADDR_P9_EX to access */
#define P9X_EX_NCU_STATUS_REG			0x1100f
#define P9X_EX_NCU_SPEC_BAR			0x11010
#define   P9X_EX_NCU_SPEC_BAR_ENABLE		PPC_BIT(0)
#define   P9X_EX_NCU_SPEC_BAR_256K		PPC_BIT(1)
#define   P9X_EX_NCU_SPEC_BAR_ADDRMSK		0x0fffffffffffc000ull /* naturally aligned */

#define P9X_NX_MMIO_BAR				0x201108d
#define  P9X_NX_MMIO_BAR_EN			PPC_BIT(52)
#define  P9X_NX_MMIO_OFFSET			0x00060302031d0000ull

#define P9X_NX_RNG_CFG				0x20110E0
#define  P9X_NX_RNG_CFG_EN			PPC_BIT(63)

#define P9X_EX_NCU_DARN_BAR			0x11011
#define  P9X_EX_NCU_DARN_BAR_EN			PPC_BIT(0)

#define P9_GPIO_DATA_OUT_ENABLE			0x00000000000B0054ull
#define P9_GPIO_DATA_OUT			0x00000000000B0051ull

#endif /* __XSCOM_P9_REGS_H__ */
