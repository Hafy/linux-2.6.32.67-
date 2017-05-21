#ifndef __MATROXFB_DAC1064_H__
#define __MATROXFB_DAC1064_H__


#include "matroxfb_base.h"

#ifdef CONFIG_FB_MATROX_MYSTIQUE
extern struct matrox_switch matrox_mystique;
#endif
#ifdef CONFIG_FB_MATROX_G
extern struct matrox_switch matrox_G100;
#endif
#ifdef NEED_DAC1064
void DAC1064_global_init(struct matrox_fb_info *minfo);
void DAC1064_global_restore(struct matrox_fb_info *minfo);
#endif

#define M1064_INDEX	0x00
#define M1064_PALWRADD	0x00
#define M1064_PALDATA	0x01
#define M1064_PIXRDMSK	0x02
#define M1064_PALRDADD	0x03
#define M1064_X_DATAREG	0x0A
#define M1064_CURPOSXL	0x0C	/* can be accessed as DWORD */
#define M1064_CURPOSXH	0x0D
#define M1064_CURPOSYL	0x0E
#define M1064_CURPOSYH	0x0F

#define M1064_XCURADDL		0x04
#define M1064_XCURADDH		0x05
#define M1064_XCURCTRL		0x06
#define     M1064_XCURCTRL_DIS		0x00	/* transparent, transparent, transparent, transparent */
#define     M1064_XCURCTRL_3COLOR	0x01	/* transparent, 0, 1, 2 */
#define     M1064_XCURCTRL_XGA		0x02	/* 0, 1, transparent, complement */
#define     M1064_XCURCTRL_XWIN		0x03	/* transparent, transparent, 0, 1 */
	/* drive DVI by standard(0)/DVI(1) PLL */
	/* if set(1), C?DVICLKEN and C?DVICLKSEL must be set(1) */
#define      M1064_XDVICLKCTRL_DVIDATAPATHSEL   0x01
	/* drive CRTC1 by standard(0)/DVI(1) PLL */
#define      M1064_XDVICLKCTRL_C1DVICLKSEL      0x02
	/* drive CRTC2 by standard(0)/DVI(1) PLL */
#define      M1064_XDVICLKCTRL_C2DVICLKSEL      0x04
	/* pixel clock allowed to(0)/blocked from(1) driving CRTC1 */
#define      M1064_XDVICLKCTRL_C1DVICLKEN       0x08
	/* DVI PLL loop filter bandwidth selection bits */
#define      M1064_XDVICLKCTRL_DVILOOPCTL       0x30
	/* CRTC2 pixel clock allowed to(0)/blocked from(1) driving CRTC2 */
#define      M1064_XDVICLKCTRL_C2DVICLKEN       0x40
	/* P1PLL loop filter bandwith selection */
#define      M1064_XDVICLKCTRL_P1LOOPBWDTCTL    0x80
#define M1064_XCURCOL0RED	0x08
#define M1064_XCURCOL0GREEN	0x09
#define M1064_XCURCOL0BLUE	0x0A
#define M1064_XCURCOL1RED	0x0C
#define M1064_XCURCOL1GREEN	0x0D
#define M1064_XCURCOL1BLUE	0x0E
#define M1064_XDVICLKCTRL	0x0F
#define M1064_XCURCOL2RED	0x10
#define M1064_XCURCOL2GREEN	0x11
#define M1064_XCURCOL2BLUE	0x12
#define DAC1064_XVREFCTRL	0x18
#define      DAC1064_XVREFCTRL_INTERNAL		0x3F
#define      DAC1064_XVREFCTRL_EXTERNAL		0x00
#define      DAC1064_XVREFCTRL_G100_DEFAULT	0x03
#define M1064_XMULCTRL		0x19
#define      M1064_XMULCTRL_DEPTH_8BPP		0x00	/* 8 bpp paletized */
#define      M1064_XMULCTRL_DEPTH_15BPP_1BPP	0x01	/* 15 bpp paletized + 1 bpp overlay */
#define      M1064_XMULCTRL_DEPTH_16BPP		0x02	/* 16 bpp paletized */
#define      M1064_XMULCTRL_DEPTH_24BPP		0x03	/* 24 bpp paletized */
#define      M1064_XMULCTRL_DEPTH_24BPP_8BPP	0x04	/* 24 bpp direct + 8 bpp overlay paletized */
#define      M1064_XMULCTRL_2G8V16		0x05	/* 15 bpp video direct, half xres, 8bpp paletized */
#define      M1064_XMULCTRL_G16V16		0x06	/* 15 bpp video, 15bpp graphics, one of them paletized */
#define      M1064_XMULCTRL_DEPTH_32BPP		0x07	/* 24 bpp paletized + 8 bpp unused */
#define      M1064_XMULCTRL_GRAPHICS_PALETIZED	0x00
#define      M1064_XMULCTRL_VIDEO_PALETIZED	0x08
#define M1064_XPIXCLKCTRL	0x1A
#define      M1064_XPIXCLKCTRL_SRC_PCI		0x00
#define      M1064_XPIXCLKCTRL_SRC_PLL		0x01
#define      M1064_XPIXCLKCTRL_SRC_EXT		0x02
#define	     M1064_XPIXCLKCTRL_SRC_SYS		0x03	/* G200/G400 */
#define      M1064_XPIXCLKCTRL_SRC_PLL2		0x03	/* G450 */
#define      M1064_XPIXCLKCTRL_SRC_MASK		0x03
#define      M1064_XPIXCLKCTRL_EN		0x00
#define      M1064_XPIXCLKCTRL_DIS		0x04
#define      M1064_XPIXCLKCTRL_PLL_DOWN		0x00
#define      M1064_XPIXCLKCTRL_PLL_UP		0x08
#define M1064_XGENCTRL		0x1D
#define      M1064_XGENCTRL_VS_0		0x00
#define      M1064_XGENCTRL_VS_1		0x01
#define      M1064_XGENCTRL_ALPHA_DIS		0x00
#define      M1064_XGENCTRL_ALPHA_EN		0x02
#define      M1064_XGENCTRL_BLACK_0IRE		0x00
#define      M1064_XGENCTRL_BLACK_75IRE		0x10
#define      M1064_XGENCTRL_SYNC_ON_GREEN	0x00
#define      M1064_XGENCTRL_NO_SYNC_ON_GREEN	0x20
#define      M1064_XGENCTRL_SYNC_ON_GREEN_MASK	0x20
#define M1064_XMISCCTRL		0x1E
#define      M1064_XMISCCTRL_DAC_DIS		0x00
#define      M1064_XMISCCTRL_DAC_EN		0x01
#define      M1064_XMISCCTRL_MFC_VGA		0x00
#define      M1064_XMISCCTRL_MFC_MAFC		0x02
#define      M1064_XMISCCTRL_MFC_DIS		0x06
#define      GX00_XMISCCTRL_MFC_MAFC		0x02
#define      GX00_XMISCCTRL_MFC_PANELLINK	0x04
#define      GX00_XMISCCTRL_MFC_DIS		0x06
#define      GX00_XMISCCTRL_MFC_MASK		0x06
#define      M1064_XMISCCTRL_DAC_6BIT		0x00
#define      M1064_XMISCCTRL_DAC_8BIT		0x08
#define      M1064_XMISCCTRL_DAC_WIDTHMASK	0x08
#define      M1064_XMISCCTRL_LUT_DIS		0x00
#define      M1064_XMISCCTRL_LUT_EN		0x10
#define      G400_XMISCCTRL_VDO_MAFC12		0x00
#define      G400_XMISCCTRL_VDO_BYPASS656	0x40
#define      G400_XMISCCTRL_VDO_C2_MAFC12	0x80
#define      G400_XMISCCTRL_VDO_C2_BYPASS656	0xC0
#define      G400_XMISCCTRL_VDO_MASK		0xE0
#define M1064_XGENIOCTRL	0x2A
#define M1064_XGENIODATA	0x2B
#define DAC1064_XSYSPLLM	0x2C
#define DAC1064_XSYSPLLN	0x2D
#define DAC1064_XSYSPLLP	0x2E
#define DAC1064_XSYSPLLSTAT	0x2F
#define M1064_XZOOMCTRL		0x38
#define      M1064_XZOOMCTRL_1			0x00
#define      M1064_XZOOMCTRL_2			0x01
#define      M1064_XZOOMCTRL_4			0x03
#define M1064_XSENSETEST	0x3A
#define      M1064_XSENSETEST_BCOMP		0x01
#define      M1064_XSENSETEST_GCOMP		0x02
#define      M1064_XSENSETEST_RCOMP		0x04
#define      M1064_XSENSETEST_PDOWN		0x00
#define      M1064_XSENSETEST_PUP		0x80
#define M1064_XCRCREML		0x3C
#define M1064_XCRCREMH		0x3D
#define M1064_XCRCBITSEL	0x3E
#define M1064_XCOLKEYMASKL	0x40
#define M1064_XCOLKEYMASKH	0x41
#define M1064_XCOLKEYL		0x42
#define M1064_XCOLKEYH		0x43
#define M1064_XPIXPLLAM		0x44
#define M1064_XPIXPLLAN		0x45
#define M1064_XPIXPLLAP		0x46
#define M1064_XPIXPLLBM		0x48
#define M1064_XPIXPLLBN		0x49
#define M1064_XPIXPLLBP		0x4A
#define M1064_XPIXPLLCM		0x4C
#define M1064_XPIXPLLCN		0x4D
#define M1064_XPIXPLLCP		0x4E
#define M1064_XPIXPLLSTAT	0x4F

#define M1064_XTVO_IDX		0x87
#define M1064_XTVO_DATA		0x88

#define M1064_XOUTPUTCONN	0x8A
#define M1064_XSYNCCTRL		0x8B
#define M1064_XVIDPLLSTAT	0x8C
#define M1064_XVIDPLLP		0x8D
#define M1064_XVIDPLLM		0x8E
#define M1064_XVIDPLLN		0x8F

#define M1064_XPWRCTRL		0xA0
#define     M1064_XPWRCTRL_PANELPDN	0x04

#define M1064_XPANMODE		0xA2

enum POS1064 {
	POS1064_XCURADDL=0, POS1064_XCURADDH, POS1064_XCURCTRL,
	POS1064_XCURCOL0RED, POS1064_XCURCOL0GREEN, POS1064_XCURCOL0BLUE,
	POS1064_XCURCOL1RED, POS1064_XCURCOL1GREEN, POS1064_XCURCOL1BLUE,
	POS1064_XCURCOL2RED, POS1064_XCURCOL2GREEN, POS1064_XCURCOL2BLUE,
	POS1064_XVREFCTRL, POS1064_XMULCTRL, POS1064_XPIXCLKCTRL, POS1064_XGENCTRL,
	POS1064_XMISCCTRL,
	POS1064_XGENIOCTRL, POS1064_XGENIODATA, POS1064_XZOOMCTRL, POS1064_XSENSETEST,
	POS1064_XCRCBITSEL,
	POS1064_XCOLKEYMASKL, POS1064_XCOLKEYMASKH, POS1064_XCOLKEYL, POS1064_XCOLKEYH,
	POS1064_XOUTPUTCONN, POS1064_XPANMODE, POS1064_XPWRCTRL };


#endif	/* __MATROXFB_DAC1064_H__ */
