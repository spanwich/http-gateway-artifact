/*
 * E1000Driver.c — CAmkES component: Intel 82540EM Standalone Driver
 *
 * Standalone driver for QEMU's -device e1000 (Intel 82540EM).
 * Uses legacy INTx interrupts, avoiding MSI-X issues with seL4.
 *
 * This replaces the libethdrivers-based e82574 driver with direct
 * hardware access for the simpler 82540EM chip.
 *
 * Receives raw Ethernet frames from e1000 and forwards them via ring buffer
 * dataport to TlsValidator. Reads TX frames from ring buffer dataport and
 * sends them via e1000.
 *
 * Based on Zephyr's eth_e1000.c (Apache 2.0 License)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <camkes.h>
#include <camkes/dma.h>
#include <camkes/io.h>
#include <camkes/irq.h>
#include <sel4/sel4.h>
#include <utils/util.h>
#include <platsupport/io.h>

#include "e1000_hw.h"
#include "web_common.h"

#define COMPONENT_NAME "E1000Driver"

/*
 * PCI Configuration Space Access
 * On x86, PCI config space is accessed via I/O ports 0xCF8 (address) and 0xCFC (data)
 * CAmkES provides pci_config_in/out*_offset() functions with base port 0xCF8
 */

/* PCI config space register offsets */
#define PCI_VENDOR_ID       0x00
#define PCI_DEVICE_ID       0x02
#define PCI_COMMAND         0x04
#define PCI_STATUS          0x06
#define PCI_BAR0            0x10

/* PCI command register bits */
#define PCI_CMD_IO_SPACE    0x0001
#define PCI_CMD_MEM_SPACE   0x0002
#define PCI_CMD_BUS_MASTER  0x0004

/* Intel e1000 IDs */
#define E1000_VENDOR_ID     0x8086
#define E1000_DEVICE_ID     0x100E  /* 82540EM */

/* e1000 PCI location on QEMU q35 (bus 0, device 2, function 0) */
#define E1000_PCI_BUS       0
#define E1000_PCI_DEV       2
#define E1000_PCI_FUN       0

/* Desired BAR0 address - must match CAmkES MMIO config */
#define E1000_BAR0_ADDR     0xfeb80000

/*
 * Read from PCI config space
 * Uses CAmkES-generated pci_config_in/out*_offset() functions
 * Base port is 0xCF8 (address), 0xCFC (data) is at offset 4
 */
static uint32_t pci_cfg_read32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset)
{
    uint32_t addr = (1 << 31) | (bus << 16) | (dev << 11) | (func << 8) | (offset & 0xFC);
    pci_config_out32_offset(0, addr);  /* Write to 0xCF8 */
    return pci_config_in32_offset(4);  /* Read from 0xCFC */
}

static uint16_t pci_cfg_read16(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset)
{
    uint32_t val = pci_cfg_read32(bus, dev, func, offset & 0xFC);
    return (val >> ((offset & 2) * 8)) & 0xFFFF;
}

/*
 * Write to PCI config space
 */
static void pci_cfg_write32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset, uint32_t val)
{
    uint32_t addr = (1 << 31) | (bus << 16) | (dev << 11) | (func << 8) | (offset & 0xFC);
    pci_config_out32_offset(0, addr);  /* Write to 0xCF8 */
    pci_config_out32_offset(4, val);   /* Write to 0xCFC */
}

static void pci_cfg_write16(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset, uint16_t val)
{
    uint32_t addr = (1 << 31) | (bus << 16) | (dev << 11) | (func << 8) | (offset & 0xFC);
    pci_config_out32_offset(0, addr);  /* Write to 0xCF8 */

    /* Read-modify-write for 16-bit access */
    uint32_t old = pci_config_in32_offset(4);  /* Read from 0xCFC */
    int shift = (offset & 2) * 8;
    uint32_t mask = 0xFFFF << shift;
    uint32_t newval = (old & ~mask) | ((uint32_t)val << shift);
    pci_config_out32_offset(4, newval);  /* Write to 0xCFC */
}

/*
 * Initialize PCI device - program BAR and enable device
 */
static int e1000_pci_init(void)
{
    printf("[%s] Initializing PCI for e1000...\n", COMPONENT_NAME);

    /* Read vendor/device ID */
    uint16_t vendor = pci_cfg_read16(E1000_PCI_BUS, E1000_PCI_DEV, E1000_PCI_FUN, PCI_VENDOR_ID);
    uint16_t device = pci_cfg_read16(E1000_PCI_BUS, E1000_PCI_DEV, E1000_PCI_FUN, PCI_DEVICE_ID);

    printf("[%s] PCI device at %d:%d.%d: vendor=0x%04x device=0x%04x\n",
           COMPONENT_NAME, E1000_PCI_BUS, E1000_PCI_DEV, E1000_PCI_FUN, vendor, device);

    if (vendor != E1000_VENDOR_ID || device != E1000_DEVICE_ID) {
        printf("[%s] ERROR: Expected Intel 82540EM (8086:100E), found %04x:%04x\n",
               COMPONENT_NAME, vendor, device);
        return -1;
    }

    /* Read current BAR0 */
    uint32_t bar0 = pci_cfg_read32(E1000_PCI_BUS, E1000_PCI_DEV, E1000_PCI_FUN, PCI_BAR0);
    printf("[%s] Current BAR0 = 0x%08x\n", COMPONENT_NAME, bar0);

    /* Check if BAR0 needs to be programmed */
    if ((bar0 & ~0xF) == 0 || bar0 == 0xFFFFFFFF) {
        printf("[%s] BAR0 not configured, programming to 0x%08x\n", COMPONENT_NAME, E1000_BAR0_ADDR);
        pci_cfg_write32(E1000_PCI_BUS, E1000_PCI_DEV, E1000_PCI_FUN, PCI_BAR0, E1000_BAR0_ADDR);

        /* Verify BAR0 was written */
        bar0 = pci_cfg_read32(E1000_PCI_BUS, E1000_PCI_DEV, E1000_PCI_FUN, PCI_BAR0);
        printf("[%s] BAR0 after programming = 0x%08x\n", COMPONENT_NAME, bar0);
    }

    /* Enable memory space access and bus mastering */
    uint16_t cmd = pci_cfg_read16(E1000_PCI_BUS, E1000_PCI_DEV, E1000_PCI_FUN, PCI_COMMAND);
    printf("[%s] PCI command register = 0x%04x\n", COMPONENT_NAME, cmd);

    cmd |= PCI_CMD_MEM_SPACE | PCI_CMD_BUS_MASTER;
    pci_cfg_write16(E1000_PCI_BUS, E1000_PCI_DEV, E1000_PCI_FUN, PCI_COMMAND, cmd);

    cmd = pci_cfg_read16(E1000_PCI_BUS, E1000_PCI_DEV, E1000_PCI_FUN, PCI_COMMAND);
    printf("[%s] PCI command after enable = 0x%04x (MEM=%d BM=%d)\n",
           COMPONENT_NAME, cmd, !!(cmd & PCI_CMD_MEM_SPACE), !!(cmd & PCI_CMD_BUS_MASTER));

    return 0;
}

/* x86 memory barriers */
#define DMB() __asm__ volatile("mfence" ::: "memory")

/*
 * Driver State
 */
struct e1000_driver {
    /* MMIO base (from CAmkES dataport) */
    volatile void *mmio;

    /* DMA manager */
    ps_dma_man_t dma_manager;

    /* RX descriptor ring */
    struct e1000_rx_desc *rx_ring;
    uintptr_t rx_ring_phys;
    void *rx_bufs[E1000_NUM_RX_DESC];
    uintptr_t rx_buf_phys[E1000_NUM_RX_DESC];
    uint32_t rx_tail;

    /* TX descriptor ring */
    struct e1000_tx_desc *tx_ring;
    uintptr_t tx_ring_phys;
    void *tx_bufs[E1000_NUM_TX_DESC];
    uintptr_t tx_buf_phys[E1000_NUM_TX_DESC];
    uint32_t tx_tail;
    uint32_t tx_head;

    /* MAC address */
    uint8_t mac_addr[6];

    /* Statistics */
    uint32_t rx_pkts;
    uint32_t tx_pkts;
    uint32_t rx_dropped;
    uint32_t irq_count;
    uint32_t rx_errors;
};

static struct e1000_driver g_drv;
static volatile bool driver_ready = false;
static uint32_t debug_dump_count = 0;  /* Track how many dumps we've done */

/* lwIP time tracking */
static volatile uint32_t lwip_time_ms = 0;

uint32_t sys_now(void)
{
    lwip_time_ms++;
    return lwip_time_ms;
}

/*
 * Register access helpers using driver structure
 */
static inline uint32_t e1000_rd(struct e1000_driver *drv, uint32_t reg)
{
    return e1000_read_reg(drv->mmio, reg);
}

static inline void e1000_wr(struct e1000_driver *drv, uint32_t reg, uint32_t val)
{
    e1000_write_reg(drv->mmio, reg, val);
}

/*
 * Parse Ethernet header to identify frame type (for debugging)
 */
static const char *frame_type_str(const unsigned char *buf, unsigned len)
{
    if (len < 14) return "SHORT";
    uint16_t ethertype = ((uint16_t)buf[12] << 8) | buf[13];
    if (ethertype == 0x0806) return "ARP";
    if (ethertype == 0x0800) {
        if (len < 34) return "IP-SHORT";
        uint8_t proto = buf[23];
        if (proto == 6) {
            if (len >= 54) {
                uint8_t flags = buf[47];
                if ((flags & 0x02) && !(flags & 0x10)) return "TCP-SYN";
                if ((flags & 0x02) && (flags & 0x10)) return "TCP-SYNACK";
                if (flags & 0x01) return "TCP-FIN";
                if (flags & 0x04) return "TCP-RST";
                if (flags & 0x10) return "TCP-ACK";
            }
            return "TCP";
        }
        if (proto == 17) return "UDP";
        if (proto == 1) return "ICMP";
        return "IP";
    }
    if (ethertype == 0x86DD) return "IPv6";
    return "OTHER";
}

/*
 * Comprehensive E1000 register and state dump for debugging
 * Call this at init completion and periodically when RX isn't working
 */
static void e1000_debug_dump(struct e1000_driver *drv)
{
    printf("\n========== E1000 COMPREHENSIVE DEBUG DUMP ==========\n");

    /* Control & Status Registers */
    uint32_t ctrl = e1000_rd(drv, E1000_CTRL);
    uint32_t status = e1000_rd(drv, E1000_STATUS);
    printf("=== Control & Status ===\n");
    printf("CTRL=0x%08x (FD=%d SLU=%d RST=%d)\n", ctrl,
           !!(ctrl & E1000_CTRL_FD), !!(ctrl & E1000_CTRL_SLU),
           !!(ctrl & E1000_CTRL_RST));
    printf("STATUS=0x%08x (LU=%d FD=%d SPEED=%d)\n", status,
           !!(status & E1000_STATUS_LU), !!(status & E1000_STATUS_FD),
           (status >> 6) & 0x3);

    /* RX Registers */
    printf("\n=== RX Registers ===\n");
    uint32_t rctl = e1000_rd(drv, E1000_RCTL);
    printf("RCTL=0x%08x (EN=%d BAM=%d UPE=%d MPE=%d SECRC=%d BSIZE=%d)\n",
           rctl,
           !!(rctl & E1000_RCTL_EN),
           !!(rctl & E1000_RCTL_BAM),
           !!(rctl & E1000_RCTL_UPE),
           !!(rctl & E1000_RCTL_MPE),
           !!(rctl & E1000_RCTL_SECRC),
           (rctl >> 16) & 0x3);

    uint32_t rdbal = e1000_rd(drv, E1000_RDBAL);
    uint32_t rdbah = e1000_rd(drv, E1000_RDBAH);
    uint32_t rdlen = e1000_rd(drv, E1000_RDLEN);
    uint32_t rdh = e1000_rd(drv, E1000_RDH);
    uint32_t rdt = e1000_rd(drv, E1000_RDT);
    printf("RDBAL=0x%08x RDBAH=0x%08x RDLEN=%u\n", rdbal, rdbah, rdlen);
    printf("RDH=%u RDT=%u (expected: ring_phys=0x%lx)\n",
           rdh, rdt, (unsigned long)drv->rx_ring_phys);

    uint32_t rdtr = e1000_rd(drv, E1000_RDTR);
    uint32_t rxdctl = e1000_rd(drv, E1000_RXDCTL);
    printf("RDTR=0x%08x RXDCTL=0x%08x\n", rdtr, rxdctl);

    /* TX Registers (for comparison - TX works) */
    printf("\n=== TX Registers (working - for comparison) ===\n");
    uint32_t tctl = e1000_rd(drv, E1000_TCTL);
    printf("TCTL=0x%08x (EN=%d PSP=%d)\n", tctl,
           !!(tctl & E1000_TCTL_EN), !!(tctl & E1000_TCTL_PSP));

    uint32_t tdbal = e1000_rd(drv, E1000_TDBAL);
    uint32_t tdbah = e1000_rd(drv, E1000_TDBAH);
    uint32_t tdlen = e1000_rd(drv, E1000_TDLEN);
    uint32_t tdh = e1000_rd(drv, E1000_TDH);
    uint32_t tdt = e1000_rd(drv, E1000_TDT);
    printf("TDBAL=0x%08x TDBAH=0x%08x TDLEN=%u\n", tdbal, tdbah, tdlen);
    printf("TDH=%u TDT=%u (expected: ring_phys=0x%lx)\n",
           tdh, tdt, (unsigned long)drv->tx_ring_phys);

    /* MAC Address */
    printf("\n=== MAC Address ===\n");
    uint32_t ral = e1000_rd(drv, E1000_RAL);
    uint32_t rah = e1000_rd(drv, E1000_RAH);
    printf("RAL=0x%08x RAH=0x%08x (AV=%d)\n", ral, rah, !!(rah & E1000_RAH_AV));
    printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           (ral >> 0) & 0xFF, (ral >> 8) & 0xFF,
           (ral >> 16) & 0xFF, (ral >> 24) & 0xFF,
           (rah >> 0) & 0xFF, (rah >> 8) & 0xFF);

    /* Interrupts */
    printf("\n=== Interrupts ===\n");
    uint32_t ims = e1000_rd(drv, E1000_IMS);
    printf("IMS=0x%08x (RXT0=%d RXDMT0=%d RXO=%d LSC=%d)\n", ims,
           !!(ims & E1000_IMS_RXT0), !!(ims & E1000_IMS_RXDMT0),
           !!(ims & E1000_IMS_RXO), !!(ims & E1000_IMS_LSC));

    /* Statistics - comprehensive */
    printf("\n=== Statistics ===\n");
    uint32_t tpr = e1000_rd(drv, E1000_TPR);
    uint32_t gprc = e1000_rd(drv, E1000_GPRC);
    uint32_t mpc = e1000_rd(drv, E1000_MPC);
    uint32_t rnbc = e1000_rd(drv, E1000_RNBC);
    printf("TPR=%u (total RX) GPRC=%u (good RX)\n", tpr, gprc);
    printf("MPC=%u (missed) RNBC=%u (no buffers)\n", mpc, rnbc);

    uint32_t tpt = e1000_rd(drv, E1000_TPT);
    uint32_t gptc = e1000_rd(drv, E1000_GPTC);
    printf("TPT=%u (total TX) GPTC=%u (good TX)\n", tpt, gptc);

    /* Error statistics */
    uint32_t crcerrs = e1000_rd(drv, E1000_CRCERRS);
    uint32_t rlec = e1000_rd(drv, E1000_RLEC);
    uint32_t ruc = e1000_rd(drv, E1000_RUC);
    uint32_t roc = e1000_rd(drv, E1000_ROC);
    uint32_t rjc = e1000_rd(drv, E1000_RJC);
    printf("CRCERRS=%u RLEC=%u (len err) RUC=%u (undersz) ROC=%u (oversz) RJC=%u (jabber)\n",
           crcerrs, rlec, ruc, roc, rjc);

    /* Packet size distribution */
    uint32_t prc64 = e1000_rd(drv, E1000_PRC64);
    uint32_t prc127 = e1000_rd(drv, E1000_PRC127);
    uint32_t prc255 = e1000_rd(drv, E1000_PRC255);
    printf("PRC64=%u PRC127=%u PRC255=%u\n", prc64, prc127, prc255);

    /* Driver internal state */
    printf("\n=== Driver State ===\n");
    printf("rx_tail=%u tx_tail=%u tx_head=%u\n",
           drv->rx_tail, drv->tx_tail, drv->tx_head);
    printf("rx_pkts=%u tx_pkts=%u rx_dropped=%u rx_errors=%u irq_count=%u\n",
           drv->rx_pkts, drv->tx_pkts, drv->rx_dropped, drv->rx_errors,
           drv->irq_count);

    /* Dump ALL RX descriptors that have any activity */
    printf("\n=== RX Descriptor Ring (showing non-zero) ===\n");
    int non_zero_count = 0;
    for (int i = 0; i < E1000_NUM_RX_DESC; i++) {
        struct e1000_rx_desc *desc = &drv->rx_ring[i];
        if (desc->status != 0 || desc->length != 0 || desc->errors != 0) {
            printf("  desc[%d]: addr=0x%lx status=0x%02x len=%u err=0x%02x\n",
                   i, (unsigned long)desc->addr, desc->status,
                   desc->length, desc->errors);
            non_zero_count++;
        }
    }
    if (non_zero_count == 0) {
        printf("  (all %d descriptors have status=0 len=0 err=0)\n",
               E1000_NUM_RX_DESC);
    } else {
        printf("  (%d descriptors with activity, %d empty)\n",
               non_zero_count, E1000_NUM_RX_DESC - non_zero_count);
    }

    /* Show first few descriptor addresses to verify DMA setup */
    printf("\n=== RX Descriptor Buffer Addresses (first 4) ===\n");
    for (int i = 0; i < 4; i++) {
        printf("  desc[%d].addr=0x%lx (expected: buf_phys=0x%lx)\n",
               i, (unsigned long)drv->rx_ring[i].addr,
               (unsigned long)drv->rx_buf_phys[i]);
    }

    /* Check raw buffer memory for any data (even without DD bit) */
    printf("\n=== Raw Buffer Check (first 4 buffers) ===\n");
    for (int i = 0; i < 4; i++) {
        uint8_t *buf = drv->rx_bufs[i];
        /* Check for any non-zero data in first 14 bytes (Ethernet header) */
        bool has_data = false;
        for (int j = 0; j < 14; j++) {
            if (buf[j] != 0) {
                has_data = true;
                break;
            }
        }
        if (has_data) {
            printf("  buf[%d]: %02x:%02x:%02x:%02x:%02x:%02x <- %02x:%02x:%02x:%02x:%02x:%02x type=%02x%02x\n",
                   i,
                   buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],   /* dst MAC */
                   buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], /* src MAC */
                   buf[12], buf[13]);                                 /* ethertype */
        } else {
            printf("  buf[%d]: (all zeros in first 14 bytes)\n", i);
        }
    }

    printf("========== END DEBUG DUMP ==========\n\n");
}

/*
 * Read MAC address from RAL/RAH registers
 */
static void e1000_read_mac(struct e1000_driver *drv)
{
    uint32_t ral = e1000_rd(drv, E1000_RAL);
    uint32_t rah = e1000_rd(drv, E1000_RAH);

    drv->mac_addr[0] = (ral >> 0) & 0xFF;
    drv->mac_addr[1] = (ral >> 8) & 0xFF;
    drv->mac_addr[2] = (ral >> 16) & 0xFF;
    drv->mac_addr[3] = (ral >> 24) & 0xFF;
    drv->mac_addr[4] = (rah >> 0) & 0xFF;
    drv->mac_addr[5] = (rah >> 8) & 0xFF;
}

/*
 * Write MAC address to RAL/RAH registers with Address Valid (AV) bit
 * Required after device reset since RAH.AV is cleared
 */
static void e1000_write_mac(struct e1000_driver *drv)
{
    uint32_t ral = drv->mac_addr[0] |
                   ((uint32_t)drv->mac_addr[1] << 8) |
                   ((uint32_t)drv->mac_addr[2] << 16) |
                   ((uint32_t)drv->mac_addr[3] << 24);
    uint32_t rah = drv->mac_addr[4] |
                   ((uint32_t)drv->mac_addr[5] << 8) |
                   E1000_RAH_AV;  /* Address Valid - REQUIRED for RX! */

    e1000_wr(drv, E1000_RAL, ral);
    e1000_wr(drv, E1000_RAH, rah);

    printf("[%s] MAC written: RAL=0x%08x RAH=0x%08x (AV=%d)\n",
           COMPONENT_NAME, ral, rah, !!(rah & E1000_RAH_AV));
}

/*
 * Allocate DMA-capable memory for descriptor rings and buffers
 */
static int e1000_alloc_dma(struct e1000_driver *drv, ps_dma_man_t *dma)
{
    drv->dma_manager = *dma;

    /* Allocate RX descriptor ring (must be 128-byte aligned for 82540EM) */
    size_t rx_ring_size = E1000_NUM_RX_DESC * sizeof(struct e1000_rx_desc);
    drv->rx_ring = ps_dma_alloc(dma, rx_ring_size, E1000_DESC_ALIGN, 0, PS_MEM_NORMAL);
    if (!drv->rx_ring) {
        printf("[%s] Failed to allocate RX descriptor ring\n", COMPONENT_NAME);
        return -1;
    }
    memset(drv->rx_ring, 0, rx_ring_size);
    drv->rx_ring_phys = ps_dma_pin(dma, drv->rx_ring, rx_ring_size);
    printf("[%s] RX ring: virt=%p phys=0x%lx\n", COMPONENT_NAME,
           drv->rx_ring, (unsigned long)drv->rx_ring_phys);

    /* Allocate TX descriptor ring */
    size_t tx_ring_size = E1000_NUM_TX_DESC * sizeof(struct e1000_tx_desc);
    drv->tx_ring = ps_dma_alloc(dma, tx_ring_size, E1000_DESC_ALIGN, 0, PS_MEM_NORMAL);
    if (!drv->tx_ring) {
        printf("[%s] Failed to allocate TX descriptor ring\n", COMPONENT_NAME);
        return -1;
    }
    memset(drv->tx_ring, 0, tx_ring_size);
    drv->tx_ring_phys = ps_dma_pin(dma, drv->tx_ring, tx_ring_size);
    printf("[%s] TX ring: virt=%p phys=0x%lx\n", COMPONENT_NAME,
           drv->tx_ring, (unsigned long)drv->tx_ring_phys);

    /* Allocate RX buffers */
    for (int i = 0; i < E1000_NUM_RX_DESC; i++) {
        drv->rx_bufs[i] = ps_dma_alloc(dma, E1000_RX_BUF_SIZE, E1000_BUF_ALIGN, 0, PS_MEM_NORMAL);
        if (!drv->rx_bufs[i]) {
            printf("[%s] Failed to allocate RX buffer %d\n", COMPONENT_NAME, i);
            return -1;
        }
        memset(drv->rx_bufs[i], 0, E1000_RX_BUF_SIZE);
        drv->rx_buf_phys[i] = ps_dma_pin(dma, drv->rx_bufs[i], E1000_RX_BUF_SIZE);

        /* Setup RX descriptor */
        drv->rx_ring[i].addr = drv->rx_buf_phys[i];
        drv->rx_ring[i].status = 0;
    }

    /* Allocate TX buffers */
    for (int i = 0; i < E1000_NUM_TX_DESC; i++) {
        drv->tx_bufs[i] = ps_dma_alloc(dma, E1000_TX_BUF_SIZE, E1000_BUF_ALIGN, 0, PS_MEM_NORMAL);
        if (!drv->tx_bufs[i]) {
            printf("[%s] Failed to allocate TX buffer %d\n", COMPONENT_NAME, i);
            return -1;
        }
        memset(drv->tx_bufs[i], 0, E1000_TX_BUF_SIZE);
        drv->tx_buf_phys[i] = ps_dma_pin(dma, drv->tx_bufs[i], E1000_TX_BUF_SIZE);

        /* Setup TX descriptor */
        drv->tx_ring[i].addr = drv->tx_buf_phys[i];
        drv->tx_ring[i].status = E1000_TXD_STAT_DD; /* Mark as done initially */
    }

    /* Memory barrier - ensure all descriptor writes are visible before HW init */
    DMB();

    printf("[%s] Allocated %d RX buffers, %d TX buffers\n", COMPONENT_NAME,
           E1000_NUM_RX_DESC, E1000_NUM_TX_DESC);

    return 0;
}

/*
 * Initialize the Intel 82540EM hardware
 */
static int e1000_hw_init(struct e1000_driver *drv)
{
    printf("[%s] Starting 82540EM initialization...\n", COMPONENT_NAME);

    /* Read device status to verify device is present */
    uint32_t status = e1000_rd(drv, E1000_STATUS);
    printf("[%s] STATUS = 0x%08x\n", COMPONENT_NAME, status);

    /* ========== Step 1: Full Device Reset ========== */
    uint32_t ctrl = e1000_rd(drv, E1000_CTRL);
    printf("[%s] CTRL before reset = 0x%08x\n", COMPONENT_NAME, ctrl);

    /* Issue device reset (CTRL.RST) */
    e1000_wr(drv, E1000_CTRL, E1000_CTRL_RST);

    /* Wait for reset to complete - RST bit self-clears */
    int reset_timeout = 100000;
    while ((e1000_rd(drv, E1000_CTRL) & E1000_CTRL_RST) && reset_timeout > 0) {
        reset_timeout--;
    }
    if (reset_timeout == 0) {
        printf("[%s] WARNING: Device reset timeout\n", COMPONENT_NAME);
    } else {
        printf("[%s] Device reset complete\n", COMPONENT_NAME);
    }

    /* Post-reset delay (Intel manual recommends waiting after reset) */
    for (volatile int i = 0; i < 1000000; i++) {}

    /* Set Link Up, Full Duplex */
    ctrl = E1000_CTRL_SLU | E1000_CTRL_FD | E1000_CTRL_ASDE;
    e1000_wr(drv, E1000_CTRL, ctrl);

    /* Small delay for link to establish */
    for (volatile int i = 0; i < 100000; i++) {}

    /* Disable interrupts during setup */
    e1000_wr(drv, E1000_IMC, 0xFFFFFFFF);

    /* Clear any pending interrupts */
    (void)e1000_rd(drv, E1000_ICR);

    /* Read MAC address (QEMU reloads from EEPROM after reset) */
    e1000_read_mac(drv);
    printf("[%s] MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", COMPONENT_NAME,
           drv->mac_addr[0], drv->mac_addr[1], drv->mac_addr[2],
           drv->mac_addr[3], drv->mac_addr[4], drv->mac_addr[5]);

    /* Write MAC back with Address Valid (AV) bit - REQUIRED for RX! */
    /* Reset clears RAH.AV, so NIC won't match any unicast packets without this */
    e1000_write_mac(drv);

    /* ========== Step 2: Clear Multicast Table Array ========== */
    /* Zero all 128 MTA entries to prevent multicast/broadcast filtering issues */
    printf("[%s] Clearing MTA (%d entries)...\n", COMPONENT_NAME, E1000_MTA_SIZE);
    for (int i = 0; i < E1000_MTA_SIZE; i++) {
        e1000_wr(drv, E1000_MTA + i * 4, 0);
    }

    /* ========== Step 3: Setup RX (correct order per Intel manual) ========== */
    /* 1. Disable receiver during setup (explicit, per Intel manual 14.4) */
    e1000_wr(drv, E1000_RCTL, 0);

    /* 2. Set RX descriptor base address */
    e1000_wr(drv, E1000_RDBAL, (uint32_t)(drv->rx_ring_phys & 0xFFFFFFFF));
    e1000_wr(drv, E1000_RDBAH, (uint32_t)(drv->rx_ring_phys >> 32));

    /* 3. Set RX descriptor ring length */
    e1000_wr(drv, E1000_RDLEN, E1000_NUM_RX_DESC * sizeof(struct e1000_rx_desc));

    /* 4. Set head to 0 */
    e1000_wr(drv, E1000_RDH, 0);

    /* 5. Set RDT (per Intel manual 14.4 - before enabling receiver!) */
    e1000_wr(drv, E1000_RDT, E1000_NUM_RX_DESC - 1);
    drv->rx_tail = 0;

    /* Memory barrier - ensure descriptor ring is visible before enabling RX */
    DMB();

    /* 6. NOW enable receiver (RCTL.EN) - AFTER setting RDT per Intel manual
     * - Enable receiver
     * - Accept broadcast
     * - Strip CRC
     * - 2KB buffers
     * - Promiscuous mode for testing
     */
    uint32_t rctl = E1000_RCTL_EN |
                    E1000_RCTL_BAM |
                    E1000_RCTL_SECRC |
                    E1000_RCTL_BSIZE_2048 |
                    E1000_RCTL_UPE |     /* Unicast promiscuous */
                    E1000_RCTL_MPE;      /* Multicast promiscuous */
    e1000_wr(drv, E1000_RCTL, rctl);

    /* Verify RCTL was written correctly */
    uint32_t rctl_readback = e1000_rd(drv, E1000_RCTL);
    printf("[%s] RCTL = 0x%08x (expected 0x%08x)\n", COMPONENT_NAME,
           rctl_readback, rctl);

    /* Readback RX ring base to verify hardware received it */
    uint32_t rdbal_rb = e1000_rd(drv, E1000_RDBAL);
    uint32_t rdbah_rb = e1000_rd(drv, E1000_RDBAH);
    printf("[%s] RX ring base: wrote=0x%lx readback=0x%x:%08x\n", COMPONENT_NAME,
           (unsigned long)drv->rx_ring_phys, rdbah_rb, rdbal_rb);

    printf("[%s] RX init: RDH=%u RDT=%u RDLEN=%u\n", COMPONENT_NAME,
           e1000_rd(drv, E1000_RDH), e1000_rd(drv, E1000_RDT),
           e1000_rd(drv, E1000_RDLEN));

    /* Debug: Print first descriptor to verify buffer address */
    printf("[%s] desc[0]: buf_addr=0x%lx status=0x%02x\n", COMPONENT_NAME,
           (unsigned long)drv->rx_ring[0].addr, drv->rx_ring[0].status);

    /* Setup TX descriptor ring */
    e1000_wr(drv, E1000_TDBAL, (uint32_t)(drv->tx_ring_phys & 0xFFFFFFFF));
    e1000_wr(drv, E1000_TDBAH, (uint32_t)(drv->tx_ring_phys >> 32));
    e1000_wr(drv, E1000_TDLEN, E1000_NUM_TX_DESC * sizeof(struct e1000_tx_desc));
    e1000_wr(drv, E1000_TDH, 0);
    e1000_wr(drv, E1000_TDT, 0);
    drv->tx_tail = 0;
    drv->tx_head = 0;

    /* Setup TX control:
     * - Enable transmitter
     * - Pad short packets
     * - Collision threshold and distance for full-duplex
     */
    uint32_t tctl = E1000_TCTL_EN |
                    E1000_TCTL_PSP |
                    E1000_TCTL_CT |
                    E1000_TCTL_COLD;
    e1000_wr(drv, E1000_TCTL, tctl);

    /* Enable RX interrupts:
     * - RX timer interrupt (packet received)
     * - RX descriptor minimum threshold (low on descriptors)
     * - RX overrun
     */
    uint32_t ims = E1000_IMS_RXT0 | E1000_IMS_RXDMT0 | E1000_IMS_RXO | E1000_IMS_LSC;
    e1000_wr(drv, E1000_IMS, ims);

    /* Final status check */
    status = e1000_rd(drv, E1000_STATUS);
    printf("[%s] Post-init STATUS = 0x%08x (link_up=%d)\n", COMPONENT_NAME,
           status, !!(status & E1000_STATUS_LU));

    printf("[%s] 82540EM initialization complete\n", COMPONENT_NAME);

    /* Comprehensive debug dump at init completion */
    e1000_debug_dump(drv);

    return 0;
}

/*
 * Transmit a frame
 */
static int e1000_tx(struct e1000_driver *drv, const void *data, uint16_t len)
{
    if (len == 0 || len > WEB_FRAME_MTU) {
        return -1;
    }

    /* Get current TX descriptor */
    uint32_t idx = drv->tx_tail;
    struct e1000_tx_desc *desc = &drv->tx_ring[idx];

    /* Wait for descriptor to be available */
    int timeout = 10000;
    while (!(desc->status & E1000_TXD_STAT_DD) && timeout > 0) {
        timeout--;
    }
    if (timeout == 0) {
        printf("[%s] TX timeout waiting for descriptor %d\n", COMPONENT_NAME, idx);
        return -1;
    }

    /* Copy data to TX buffer */
    memcpy(drv->tx_bufs[idx], data, len);
    DMB();

    /* Setup descriptor */
    desc->length = len;
    desc->cmd = E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS | E1000_TXD_CMD_RS;
    desc->status = 0;
    DMB();

    /* Advance tail pointer */
    drv->tx_tail = (idx + 1) % E1000_NUM_TX_DESC;
    e1000_wr(drv, E1000_TDT, drv->tx_tail);

    drv->tx_pkts++;
    return 0;
}

/*
 * Poll for received frames
 */
static void e1000_poll_rx(struct e1000_driver *drv)
{
    volatile struct ring_dataport *out = (volatile struct ring_dataport *)frame_out;

    while (1) {
        uint32_t idx = drv->rx_tail;
        struct e1000_rx_desc *desc = &drv->rx_ring[idx];

        /* Check if this descriptor has received a packet */
        if (!(desc->status & E1000_RXD_STAT_DD)) {
            break;  /* No more packets */
        }

        /* Check for errors */
        if (desc->errors) {
            printf("[%s] RX error 0x%02x on descriptor %d\n", COMPONENT_NAME,
                   desc->errors, idx);
            drv->rx_errors++;
        } else if (desc->status & E1000_RXD_STAT_EOP) {
            /* Valid complete packet */
            uint16_t len = desc->length;

            if (len >= 14 && len <= WEB_FRAME_MTU) {
                /* Try to put frame into ring buffer */
                struct frame_entry *slot = ring_produce(out);
                if (slot) {
                    slot->len = len;
                    memcpy(slot->data, drv->rx_bufs[idx], len);
                    ring_commit(out);
                    frame_out_ready_emit();
                    drv->rx_pkts++;
                } else {
                    drv->rx_dropped++;
                }
            }
        }

        /* Reset descriptor for reuse */
        desc->status = 0;
        desc->errors = 0;
        desc->length = 0;
        DMB();

        /* Advance tail pointer */
        drv->rx_tail = (idx + 1) % E1000_NUM_RX_DESC;
        e1000_wr(drv, E1000_RDT, idx);
    }
}

/*
 * IRQ handler - called by CAmkES interrupt thread
 */
void eth_irq_handle(void)
{
    if (!driver_ready) {
        eth_irq_acknowledge();
        return;
    }

    g_drv.irq_count++;

    /* Read and clear interrupt causes */
    uint32_t icr = e1000_rd(&g_drv, E1000_ICR);

    /* Handle RX interrupt */
    if (icr & (E1000_ICR_RXT0 | E1000_ICR_RXDMT0 | E1000_ICR_RXO)) {
        e1000_poll_rx(&g_drv);
    }

    /* Handle link status change */
    if (icr & E1000_ICR_LSC) {
        uint32_t status = e1000_rd(&g_drv, E1000_STATUS);
        printf("[%s] Link status changed: %s\n", COMPONENT_NAME,
               (status & E1000_STATUS_LU) ? "UP" : "DOWN");
    }

    eth_irq_acknowledge();
}

/*
 * Notification handler - frames ready to transmit
 */
void frame_in_ready_handle(void)
{
    /* TX frames handled in main loop */
}

/*
 * CAmkES pre_init - called early during component initialization
 */
void pre_init(void)
{
    printf("[%s] pre_init called\n", COMPONENT_NAME);
}

/*
 * CAmkES post_init - called after CAmkES infrastructure is ready
 */
void post_init(void)
{
    int error;
    ps_io_ops_t io_ops;

    printf("[%s] post_init starting...\n", COMPONENT_NAME);
    printf("[%s] Intel 82540EM standalone driver\n", COMPONENT_NAME);

    /* Initialize PCI device FIRST - program BAR and enable memory access */
    error = e1000_pci_init();
    if (error) {
        printf("[%s] PCI initialization failed\n", COMPONENT_NAME);
        return;
    }

    /* Get io_ops from CAmkES */
    error = camkes_io_ops(&io_ops);
    if (error) {
        printf("[%s] Failed to get io_ops: %d\n", COMPONENT_NAME, error);
        return;
    }

    /* Initialize driver structure */
    memset(&g_drv, 0, sizeof(g_drv));
    g_drv.mmio = (volatile void *)eth_mmio;

    printf("[%s] MMIO base = %p\n", COMPONENT_NAME, g_drv.mmio);

    /* Verify device is present by reading STATUS */
    uint32_t status = e1000_rd(&g_drv, E1000_STATUS);
    printf("[%s] Initial STATUS = 0x%08x\n", COMPONENT_NAME, status);

    /* Allocate DMA memory */
    error = e1000_alloc_dma(&g_drv, &io_ops.dma_manager);
    if (error) {
        printf("[%s] Failed to allocate DMA memory\n", COMPONENT_NAME);
        return;
    }

    /* Initialize hardware */
    error = e1000_hw_init(&g_drv);
    if (error) {
        printf("[%s] Failed to initialize hardware\n", COMPONENT_NAME);
        return;
    }

    driver_ready = true;
    printf("[%s] post_init complete - driver ready\n", COMPONENT_NAME);
}

/*
 * Main driver loop
 */
int run(void)
{
    printf("[%s] Entering main loop\n", COMPONENT_NAME);

    volatile struct ring_dataport *in = (volatile struct ring_dataport *)frame_in;

    uint32_t loop_count = 0;
    uint32_t last_irq_count = 0;
    uint32_t last_rx_pkts = 0;
    uint32_t last_tx_pkts = 0;

    while (1) {
        bool did_work = false;

        /* Poll RX (supplement IRQ-driven receive) */
        if (driver_ready) {
            uint32_t rx_before = g_drv.rx_pkts;
            e1000_poll_rx(&g_drv);
            if (g_drv.rx_pkts != rx_before) {
                did_work = true;
            }
        }

        /* TX: drain all queued frames from ring */
        struct frame_entry *tx_slot;
        while ((tx_slot = ring_consume(in)) != NULL) {
            uint16_t tx_len = tx_slot->len;
            if (tx_len > 0 && tx_len <= WEB_FRAME_MTU) {
                e1000_tx(&g_drv, tx_slot->data, tx_len);
            }
            ring_release(in);
            did_work = true;
        }

        /* Periodic debug output */
        loop_count++;
        if ((loop_count % 500000) == 0) {
            uint32_t rdh = e1000_rd(&g_drv, E1000_RDH);
            uint32_t rdt = e1000_rd(&g_drv, E1000_RDT);

            printf("[%s] irq=%u(+%u) rx=%u(+%u) tx=%u(+%u) drop=%u RDH=%u RDT=%u\n",
                   COMPONENT_NAME,
                   g_drv.irq_count, g_drv.irq_count - last_irq_count,
                   g_drv.rx_pkts, g_drv.rx_pkts - last_rx_pkts,
                   g_drv.tx_pkts, g_drv.tx_pkts - last_tx_pkts,
                   g_drv.rx_dropped,
                   rdh, rdt);

            /* If RX still not working, do periodic comprehensive dump */
            if (g_drv.rx_pkts == 0 && g_drv.rx_ring != NULL) {
                /* Quick stats always */
                uint32_t tpr = e1000_rd(&g_drv, E1000_TPR);
                uint32_t gprc = e1000_rd(&g_drv, E1000_GPRC);
                uint32_t mpc = e1000_rd(&g_drv, E1000_MPC);
                uint32_t rnbc = e1000_rd(&g_drv, E1000_RNBC);
                printf("[%s] HW stats: TPR=%u GPRC=%u MPC=%u RNBC=%u\n",
                       COMPONENT_NAME, tpr, gprc, mpc, rnbc);

                /* Full dump every ~20 iterations (about every 20 status prints)
                 * to avoid flooding the console, but ensure we catch state changes */
                debug_dump_count++;
                if (debug_dump_count == 1 || debug_dump_count == 5 ||
                    (debug_dump_count % 20) == 0) {
                    printf("[%s] Periodic debug dump #%u (RX still not working)\n",
                           COMPONENT_NAME, debug_dump_count);
                    e1000_debug_dump(&g_drv);
                }
            } else if (g_drv.rx_pkts > 0 && debug_dump_count > 0) {
                /* RX started working - do one final dump to see what changed */
                printf("[%s] RX WORKING! First packet received, final debug dump:\n",
                       COMPONENT_NAME);
                e1000_debug_dump(&g_drv);
                debug_dump_count = 0;  /* Reset so we don't keep dumping */
            }

            last_irq_count = g_drv.irq_count;
            last_rx_pkts = g_drv.rx_pkts;
            last_tx_pkts = g_drv.tx_pkts;
        }

        /* Yield when no work done */
        if (!did_work) {
            seL4_Yield();
        }
    }

    return 0;
}
