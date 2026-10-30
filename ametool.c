/*
 * ametool - Application-Managed Encryption (AME-T10) helper for LTO via SG_IO
 *
 * Based on IBM LTO SCSI Reference GA32-0928-07:
 *   SPOUT B5h / Set Data Encryption 20h[0010h] (Table 417)
 *   SPIN Data Encryption Capabilities / Status / Next Block Status
 *   MAM attributes: MEDIUM SERIAL (0401h), USER MEDIUM TEXT LABEL (0803h),
 *                   BARCODE (0806h)
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <scsi/sg.h>

#define DK_LENGTH  32
#define DKI_LENGTH 12
#define DKI_ASCII  3

#define SPIN         0xA2
#define SPOUT        0xB5
#define MODE_SENSE10 0x5A
#define READ_ATTR    0x8C
#define INQUIRY      0x12

#define SEC_PROTO_TAPE_DATA_ENC   0x20
#define SPS_DATA_ENC_CAPABILITIES 0x0010
#define SPS_SET_DATA_ENCRYPTION   0x0010
#define SPS_DATA_ENC_STATUS       0x0020
#define SPS_NEXT_BLOCK_ENC_STATUS 0x0021

#define ENC_DISABLE 0x00
#define ENC_ENCRYPT 0x02
#define DEC_DISABLE 0x00
#define DEC_MIXED   0x03
#define SCOPE_ALL_IT_NEXUS 0x2
#define ENC_SOLUTION_AME   0x03

#define MAM_MEDIUM_SERIAL 0x0401
#define MAM_USER_LABEL    0x0803
#define MAM_BARCODE       0x0806
#define MAM_ATTR_HDR      5

struct ame_status {
	int mp30_ok;
	int is_ame;
	uint8_t method;
	uint8_t key_path;
	uint8_t def_state;

	int caps_ok;
	uint8_t cfg_p;
	uint8_t alg_index; /* preferred AVFMV */

	int drv_ok;
	uint8_t enc_mode;
	uint8_t dec_mode;
	uint8_t drv_alg;
	int vcelb; /* volume contains encrypted logical blocks */
	int have_dki;
	uint8_t dki[DKI_LENGTH];

	int next_ok;
	uint8_t next_enc_status;
	uint8_t next_alg;

	char medium_serial[64];
	char barcode[64];
	char label[192];
	char drive_id[64];
};

static void u16be(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)(v & 0xff);
}

static void u32be(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)(v & 0xff);
}

static uint16_t be16(const uint8_t *p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
}

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static int parse_dki(const char *s, uint8_t out[DKI_LENGTH])
{
	size_t len = strlen(s);
	size_t expect = DKI_ASCII + (DKI_LENGTH - DKI_ASCII) * 2;

	if (len != expect) {
		fprintf(stderr, "DKi must be %zu chars (3 ASCII + 18 hex), got %zu\n",
			expect, len);
		return -1;
	}
	memcpy(out, s, DKI_ASCII);
	for (int i = 0; i < DKI_LENGTH - DKI_ASCII; i++) {
		int hi = hex_nibble(s[DKI_ASCII + i * 2]);
		int lo = hex_nibble(s[DKI_ASCII + i * 2 + 1]);
		if (hi < 0 || lo < 0) {
			fprintf(stderr, "DKi has invalid hex at offset %d\n",
				DKI_ASCII + i * 2);
			return -1;
		}
		out[DKI_ASCII + i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

static void format_dki(const uint8_t dki[DKI_LENGTH], char out[22])
{
	memcpy(out, dki, DKI_ASCII);
	for (int i = 0; i < DKI_LENGTH - DKI_ASCII; i++)
		sprintf(out + DKI_ASCII + i * 2, "%02x", dki[DKI_ASCII + i]);
	out[21] = '\0';
}

static int b64_val(char c)
{
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	if (c == '=') return -2;
	return -1;
}

static int parse_dk_b64(const char *s, uint8_t out[DK_LENGTH])
{
	uint8_t tmp[64];
	size_t n = 0;
	int val = 0, valb = -8;

	for (const char *p = s; *p; p++) {
		if (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')
			continue;
		int v = b64_val(*p);
		if (v == -1) {
			fprintf(stderr, "invalid base64 in DK\n");
			return -1;
		}
		if (v == -2)
			break;
		val = (val << 6) + v;
		valb += 6;
		if (valb >= 0) {
			if (n >= sizeof(tmp)) {
				fprintf(stderr, "DK base64 too long\n");
				return -1;
			}
			tmp[n++] = (uint8_t)((val >> valb) & 0xff);
			valb -= 8;
		}
	}
	if (n != DK_LENGTH) {
		fprintf(stderr, "DK must decode to %d bytes, got %zu\n", DK_LENGTH, n);
		return -1;
	}
	memcpy(out, tmp, DK_LENGTH);
	return 0;
}

static int sense_is_unit_attention(const uint8_t *sense, int len)
{
	if (len < 3)
		return 0;
	if ((sense[0] & 0x7f) != 0x70 && (sense[0] & 0x7f) != 0x71)
		return 0;
	return (sense[2] & 0x0f) == 0x06;
}

static int sg_cmd(int fd, uint8_t *cdb, size_t cdb_len,
		  int dxfer_dir, void *dxferp, unsigned dxfer_len,
		  const char *name, int quiet)
{
	for (int attempt = 0; attempt < 4; attempt++) {
		sg_io_hdr_t io;
		uint8_t sense[32];
		memset(&io, 0, sizeof(io));
		memset(sense, 0, sizeof(sense));

		io.interface_id    = 'S';
		io.cmd_len         = (unsigned char)cdb_len;
		io.mx_sb_len       = sizeof(sense);
		io.dxfer_direction = dxfer_dir;
		io.dxfer_len       = dxfer_len;
		io.dxferp          = dxferp;
		io.cmdp            = cdb;
		io.sbp             = sense;
		io.timeout         = 60000;

		if (ioctl(fd, SG_IO, &io) < 0) {
			if (!quiet)
				perror(name);
			return -1;
		}
		if ((io.info & SG_INFO_OK_MASK) == SG_INFO_OK)
			return 0;

		if (sense_is_unit_attention(sense, io.sb_len_wr) && attempt + 1 < 4) {
			if (!quiet) {
				uint8_t asc = io.sb_len_wr > 12 ? sense[12] : 0;
				uint8_t ascq = io.sb_len_wr > 13 ? sense[13] : 0;
				fprintf(stderr,
					"%s: UNIT ATTENTION (ASC/ASCQ %02X/%02X), retrying...\n",
					name, asc, ascq);
			}
			continue;
		}

		if (!quiet) {
			fprintf(stderr, "%s failed: status=0x%02x host=0x%x driver=0x%x\n",
				name, io.status, io.host_status, io.driver_status);
			if (io.sb_len_wr > 0) {
				fprintf(stderr, "  sense:");
				for (int i = 0; i < io.sb_len_wr; i++)
					fprintf(stderr, " %02x", sense[i]);
				fprintf(stderr, "\n");
			}
		}
		return -1;
	}
	return -1;
}

static void trim_spaces(char *s)
{
	size_t n = strlen(s);
	while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\n'))
		s[--n] = '\0';
	char *p = s;
	while (*p == ' ' || *p == '\t')
		p++;
	if (p != s)
		memmove(s, p, strlen(p) + 1);
}

static int read_mam_ascii(int fd, uint16_t id, char *out, size_t out_sz)
{
	/* Response: AVAILABLE DATA(4) + attr hdr(5) + value. LTFS copies from +4. */
	size_t val_len;
	size_t xfer;
	uint8_t *buf;
	uint8_t cdb[16];
	int rc;

	switch (id) {
	case MAM_MEDIUM_SERIAL: val_len = 32; break;
	case MAM_BARCODE:       val_len = 32; break;
	case MAM_USER_LABEL:    val_len = 160; break;
	default: return -1;
	}

	xfer = 4 + MAM_ATTR_HDR + val_len;
	buf = calloc(1, xfer);
	if (!buf)
		return -1;

	memset(cdb, 0, sizeof(cdb));
	cdb[0] = READ_ATTR;
	cdb[1] = 0x00; /* ATTRIBUTE VALUES */
	/* partition 0 in byte 7 */
	u16be(cdb + 8, id);
	u32be(cdb + 10, (uint32_t)xfer);

	rc = sg_cmd(fd, cdb, sizeof(cdb), SG_DXFER_FROM_DEV, buf, (unsigned)xfer,
		    "READ ATTRIBUTE", 1);
	if (rc == 0) {
		/* Match LTFS: attribute starts at offset 4 of raw transfer */
		uint8_t *attr = buf + 4;
		uint16_t got_id = be16(attr);
		uint16_t got_len = be16(attr + 3);
		if (got_id == id && got_len <= val_len &&
		    (size_t)MAM_ATTR_HDR + got_len <= xfer - 4) {
			size_t n = got_len < out_sz - 1 ? got_len : out_sz - 1;
			memcpy(out, attr + MAM_ATTR_HDR, n);
			out[n] = '\0';
			trim_spaces(out);
		} else {
			rc = -1;
		}
	}
	free(buf);
	return rc;
}

static int read_inquiry_product(int fd, char *out, size_t out_sz)
{
	uint8_t cdb[6] = {0};
	uint8_t buf[96];
	char vendor[9], product[17], rev[5];

	memset(buf, 0, sizeof(buf));
	cdb[0] = INQUIRY;
	cdb[4] = sizeof(buf);

	if (sg_cmd(fd, cdb, sizeof(cdb), SG_DXFER_FROM_DEV, buf, sizeof(buf),
		   "INQUIRY", 1) < 0)
		return -1;

	memcpy(vendor, buf + 8, 8); vendor[8] = '\0';
	memcpy(product, buf + 16, 16); product[16] = '\0';
	memcpy(rev, buf + 32, 4); rev[4] = '\0';
	trim_spaces(vendor);
	trim_spaces(product);
	trim_spaces(rev);
	snprintf(out, out_sz, "%s %s %s", vendor, product, rev);
	return 0;
}

static const char *enc_mode_name(uint8_t m)
{
	switch (m) {
	case 0: return "Disable";
	case 1: return "External";
	case 2: return "Encrypt";
	default: return "Unknown";
	}
}

static const char *dec_mode_name(uint8_t m)
{
	switch (m) {
	case 0: return "Disable";
	case 1: return "Raw";
	case 2: return "Decrypt";
	case 3: return "Mixed";
	default: return "Unknown";
	}
}

static const char *next_enc_name(uint8_t s)
{
	switch (s & 0x0f) {
	case 0: return "incapable";
	case 1: return "not yet determined";
	case 2: return "not a logical block";
	case 3: return "not encrypted";
	case 4: return "encrypted (unsupported algorithm)";
	case 5: return "encrypted (supported algorithm)";
	case 6: return "encrypted (wrong/missing key)";
	default: return "reserved";
	}
}

static int spin_page(int fd, uint16_t sps, uint8_t *buf, size_t buf_sz, int quiet)
{
	uint8_t cdb[12] = {0};
	cdb[0] = SPIN;
	cdb[1] = SEC_PROTO_TAPE_DATA_ENC;
	u16be(cdb + 2, sps);
	u32be(cdb + 6, (uint32_t)buf_sz);
	memset(buf, 0, buf_sz);
	return sg_cmd(fd, cdb, sizeof(cdb), SG_DXFER_FROM_DEV, buf, (unsigned)buf_sz,
		      "SPIN", quiet);
}

static void extract_dki_from_kad(const uint8_t *buf, size_t size, unsigned kad_off,
				 struct ame_status *st)
{
	unsigned off = kad_off;
	while (off + 4 <= size) {
		uint8_t type = buf[off];
		uint16_t dlen = be16(buf + off + 2);
		if (off + 4 + dlen > size)
			break;
		if (type == 0x01 && dlen >= 1) {
			size_t n = dlen < DKI_LENGTH ? dlen : DKI_LENGTH;
			memcpy(st->dki, buf + off + 4, n);
			st->have_dki = 1;
			return;
		}
		off += 4 + dlen;
	}
}

static int collect_status(int fd, struct ame_status *st, int quiet_errors)
{
	uint8_t buf[512];
	memset(st, 0, sizeof(*st));
	st->alg_index = 0x01;

	read_inquiry_product(fd, st->drive_id, sizeof(st->drive_id));
	if (read_mam_ascii(fd, MAM_MEDIUM_SERIAL, st->medium_serial,
			   sizeof(st->medium_serial)) < 0)
		snprintf(st->medium_serial, sizeof(st->medium_serial), "(unavailable)");
	if (read_mam_ascii(fd, MAM_BARCODE, st->barcode, sizeof(st->barcode)) < 0)
		snprintf(st->barcode, sizeof(st->barcode), "(unavailable)");
	if (read_mam_ascii(fd, MAM_USER_LABEL, st->label, sizeof(st->label)) < 0)
		snprintf(st->label, sizeof(st->label), "(unavailable)");

	/* MP 30h[20h] */
	{
		uint8_t cdb[10] = {0};
		memset(buf, 0, sizeof(buf));
		cdb[0] = MODE_SENSE10;
		cdb[1] = 0x08;
		cdb[2] = 0x30;
		cdb[3] = 0x20;
		cdb[8] = 64;
		if (sg_cmd(fd, cdb, sizeof(cdb), SG_DXFER_FROM_DEV, buf, 64,
			   "MODE SENSE MP30h[20h]", quiet_errors) == 0) {
			uint8_t *page = buf + 8;
			if ((page[0] & 0x3f) == 0x30 && page[1] == 0x20) {
				st->mp30_ok = 1;
				st->method = page[5];
				st->key_path = page[6];
				st->def_state = page[7];
				st->is_ame = (st->method == ENC_SOLUTION_AME);
			}
		}
	}

	/* Capabilities */
	if (spin_page(fd, SPS_DATA_ENC_CAPABILITIES, buf, sizeof(buf), quiet_errors) == 0 &&
	    be16(buf) == SPS_DATA_ENC_CAPABILITIES) {
		uint16_t page_len = be16(buf + 2);
		unsigned off;
		int found_avfmv = 0;

		st->caps_ok = 1;
		st->cfg_p = buf[4] & 0x03;
		for (off = 20; off + 24 <= (unsigned)page_len + 4 && off + 24 <= sizeof(buf);
		     off += 24) {
			uint8_t idx = buf[off];
			int avfmv = (buf[off + 4] >> 7) & 1;
			if (!found_avfmv) {
				st->alg_index = idx;
				if (avfmv)
					found_avfmv = 1;
			}
			if (avfmv) {
				st->alg_index = idx;
				break;
			}
		}
	}

	/* Drive encryption parameters + VCELB */
	if (spin_page(fd, SPS_DATA_ENC_STATUS, buf, sizeof(buf), quiet_errors) == 0 &&
	    be16(buf) == SPS_DATA_ENC_STATUS) {
		uint16_t page_len = be16(buf + 2);
		st->drv_ok = 1;
		st->enc_mode = buf[5];
		st->dec_mode = buf[6];
		st->drv_alg = buf[7];
		st->vcelb = (buf[12] >> 3) & 0x01; /* VCELB (SSC / GA32-0928 Table 408) */
		if (st->enc_mode != ENC_DISABLE || st->dec_mode != DEC_DISABLE)
			extract_dki_from_kad(buf, (size_t)page_len + 4, 24, st);
	}

	/* Next block on medium */
	if (spin_page(fd, SPS_NEXT_BLOCK_ENC_STATUS, buf, sizeof(buf), quiet_errors) == 0 &&
	    be16(buf) == SPS_NEXT_BLOCK_ENC_STATUS) {
		st->next_ok = 1;
		st->next_enc_status = buf[12] & 0x0f;
		st->next_alg = buf[13];
		if (st->next_enc_status >= 4 && st->next_enc_status <= 6 && !st->have_dki)
			extract_dki_from_kad(buf, (size_t)be16(buf + 2) + 4, 16, st);
	}

	return 0;
}

static void print_status(const struct ame_status *st)
{
	char dki_txt[22];

	printf("Drive:          %s\n",
	       st->drive_id[0] ? st->drive_id : "(unknown)");
	printf("Medium serial:  %s\n", st->medium_serial);
	printf("Barcode:        %s\n", st->barcode);
	printf("Volume label:   %s\n", st->label);

	if (st->mp30_ok) {
		const char *m = "other/custom";
		if (st->method == 0x01) m = "No Encryption";
		else if (st->method == 0x03) m = "AME";
		else if (st->method == 0x04) m = "LME";
		printf("Enc. solution:  %s (0x%02X)  key_path=0x%02X default_state=0x%02X\n",
		       m, st->method, st->key_path, st->def_state);
	} else {
		printf("Enc. solution:  (MP 30h[20h] unavailable)\n");
	}

	if (st->caps_ok) {
		printf("SPIN CFG_P:     %u%s\n", st->cfg_p,
		       st->cfg_p == 1 ? " (host may set key)" :
		       st->cfg_p == 2 ? " (configuration prevented)" : "");
		printf("Preferred alg:  0x%02X (AVFMV)\n", st->alg_index);
	}

	if (st->drv_ok) {
		printf("Drive key mode: ENCRYPT=%s DECRYPT=%s alg=0x%02X\n",
		       enc_mode_name(st->enc_mode), dec_mode_name(st->dec_mode),
		       st->drv_alg);
		printf("Volume has encrypted data (VCELB): %s\n",
		       st->vcelb ? "yes" : "no / unknown");
		if (st->have_dki) {
			format_dki(st->dki, dki_txt);
			printf("Loaded DKi:     %s\n", dki_txt);
		} else if (st->enc_mode != ENC_DISABLE || st->dec_mode != DEC_DISABLE) {
			printf("Loaded DKi:     (none in status page)\n");
		} else {
			printf("Loaded DKi:     (no key loaded)\n");
		}
	} else {
		printf("Drive key mode: (SPIN 0020h unavailable)\n");
	}

	if (st->next_ok) {
		printf("Next block:     %s", next_enc_name(st->next_enc_status));
		if (st->next_enc_status >= 4 && st->next_enc_status <= 6)
			printf(" (alg=0x%02X)", st->next_alg);
		printf("\n");
	}
}

static int spout_set_key(int fd, const uint8_t *dki, const uint8_t *dk,
			 uint8_t alg_index, int ckod)
{
	size_t size = dki ? (20 + DK_LENGTH + 4 + DKI_LENGTH) : 20;
	uint8_t *page = calloc(1, size);
	uint8_t cdb[12];
	int rc;

	if (!page) {
		perror("calloc");
		return -1;
	}

	u16be(page + 0, SPS_SET_DATA_ENCRYPTION);
	u16be(page + 2, (uint16_t)(size - 4));
	page[4] = (uint8_t)(SCOPE_ALL_IT_NEXUS << 5);
	page[5] = ckod ? 0x04 : 0x00;
	page[6] = dki ? ENC_ENCRYPT : ENC_DISABLE;
	page[7] = dki ? DEC_MIXED : DEC_DISABLE;
	page[8] = alg_index;
	page[9] = 0x00;
	page[10] = 0x00;
	u16be(page + 18, dki ? DK_LENGTH : 0x0000);

	if (dki) {
		memcpy(page + 20, dk, DK_LENGTH);
		page[20 + DK_LENGTH] = 0x01;
		page[20 + DK_LENGTH + 1] = 0x00;
		u16be(page + 20 + DK_LENGTH + 2, DKI_LENGTH);
		memcpy(page + 20 + DK_LENGTH + 4, dki, DKI_LENGTH);
	}

	memset(cdb, 0, sizeof(cdb));
	cdb[0] = SPOUT;
	cdb[1] = SEC_PROTO_TAPE_DATA_ENC;
	u16be(cdb + 2, SPS_SET_DATA_ENCRYPTION);
	u32be(cdb + 6, (uint32_t)size);

	rc = sg_cmd(fd, cdb, sizeof(cdb), SG_DXFER_TO_DEV, page, (unsigned)size,
		    "SPOUT Set Data Encryption", 0);
	free(page);
	return rc;
}

static int read_line(const char *prompt, char *buf, size_t buflen, int hide)
{
	struct termios oldt, newt;
	int have_term = 0;

	fputs(prompt, stdout);
	fflush(stdout);

	if (hide && isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &oldt) == 0) {
		newt = oldt;
		newt.c_lflag &= ~(ECHO);
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt);
		have_term = 1;
	}

	if (!fgets(buf, (int)buflen, stdin)) {
		if (have_term)
			tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
		return -1;
	}

	if (have_term) {
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
		fputc('\n', stdout);
	}

	trim_spaces(buf);
	return 0;
}

static int prompt_keys(uint8_t dki[DKI_LENGTH], uint8_t dk[DK_LENGTH])
{
	char dki_buf[128];
	char dk_buf[256];

	if (read_line("DKi: ", dki_buf, sizeof(dki_buf), 0) < 0)
		return -1;
	if (read_line("DK: ", dk_buf, sizeof(dk_buf), 1) < 0)
		return -1;
	if (parse_dki(dki_buf, dki) < 0 || parse_dk_b64(dk_buf, dk) < 0)
		return -1;
	return 0;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s <sg-device> --status\n"
		"  %s <sg-device> [--dki DKi] [--dk DK] [--no-ckod] [--alg N] [--force]\n"
		"  %s <sg-device> --clear [--no-ckod] [--force]\n"
		"\n"
		"  --status   show cartridge / AME status only\n"
		"  --clear    clear encryption parameters on the drive\n"
		"  --dki/--dk LTFS-style key id and base64 data key; if omitted when\n"
		"             setting a key, prompted on stdin after status is shown\n"
		"  --no-ckod  keep key across demount (default is CKOD=1)\n"
		"  --force    skip AME / CFG_P refusal checks\n"
		"  --alg N    force ALGORITHM INDEX (default: SPIN AVFMV)\n",
		argv0, argv0, argv0);
}

int main(int argc, char **argv)
{
	const char *dki_str = NULL;
	const char *dk_str = NULL;
	int do_clear = 0;
	int do_status = 0;
	int skip_check = 0;
	int ckod = 1; /* default CKOD=1 */
	int alg_override = -1;
	uint8_t alg_index = 0x01;
	struct ame_status st;

	static struct option opts[] = {
		{"dki",     required_argument, 0, 'i'},
		{"dk",      required_argument, 0, 'k'},
		{"clear",   no_argument,       0, 'c'},
		{"status",  no_argument,       0, 's'},
		{"no-ckod", no_argument,       0, 'n'},
		{"force",   no_argument,       0, 'f'},
		{"alg",     required_argument, 0, 'a'},
		{"help",    no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

	int c;
	while ((c = getopt_long(argc, argv, "i:k:csnfa:h", opts, NULL)) != -1) {
		switch (c) {
		case 'i': dki_str = optarg; break;
		case 'k': dk_str = optarg; break;
		case 'c': do_clear = 1; break;
		case 's': do_status = 1; break;
		case 'n': ckod = 0; break;
		case 'f': skip_check = 1; break;
		case 'a': alg_override = (int)strtol(optarg, NULL, 0); break;
		case 'h':
		default:
			usage(argv[0]);
			return c == 'h' ? 0 : 1;
		}
	}

	if (optind >= argc) {
		usage(argv[0]);
		return 1;
	}
	const char *dev = argv[optind];

	if (do_status && (do_clear || dki_str || dk_str)) {
		fprintf(stderr, "--status cannot be combined with --clear/--dki/--dk\n");
		return 1;
	}
	if (do_clear && (dki_str || dk_str)) {
		fprintf(stderr, "--clear cannot be combined with --dki/--dk\n");
		return 1;
	}
	if ((dki_str && !dk_str) || (!dki_str && dk_str)) {
		fprintf(stderr, "provide both --dki and --dk, or neither (to prompt)\n");
		return 1;
	}

	int fd = open(dev, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror(dev);
		return 1;
	}

	collect_status(fd, &st, 0);
	print_status(&st);
	printf("\n");

	if (do_status) {
		close(fd);
		return 0;
	}

	if (!skip_check) {
		if (st.mp30_ok && !st.is_ame) {
			fprintf(stderr,
				"Encryption solution is not AME (03h). "
				"SPOUT requires AME-T10. Use --force to override.\n");
			close(fd);
			return 1;
		}
		if (st.caps_ok && st.cfg_p == 2) {
			fprintf(stderr,
				"CFG_P prevents host key set. Use --force to override.\n");
			close(fd);
			return 1;
		}
	}

	alg_index = st.alg_index;
	if (alg_override >= 0)
		alg_index = (uint8_t)alg_override;

	uint8_t dki[DKI_LENGTH], dk[DK_LENGTH];
	int rc;

	if (do_clear) {
		fprintf(stderr, "Clearing encryption parameters (CKOD=%d)...\n", ckod);
		rc = spout_set_key(fd, NULL, NULL, alg_index, ckod);
	} else {
		if (dki_str) {
			if (parse_dki(dki_str, dki) < 0 || parse_dk_b64(dk_str, dk) < 0) {
				close(fd);
				return 1;
			}
		} else {
			if (!isatty(STDIN_FILENO)) {
				fprintf(stderr,
					"stdin is not a TTY; pass --dki and --dk explicitly\n");
				close(fd);
				return 1;
			}
			if (prompt_keys(dki, dk) < 0) {
				close(fd);
				return 1;
			}
		}
		fprintf(stderr, "Setting key (alg=0x%02X CKOD=%d ENCRYPT+MIXED)...\n",
			alg_index, ckod);
		rc = spout_set_key(fd, dki, dk, alg_index, ckod);
	}

	if (rc == 0) {
		fprintf(stderr, "OK\n\n");
	}

	close(fd);
	return rc == 0 ? 0 : 1;
}
