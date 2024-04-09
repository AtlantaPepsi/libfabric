#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include "util.h"
#include "rocr.h"

static int	ep_type = FI_EP_RDM;
static char	*prov_name;
static char	*domain_name;

static struct fi_info		*fi;
static struct fid_fabric	*fabric;
static struct fid_eq		*eq;
static struct fid_domain	*domain;
static struct fid_ep		*ep;
static struct fid_av		*av;
static struct fid_cq		*cq;
static struct fid_mr		*mr;

static enum fi_hmem_iface 	iface = FI_HMEM_SYSTEM;

static void	*buf;
static size_t	buf_size = 65536;
static int 	buf_location = MALLOC;

static void init_buf(void)
{
	int page_size = sysconf(_SC_PAGESIZE);

	buf = rocr_alloc_buf(page_size, buf_size, buf_location, 0, NULL);
	if (!buf) {
		fprintf(stderr, "Couldn't allocate work buf.\n");
		exit(-1);
	}
}

static void free_buf(void)
{
	rocr_free_buf(buf, buf_location);
}

static void init_ofi(void)
{
	struct fi_info *hints;
	struct fi_cq_attr cq_attr = {};
	struct fi_av_attr av_attr = {};
	struct fi_eq_attr eq_attr = {};
	int version;

	EXIT_ON_NULL((hints = fi_allocinfo()));

	hints->caps = FI_HMEM;
	hints->ep_attr->type = ep_type;
	if (prov_name)
		hints->fabric_attr->prov_name = strdup(prov_name);
	hints->domain_attr->mr_mode = (FI_MR_ALLOCATED | FI_MR_PROV_KEY |
				       FI_MR_VIRT_ADDR | FI_MR_LOCAL |
				       FI_MR_HMEM | FI_MR_ENDPOINT);
	if (domain_name)
		hints->domain_attr->name = strdup(domain_name);

	version = FI_VERSION(1, 12);

	if (ep_type == FI_EP_RDM)
		EXIT_ON_ERROR(fi_getinfo(version, NULL, NULL, 0, hints, &fi));
	else
		EXIT_ON_ERROR(fi_getinfo(version, "localhost", "12345", 0,
					 hints, &fi));

	fi_freeinfo(hints);

	printf("Using OFI device: %s (%s)\n", fi->fabric_attr->prov_name,
		fi->domain_attr->name);

	EXIT_ON_ERROR(fi_fabric(fi->fabric_attr, &fabric, NULL));
	EXIT_ON_ERROR(fi_domain(fabric, fi, &domain, NULL));
	EXIT_ON_ERROR(fi_endpoint(domain, fi, &ep, NULL));
	EXIT_ON_ERROR(fi_cq_open(domain, &cq_attr, &cq, NULL));
	if (ep_type == FI_EP_RDM) {
		EXIT_ON_ERROR(fi_av_open(domain, &av_attr, &av, NULL));
		EXIT_ON_ERROR(fi_ep_bind(ep, (fid_t)av, 0));
	} else {
		EXIT_ON_ERROR(fi_eq_open(fabric, &eq_attr, &eq, NULL));
		EXIT_ON_ERROR(fi_ep_bind(ep, (fid_t)eq, 0));
	}
	EXIT_ON_ERROR(fi_ep_bind(ep, (fid_t)cq, (FI_TRANSMIT | FI_RECV |
						 FI_SELECTIVE_COMPLETION)));
	EXIT_ON_ERROR(fi_enable(ep));
}

void reg_mr_hmem(void)
{
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = buf_size,
	};
	struct fi_mr_attr mr_attr = {
		.mr_iov = &iov,
		.iov_count = 1,
		.access = FI_REMOTE_READ | FI_REMOTE_WRITE,
		.requested_key = 1,
		.iface = iface,
	};

	CHECK_ERROR(fi_mr_regattr(domain, &mr_attr, 0, &mr));

	if (fi->domain_attr->mr_mode & FI_MR_ENDPOINT) {
		CHECK_ERROR(fi_mr_bind(mr, (fid_t)ep, 0));
		CHECK_ERROR(fi_mr_enable(mr));
	}

	printf("mr %p, buf %p, rkey 0x%lx, len %zd\n",
		mr, buf, fi_mr_key(mr), buf_size);

err_out:
	return;
}

void reg_mr_dmabuf(void)
{
	int fd = -1, offset = -1;
	rocr_get_buf_fd(buf, buf_size, &fd, &offset);
	assert(!offset);

	struct fi_mr_dmabuf dmabuf = {
		.fd = fd,
		.offset = 0,
		.len = buf_size,
		.base_addr = NULL,
	};

	struct fi_mr_attr mr_attr = {
		.dmabuf = &dmabuf,
		.access = FI_REMOTE_READ | FI_REMOTE_WRITE,
		.requested_key = 1,
	};
	//mr_attr.dmabuf = &dmabuf; // necessary
	printf("offset %zu, base %p, dmabuf %p\n",mr_attr.dmabuf->offset,mr_attr.dmabuf->base_addr,mr_attr.dmabuf);

	CHECK_ERROR(fi_mr_regattr(domain, &mr_attr,FI_MR_DMABUF, &mr));

	if (fi->domain_attr->mr_mode & FI_MR_ENDPOINT) {
		CHECK_ERROR(fi_mr_bind(mr, &ep->fid, 0));
		CHECK_ERROR(fi_mr_enable(mr));
	}

	printf("mr dma %p, buf %p, rkey 0x%lx, len %zd\n",
		mr, buf, fi_mr_key(mr), buf_size);

err_out:
	return;
}

void dereg_mr(void)
{
	if (mr)
		fi_close(&mr->fid);
}

static void finalize_ofi(void)
{
	fi_close((fid_t)ep);
	if (ep_type == FI_EP_RDM)
		fi_close((fid_t)av);
	fi_close((fid_t)cq);
	fi_close((fid_t)domain);
	if (ep_type == FI_EP_MSG)
		fi_close((fid_t)eq);
	fi_close((fid_t)fabric);
	fi_freeinfo(fi);
}

static void usage(char *prog)
{
	printf("Usage: %s [options]\n", prog);
	printf("Options:\n");
	printf("\t-m <location>    Where to allocate the buffer, can be 'malloc', 'host', 'device' or 'shared', default: malloc\n");
	printf("\t-d <x>           Use the GPU device <x>, default: 0\n");
	printf("\t-e <ep_type>     Set the endpoint type, can be 'rdm' or 'msg', default: rdm\n");
	printf("\t-p <prov_name>   Use the OFI provider named as <prov_name>, default: the first one\n");
	printf("\t-D <domain_name> Open OFI domain named as <domain_name>, default: automatic\n");
	printf("\t-S <size>        Set the buffer size, default: 65536\n");
	printf("\t-i <iface>       Choose verbs MR register flags and policy, can be 'hmem_s', 'hmem_r' or 'dmabuf', default: dmabuf\n");
	printf("\t-h               Print this message\n");
}

int main(int argc, char *argv[])
{
/* 	??
	putenv("FI_HMEM_ROCR_USE_DMABUF=1");
	putenv("FI_VERBS_USE_DMABUF=1");
*/
	char *gpu_dev_nums = NULL;
	int c;

	while ((c = getopt(argc, argv, "d:D:e:p:m:S:i:h")) != -1) {
		switch (c) {
		case 'd':
			gpu_dev_nums = strdup(optarg);
			break;
		case 'D':
			domain_name = strdup(optarg);
			break;
		case 'e':
			if (!strcmp(optarg, "rdm"))
				ep_type = FI_EP_RDM;
			else if (!strcmp(optarg, "msg"))
				ep_type = FI_EP_MSG;
			else
				printf("Invalid ep type %s, use default\n", optarg);
			break;
		case 'p':
			prov_name = strdup(optarg);
			break;
		case 'm':
			if (!strcmp(optarg, "malloc"))
				buf_location = MALLOC;
			else if (!strcmp(optarg, "host"))
				buf_location = HOST;
			else if (!strcmp(optarg, "device"))
				buf_location = DEVICE;
			else
				printf("Invalid buffer location %s, use default\n", optarg);
			break;
		case 'S':
			buf_size = atoi(optarg);
			break;
		case 'i':
			if (!strcmp(optarg, "hmem_r"))
				iface = FI_HMEM_ROCR;
			else if (!strcmp(optarg, "hmem_s"))
				iface = FI_HMEM_SYSTEM;
			else if (!strcmp(optarg, "dmabuf"))
				iface = -1;
			else
				printf("Invalid FI MR interface %s, use default\n", optarg);
			break;
		default:
			usage(argv[0]);
			exit(-1);
			break;
		}
	}

	if (buf_location != DEVICE && iface != FI_HMEM_SYSTEM)
	{
		printf("error: HMEM_ROCR and dmabuf are not applicable for non-device memory\n");
		exit(1);
	}

	if (buf_location != MALLOC)
		rocr_init(gpu_dev_nums, 0);

	init_buf();
	init_ofi();

	if (iface != -1)
		reg_mr_hmem();
	else
		reg_mr_dmabuf();

	dereg_mr();


	finalize_ofi();
	free_buf();

	return 0;
}
