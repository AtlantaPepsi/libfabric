
#ifndef _DMABUF_RDMA_TESTS_XE_H_
#define _DMABUF_RDMA_TESTS_XE_H_

#include <stdint.h>
#include "hmem.h"

#include <hsa/hsa.h>
#include <hsa/hsa_ext_amd.h>

#define MAX_GPUS	(16)

/*
 * Buffer location and method of allocation
 */
enum {
	MALLOC,	/* Host memory allocated via malloc and alike */
	HOST,	/* Host memory allocated via zeMemAllocHost */
	DEVICE,	/* Device memory allocated via zeMemAllocDevice */
	SHARED	/* Shared memory allocated via zeMemAllocShared */
};

/*
 * All information related to a buffer allocated via oneAPI L0 API.
 */
struct rocr_buf {
	void			*buf;
	void			*base;
	uint64_t		offset;
	size_t			size;
    	int             	dev;
	int             	type;
	int			location;
};

/*
 * Initialize GPU devices specified in the string of comma separated numbers.
 * Returns the number of GPU device successfully initialized.
 */
int	rocr_init(char *gpu_dev_nums, int enable_multi_gpu);

/*
 * Get the device number for the ith successfully initialized GPU.
 */
int	rocr_get_dev_num(int i);

/*
 * Alloctaed a buffer from specified location, on the speficied GPU if
 * applicable. The rocr_buf output is optional, can pass in NULL if the
 * information is not needed.
 */
void	*rocr_alloc_buf(size_t page_size, size_t size, int where, int gpu,
			struct rocr_buf *rocr_buf);

/*
 * Get the dma-buf fd associated with the buffer allocated with the oneAPI L0
 * functions. Return -1 if it's not a dma-buf object.
 */
int	rocr_get_buf_fd(void *buf);

/*
 * Show the fields of the rocr_buf structure.
 */
void	rocr_show_buf(struct rocr_buf *buf);

/*
 * Free the buffer allocated with rocr_alloc_buf.
 */
void	rocr_free_buf(void *buf, int where);

/*
 * Like memset(). Use oneAPI L0 to access device memory.
 */
void	rocr_set_buf(void *buf, char c, size_t size, int location, int gpu);

/*
 * Like memcpy(). Use oneAPI L0 to access device memory.
 */
void	rocr_copy_buf(void *dst, void *src, size_t size, int gpu);


/*
 * Registry for MOFED peer-mem plug-in
 */
int     dmabuf_reg_open(void);
void    dmabuf_reg_close(void);
int     dmabuf_reg_add(uint64_t base, uint64_t size, int fd);
void    dmabuf_reg_remove(uint64_t addr);

extern int	use_dmabuf_reg;
#endif /* _DMABUF_RDMA_TESTS_XE_H_ */

