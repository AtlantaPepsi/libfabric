#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include "util.h"
#include "rocr.h"

/*
 * Memory allocation & copy routines using ROCRr HSA calls
 */

extern int buf_location;
/*
struct gpu {
	int dev_num;
	int subdev_num;
};
static struct gpu gpus[MAX_GPUS];
*/
int use_dmabuf_reg;

static int num_gpus;

hsa_agent_t gpu_agents[MAX_GPUS];
hsa_region_t gpu_region[MAX_GPUS];
hsa_status_t hsa_ret;

static hsa_status_t region_cb(hsa_region_t region, void *data)
{
	static int id = -1;
	id++;
	hsa_status_t hsa_ret;
	hsa_region_segment_t hsa_segment;

	hsa_ret = hsa_region_get_info(region, HSA_REGION_INFO_SEGMENT,
				      &hsa_segment);

	if (hsa_ret == HSA_STATUS_SUCCESS &&
	    hsa_segment == HSA_REGION_SEGMENT_GLOBAL) {
        	printf("registered region %d of type %d\n", id, hsa_segment);
			gpu_region[id] = region;
        	return HSA_STATUS_INFO_BREAK;
	}

	return hsa_ret;
}

static hsa_status_t agent_cb(hsa_agent_t agent, void *data)
{
    	static int agent_id = -1, gpu_id = -1;
    	agent_id++;
	hsa_status_t hsa_ret;
	hsa_device_type_t hsa_dev_type;

	hsa_ret = hsa_agent_get_info(agent, HSA_AGENT_INFO_DEVICE,
				     (void *) &hsa_dev_type);

	if (hsa_ret == HSA_STATUS_SUCCESS &&
	    hsa_dev_type == HSA_DEVICE_TYPE_GPU) {
        	gpu_id++;
        	hsa_ret = hsa_agent_iterate_regions(agent, region_cb, NULL);
        	if (hsa_ret != HSA_STATUS_INFO_BREAK &&
            	    hsa_ret != HSA_STATUS_SUCCESS) {
            		printf("Failed to find GPU region\n");
        	} else {
            		printf("registered agent %d as %d th device\n", 
                   		agent_id, gpu_id);
		    	gpu_agents[gpu_id] = agent;
            		num_gpus++;
            		hsa_ret = HSA_STATUS_SUCCESS;
        	}
	}

	return hsa_ret;
}

int rocr_init(char *gpu_dev_nums, int enable_multi_gpu)
{
    	//ft_hmem_init(FI_HMEM_ROCR);
    	hsa_ret = hsa_init(); //<-- add device selection logic
   
	hsa_ret = hsa_iterate_agents(agent_cb, NULL);
	if (hsa_ret != HSA_STATUS_SUCCESS) {
		printf("Failed to find GPU agent\n");
	}
	num_gpus= 1;
    	return num_gpus;
}

void *rocr_alloc_buf(size_t page_size, size_t size, int where, int gpu,
	     	     struct rocr_buf *rocr_buf)
{
	void *buf = NULL;

    	switch (where) {
		case MALLOC:
			posix_memalign(&buf, page_size, size);
			break;
	  	case HOST:
		        // assuming page aligned
		        buf = malloc(size);
		        void *dev_addr = NULL;
		
		        hsa_status_t status = hsa_amd_memory_lock(buf, size, NULL, 0, &dev_addr);
        		if ((status != HSA_STATUS_SUCCESS) || (dev_addr == NULL)) {
            			printf("weeeee \n");
        		}
        		buf = dev_addr;
			break;
	  	case DEVICE:
		        // ft_rocr_alloc(gpu, &buf, size);
		        hsa_status_t hsa_ret;
		
		        hsa_ret = hsa_memory_allocate(gpu_region[gpu], size, &buf);
       			if (hsa_ret != HSA_STATUS_SUCCESS)
            			printf("cannot alloc device %d\n", gpu);
		
        		printf("allocated %p on device %d\n", buf, gpu);
			break;
	  	default:
        		printf("Should have been shared here\n");
			break;
	}

	if (rocr_buf) {
		rocr_buf->buf = buf;
		rocr_buf->size = size;
		rocr_buf->type = 0;
		rocr_buf->dev = gpu;
        	rocr_buf->location = where;
	}
	return buf;
}

void rocr_free_buf(void *buf, int where)
{
    	printf("freeing buf %p on %d\n", buf, where);
    	if (where == DEVICE)
	{
        	hsa_ret = hsa_memory_free(buf);
	    	if (hsa_ret != HSA_STATUS_SUCCESS)
            		printf("free failed\n");
	}
    	else {
        	free(buf);
    	}
    	printf("freed buf %p on %d\n", buf, where);
}

void rocr_copy_buf(void *dst, void *src, size_t size, int gpu)
{
    	hsa_ret = hsa_memory_copy(dst, src, size);
    	if (hsa_ret != HSA_STATUS_SUCCESS)
        	printf("copy failed\n");
}

void rocr_set_buf(void *buf, char c, size_t size, int location, int gpu)
{
	char integer[4] = {c, c, c, c};
	uint32_t value = *(uint32_t*)integer;
	
	if (location == DEVICE) {
        	hsa_ret = hsa_amd_memory_fill(buf, value, size / sizeof(uint32_t));
        	//ft_rocr_memset(0, buf, value, size);
    	} else {
        	memset(buf, c, size);
    	}
}
