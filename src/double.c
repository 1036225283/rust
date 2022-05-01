#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#ifdef MAC
#include <OpenCL/cl.h>
#else
#include <CL/cl.h>
#endif

typedef struct Student
{
    int num;
    int total;
    char name[238068];
    float scores[3];
} Student;

Student STU;

void print_data(Student *stu)
{
    // printf("C side print: %d %s %d %.2f %.2f %.2f\n",
    //        stu->num,
    //        stu->name,
    //        stu->total,
    //        stu->scores[0],
    //        stu->scores[1],
    //        stu->scores[2]);

    printf("C side print: %d %s %d %.2f %.2f %.2f\n",
           STU.num,
           STU.name,
           STU.total,
           STU.scores[0],
           STU.scores[1],
           STU.scores[2]);
}

void fill_data(Student *stu)
{
    stu->num = 2;
    stu->total = 100;
    // strcpy(stu->name, "Bob");
    stu->scores[0] = 60.6;
    stu->scores[1] = 70.7;
    stu->scores[2] = 80.8;

    STU.num = stu->num;
    STU.total = stu->total;
    strcpy(STU.name, stu->name);
    for (int i = 0; i < 3; i++)
    {
        STU.scores[i] = stu->scores[i];
    }
}

int test()
{
    /* code */
    printf("this is test\n");

    cl_int err;
    cl_platform_id platform;
    err = clGetPlatformIDs(1, &platform, NULL);
    if (err != CL_SUCCESS)
    {
        printf("Cannot get platform");
        return -1;
    }

    cl_device_id device;
    err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_ALL, 1, &device, NULL);
    if (err != CL_SUCCESS)
    {
        printf("Cannot get device");

        return -1;
    }

    cl_context context = clCreateContext(NULL, 1, &device, NULL, NULL, &err);
    if (err != CL_SUCCESS)
    {
        printf("Create context failed");
        return -1;
    }

    cl_command_queue queue = clCreateCommandQueue(context, device, 0, &err);
    if (err != CL_SUCCESS)
    {
        printf("Create command queue failed");
        return -1;
    }

    const uint32_t cal_num = 10000;
    uint32_t *hA = (uint32_t *)malloc(cal_num * sizeof(uint32_t));
    ;
    uint32_t *hB = (uint32_t *)malloc(cal_num * sizeof(uint32_t));
    ;
    uint32_t *hC = (uint32_t *)malloc(cal_num * sizeof(uint32_t));
    ;

    // initialize data
    memset(hC, 0, sizeof(uint32_t) * cal_num);
    for (uint32_t i = 0; i < cal_num; i++)
    {
        hA[i] = hB[i] = i;
    }

    cl_mem mA = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(uint32_t) * cal_num, hA, NULL);
    cl_mem mB = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(uint32_t) * cal_num, hB, NULL);
    cl_mem mC = clCreateBuffer(context, CL_MEM_READ_WRITE, sizeof(uint32_t) * cal_num, NULL, NULL);
    if (mA == NULL || mB == NULL || mC == NULL)
    {
        printf("Create buffer failed");

        return -1;
    }
    char input_code[238067];

    char *program_source = "int double_input(int input){return input * 2;}__kernel void test_main(__global const uint* A, __global const uint* B, __global uint* C) { size_t idx = get_global_id(0); C[idx] = A[idx] + B[idx]; }\n\n";
    // const char *program_source ="__kernel void test_main(__global const uint* A, __global const uint* B, __global uint* C) {  }";

    for (int i = 0; i < 198; i++)
    {
        input_code[i] = program_source[i];
        printf("%d ", input_code[i]);
    }

    input_code[198] = "\0";
    // char * input_code_point = &input_code;
    char *input_code_point = &(STU.name);

    size_t input_size = 238068;
    // size_t input_size = 198;

    printf("\nss = %s \n", program_source);

    cl_int *errcode_ret;

    // cl_program program = clCreateProgramWithSource(context, 1, &program_source, &input_size , NULL);
    cl_program program = clCreateProgramWithSource(context, 1, &input_code_point, &input_size, NULL);
    if (program == NULL)
    {
        printf("Create program failed, %ls ", errcode_ret);
        return -1;
    }

    size_t log_size;
    char *program_log;
    err = clBuildProgram(program, 0, NULL, NULL, NULL, NULL);
    if (err != CL_SUCCESS)
    {
        printf("Build program failed %d ", err);
        //确定日志文件的大小
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);
        printf("Build program failed %d ", log_size);

        program_log = (char *)malloc(log_size + 1);
        program_log[log_size] = '\0';
        //读取日志
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, log_size + 1, program_log, NULL);
        printf("%s\n", program_log);
        free(program_log);
        return -1;
    }

    cl_kernel kernel = clCreateKernel(program, "int_to_address", errcode_ret);
    if (kernel == NULL)
    {

        printf("Create kernel failed, %ls ", errcode_ret);
        return -1;
    }

    // err = clSetKernelArg(kernel, 0, sizeof(cl_mem), &mA);
    // err |= clSetKernelArg(kernel, 1, sizeof(cl_mem), &mB);
    // err |= clSetKernelArg(kernel, 2, sizeof(cl_mem), &mC);
    // if (err != CL_SUCCESS)
    // {
    //     printf("Set kernel arg failed");
    //     return -1;
    // }

    // // size_t global_size[]{cal_num};
    // size_t global_size = cal_num;
    // // size_t local_size[]{cal_num / 10};
    // size_t local_size = cal_num / 10;
    // err = clEnqueueNDRangeKernel(queue, kernel, 1, NULL, &global_size, &local_size, 0, NULL, NULL);
    // if (err != CL_SUCCESS)
    // {
    //     printf("Run kernel failed");
    //     return -1;
    // }

    // err = clEnqueueReadBuffer(queue, mC, CL_TRUE, 0, sizeof(uint32_t) * cal_num, hC, 0, NULL, NULL);
    // if (err != CL_SUCCESS)
    // {
    //     printf("Read data failed");
    //     return -1;
    // }

    // // check one output data
    // if (hC[1024] != hA[1024] + hB[1024])
    // {
    //     printf("Data calculation failed");
    //     return -1;
    // }

    // printf(" data = %d \n", hC[1025]);
    // printf("this is end\n");

    return 0;
}

int *luck()
{
    int *arr = (int *)malloc(10 * sizeof(int));
    for (int i = 0; i < 10; i++)
    {
        arr[i] = i;
    }

    return arr;
}

void show(int8_t *input, int length)
{
    for (int i = 0; i < length; i++)
    {
        printf("test %d", input[i]);
    }
}

int double_input(int input)
{
    test();
    return input * 2;
}
