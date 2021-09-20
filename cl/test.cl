int main(int argc, char **argv) {

  // 创建设备

  cl_int err;
  cl_platform_id platform;
  err = clGetPlatformIDs(1, &platform, nullptr);
  if (err != CL_SUCCESS) {
    std::cout << "Cannot get platform" << std::endl;
    return -1;
  }

  cl_device_id device;
  err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_ALL, 1, &device, nullptr);
  if (err != CL_SUCCESS) {
    std::cout << "Cannot get device" << std::endl;
    return -1;
  }

  // 创建命令队列
  cl_context context =
      clCreateContext(nullptr, 1, &device, nullptr, nullptr, &err);
  if (err != CL_SUCCESS) {
    std::cout << "Create context failed" << std::endl;
    return -1;
  }

  cl_command_queue queue = clCreateCommandQueue(context, device, 0, &err);
  if (err != CL_SUCCESS) {
    std::cout << "Create command queue failed" << std::endl;
    return -1;
  }

  // 创建主机内存
  const uint32_t cal_num = 10000;
  uint32_t *hA = new uint32_t[cal_num];
  uint32_t *hB = new uint32_t[cal_num];
  uint32_t *hC = new uint32_t[cal_num];

  // initialize data
  memset(hC, 0, sizeof(uint32_t) * cal_num);
  for (uint32_t i = 0; i < cal_num; i++) {
    hA[i] = hB[i] = i;
  }

  // 创建GPU 内存
  cl_mem mA = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                             sizeof(uint32_t) * cal_num, hA, nullptr);
  cl_mem mB = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                             sizeof(uint32_t) * cal_num, hB, nullptr);
  cl_mem mC = clCreateBuffer(context, CL_MEM_READ_WRITE,
                             sizeof(uint32_t) * cal_num, nullptr, nullptr);
  if (mA == nullptr || mB == nullptr || mC == nullptr) {
    std::cout << "Create buffer failed" << std::endl;
    return -1;
  }

  // 创建GPU kernel函数
  const char *program_source =
      "__kernel void test_main(__global const uint* A, __global const uint* B, "
      "__global uint* C) {\n"
      "  size_t idx = get_global_id(0);\n"
      "  C[idx] = A[idx] + B[idx];\n"
      "}";

  // 从资源文件创建kernel函数
  cl_program program =
      clCreateProgramWithSource(context, 1, &program_source, nullptr, nullptr);
  if (program == nullptr) {
    std::cout << "Create program failed" << std::endl;
    return -1;
  }

  // 编译
  err = clBuildProgram(program, 0, nullptr, nullptr, nullptr, nullptr);
  if (err != CL_SUCCESS) {
    std::cout << "Build program failed" << std::endl;
    return -1;
  }

  // 创建kernel
  cl_kernel kernel = clCreateKernel(program, "test_main", nullptr);
  if (kernel == nullptr) {
    std::cout << "Create kernel failed" << std::endl;
    return -1;
  }

  // 映射内存,哪个bufffer对应到哪个kernel
  err = clSetKernelArg(kernel, 0, sizeof(cl_mem), &mA);
  err |= clSetKernelArg(kernel, 1, sizeof(cl_mem), &mB);
  err |= clSetKernelArg(kernel, 2, sizeof(cl_mem), &mC);
  if (err != CL_SUCCESS) {
    std::cout << "Set kernel arg failed" << std::endl;
    return -1;
  }

  // 执行,global_size 执行多少次,也就是kernel获取到的get_global_id,
  // local_size,每执行一组要多少次运算 global_size / local_size =  执行多少组
  size_t global_size[]{cal_num};
  size_t local_size[]{cal_num / 10};
  err = clEnqueueNDRangeKernel(queue, kernel, 1, nullptr, global_size,
                               local_size, 0, nullptr, nullptr);
  if (err != CL_SUCCESS) {
    std::cout << "Run kernel failed" << std::endl;
    return -1;
  }

  // 拿到输出结果
  err = clEnqueueReadBuffer(queue, mC, CL_TRUE, 0, sizeof(uint32_t) * cal_num,
                            hC, 0, nullptr, nullptr);
  if (err != CL_SUCCESS) {
    std::cout << "Read data failed" << std::endl;
    return -1;
  }

  // check one output data
  if (hC[1024] != hA[1024] + hB[1024]) {
    std::cout << "Data calculation failed" << std::endl;
    return -1;
  }

  return 0;
}
}