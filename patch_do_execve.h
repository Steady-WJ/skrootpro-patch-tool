#pragma once
#include <iostream>
#include <vector>
#include "patch_base.h"

class PatchDoExecve : public PatchBase
{
public:
	PatchDoExecve(const PatchBase& patch_base, const KernelSymbolOffset &sym);
	~PatchDoExecve();

	size_t patch_do_execve(const SymbolRegion& hook_func_start_region, size_t task_struct_cred_offset, size_t task_struct_seccomp_offset,
		std::vector<patch_bytes_data>& vec_out_patch_bytes_data);

private:
	size_t m_do_execve_addr = 0;
};
