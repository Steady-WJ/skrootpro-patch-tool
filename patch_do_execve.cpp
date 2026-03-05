#include "patch_do_execve.h"
#include "analyze/base_func.h"
#include "3rdparty/aarch64_asm_helper.h"
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

#define MAX_ERRNO	4095
#define TIF_SECCOMP 11

PatchDoExecve::PatchDoExecve(const PatchBase& patch_base, const KernelSymbolOffset& sym) : PatchBase(patch_base) {
	m_do_execve_addr = sym.do_execveat_common;
}
PatchDoExecve::~PatchDoExecve() {}

size_t PatchDoExecve::patch_do_execve(const SymbolRegion& hook_func_start_region, size_t task_struct_cred_offset, size_t task_struct_seccomp_offset,
	std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {

	size_t hook_func_start_addr = hook_func_start_region.offset;
	if (hook_func_start_addr == 0) { return 0; }
	if (m_do_execve_addr == 0) { return 0; }
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;

	int atomic_usage_len = get_cred_atomic_usage_len();
	int securebits_padding = get_cred_securebits_padding();
	int securebits_len = 4 + securebits_padding;
	uint64_t cap_ability_max = get_cap_ability_max();

	size_t hook_jump_back_addr = m_do_execve_addr + 4;
	char empty_root_key_buf[ROOT_KEY_LEN] = { 0 };

	aarch64_asm_ctx asm_ctx = init_aarch64_asm();
	auto a = asm_ctx.assembler();
	Label label_end = a->newLabel();
	Label label_cycle_name = a->newLabel();
	int key_start = a->offset();
	a->embed((const uint8_t*)empty_root_key_buf, sizeof(empty_root_key_buf));
	// placeholder for original instruction (will be replaced)
	a->mov(x0, x0);
	// validate filename pointer (x1 = struct filename*)
	a->mov(x11, Imm(uint64_t(-MAX_ERRNO)));
	a->cmp(x1, x11);
	a->b(CondCode::kCS, label_end);
	// load filename->name (first member, char*)
	a->ldr(x11, ptr(x1));
	// compute root_key address
	int key_offset = key_start - a->offset();
	aarch64_asm_adr_x(a, x12, key_offset);
	// compare filename with root_key byte by byte
	a->bind(label_cycle_name);
	a->ldrb(w14, ptr(x11).post(1));
	a->ldrb(w15, ptr(x12).post(1));
	a->cmp(w14, w15);
	a->b(CondCode::kNE, label_end);
	a->cbnz(w15, label_cycle_name);
	// === ROOT privilege escalation ===
	// get current task_struct via mrs sp_el0
	emit_get_current(a, x12);
	// load cred pointer, skip atomic_usage
	a->ldr(x14, ptr(x12, task_struct_cred_offset));
	a->add(x14, x14, Imm(atomic_usage_len));
	// zero out uid/gid/suid/sgid/euid/egid/fsuid/fsgid (32 bytes)
	a->str(xzr, ptr(x14).post(8));
	a->str(xzr, ptr(x14).post(8));
	a->str(xzr, ptr(x14).post(8));
	a->str(xzr, ptr(x14).post(8));
	// zero out securebits
	a->str(wzr, ptr(x14).post(securebits_len));
	// set all 5 capabilities to max
	a->mov(x13, Imm(cap_ability_max));
	a->stp(x13, x13, ptr(x14).post(16));
	a->stp(x13, x13, ptr(x14).post(16));
	a->str(x13, ptr(x14).post(8));
	// clear TIF_SECCOMP flag via atomic operation on task_struct->flags
	a->ldaxr(x14, ptr(x12));
	a->mov(x15, Imm((uint64_t)1ULL << TIF_SECCOMP));
	a->bic(x14, x14, x15);
	a->stlxr(x15, x14, ptr(x12));
	// clear seccomp.mode
	a->str(wzr, ptr(x12, task_struct_seccomp_offset));
	// === end privilege escalation ===

	// === Pro 跳板：首次 execve 初始化标志 ===
	// die 区域头部预留了 4 字节 init_flag（由 patch_kernel_handler 写入初始值 0）。
	// 首次 root_key 匹配成功时将 init_flag 置 1，标记内核 patch 已激活。
	// 用户态 testInstall install 通过 kernel_module_kit SDK 检测此标志，
	// 部署 autorun bootstrap，后续开机自动加载 SKRoot 模块。
	{
		Label label_trampoline_skip = a->newLabel();
		int init_flag_offset = -4 - a->offset();
		aarch64_asm_adr_x(a, x13, init_flag_offset);
		a->ldr(w14, ptr(x13));
		a->cbnz(w14, label_trampoline_skip);
		a->mov(w14, Imm(1));
		a->str(w14, ptr(x13));
		a->bind(label_trampoline_skip);
	}

	a->bind(label_end);
	aarch64_asm_b(a, (int32_t)(hook_jump_back_addr - (hook_func_start_addr + a->offset())));
	std::cout << print_aarch64_asm(a) << std::endl;
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
	if (bytes.size() == 0) return 0;
	std::string str_bytes = bytes2hex((const unsigned char*)bytes.data(), bytes.size());
	size_t shellcode_size = str_bytes.length() / 2;
	// replace placeholder with original first instruction of do_execveat_common
	char hookOrigCmd[4] = { 0 };
	memcpy(&hookOrigCmd, (void*)((size_t)&m_file_buf[0] + m_do_execve_addr), sizeof(hookOrigCmd));
	std::string strHookOrigCmd = bytes2hex((const unsigned char*)hookOrigCmd, sizeof(hookOrigCmd));
	str_bytes = str_bytes.substr(0, sizeof(empty_root_key_buf) * 2) + strHookOrigCmd + str_bytes.substr(sizeof(empty_root_key_buf) * 2 + 0x4 * 2);

	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_do_execve failed: not enough kernel space." << std::endl;
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ str_bytes, hook_func_start_addr });
	// patch do_execveat_common entry: B to shellcode (skip root_key area)
	patch_jump(m_do_execve_addr, hook_func_start_addr + sizeof(empty_root_key_buf), vec_out_patch_bytes_data);
	return shellcode_size;
}
