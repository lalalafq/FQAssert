//
// Copyright (c) 2008-present, Meitu, Inc.
// All rights reserved.
//
// This source code is licensed under the license found in the LICENSE file in
// the root directory of this source tree.
//
// Created on: 2020/5/20
// Created by: fuqi
//


#import "FQAssert.h"
#include <stdbool.h>
#include <stdint.h>
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>


#pragma - mark DEFINE MACRO FOR DIFFERENT CPU ARCHITECTURE
#ifdef __LP64__
    #define STRUCT_NLIST struct nlist_64
#else
    #define STRUCT_NLIST struct nlist
#endif

#define CALL_INSTRUCTION_FROM_RETURN_ADDRESS(A) (DETAG_INSTRUCTION_ADDRESS((A)) - 1)

#if defined(__arm64__)
#define DETAG_INSTRUCTION_ADDRESS(A) ((A) & ~(3UL))
#define MT_THREAD_STATE_COUNT ARM_THREAD_STATE64_COUNT
#define MT_THREAD_STATE ARM_THREAD_STATE64
#define MT_FRAME_POINTER __fp
#define MT_STACK_POINTER __sp
#define MT_INSTRUCTION_ADDRESS __pc

#elif defined(__arm__)
#define DETAG_INSTRUCTION_ADDRESS(A) ((A) & ~(1UL))
#define MT_THREAD_STATE_COUNT ARM_THREAD_STATE_COUNT
#define MT_THREAD_STATE ARM_THREAD_STATE
#define MT_FRAME_POINTER __r[7]
#define MT_STACK_POINTER __sp
#define MT_INSTRUCTION_ADDRESS __pc

#elif defined(__x86_64__)
#define DETAG_INSTRUCTION_ADDRESS(A) (A)
#define MT_THREAD_STATE_COUNT x86_THREAD_STATE64_COUNT
#define MT_THREAD_STATE x86_THREAD_STATE64
#define MT_FRAME_POINTER __rbp
#define MT_STACK_POINTER __rsp
#define MT_INSTRUCTION_ADDRESS __rip

#elif defined(__i386__)
#define DETAG_INSTRUCTION_ADDRESS(A) (A)
#define MT_THREAD_STATE_COUNT x86_THREAD_STATE32_COUNT
#define MT_THREAD_STATE x86_THREAD_STATE32
#define MT_FRAME_POINTER __ebp
#define MT_STACK_POINTER __esp
#define MT_INSTRUCTION_ADDRESS __eip

#endif


@implementation FQAssert

typedef struct {
    uintptr_t *frames;
    size_t frames_size;
} fq_stack_backtrace;


typedef struct _fq_stackframe_entity {
    const struct _fq_stackframe_entity *const previous;
    const uintptr_t return_address;
} fq_stackframe_entity;

static kern_return_t fq_mach_copy_mem(const void *const src, void *const dst, const size_t num_bytes) {
    vm_size_t bytes_copied = 0;
    return vm_read_overwrite(mach_task_self(), (vm_address_t)src, (vm_size_t)num_bytes, (vm_address_t)dst, &bytes_copied);
}


#pragma mark - 回溯找堆栈
static fq_stack_backtrace *fq_malloc_stack_backtrace() {
    fq_stack_backtrace *stackframes = (fq_stack_backtrace *)malloc(sizeof(fq_stack_backtrace));
    if (stackframes) {
        memset(stackframes, 0, sizeof(fq_stack_backtrace));
    }
    return stackframes;
}

static void fq_free_stack_backtrace(fq_stack_backtrace *stackframes) {
    if (stackframes == nil)
        return;

    if (stackframes->frames) {
        free(stackframes->frames);
        stackframes->frames = nil;
    }
    stackframes->frames_size = 0;

    free(stackframes);
}

static bool fq_stack_backtrace_of_thread(thread_t thread, fq_stack_backtrace *out_stack_backtrace, const size_t backtrace_depth_max, uintptr_t top_frames_to_skip) {
    if (out_stack_backtrace == nil)
        return false;


    _STRUCT_MCONTEXT machine_context;
    mach_msg_type_number_t state_count = MT_THREAD_STATE_COUNT;
    kern_return_t kr = thread_get_state(thread, MT_THREAD_STATE, (thread_state_t)(&machine_context.__ss), &state_count);
    if (kr != KERN_SUCCESS) {
        return false;
    }

    size_t frames_size = 0;
    uintptr_t backtrace_frames[backtrace_depth_max];

    const uintptr_t instruction_addr = machine_context.__ss.MT_INSTRUCTION_ADDRESS;
    if (instruction_addr) {
        backtrace_frames[frames_size++] = instruction_addr;
    } else {
        out_stack_backtrace->frames_size = frames_size;
        return false;
    }

    uintptr_t link_register = 0;

#if defined(__i386__) || defined(__x86_64__)
    link_register = 0;
#else
    link_register = machine_context.__ss.__lr;
#endif //mt_mach_linkRegister(&machineContext);

    if (link_register) {
        backtrace_frames[frames_size++] = CALL_INSTRUCTION_FROM_RETURN_ADDRESS(link_register);
    }

    // get frame point
    fq_stackframe_entity frame = {NULL, 0};
    const uintptr_t frame_ptr = machine_context.__ss.MT_FRAME_POINTER;
    if (frame_ptr == 0 || fq_mach_copy_mem((void *)frame_ptr, &frame, sizeof(frame)) != KERN_SUCCESS) {
        out_stack_backtrace->frames_size = frames_size;
        return false;
    }


    for (; frames_size < backtrace_depth_max; frames_size++) {
        backtrace_frames[frames_size] = CALL_INSTRUCTION_FROM_RETURN_ADDRESS(frame.return_address);
        if (backtrace_frames[frames_size] == 0 || frame.previous == 0 || fq_mach_copy_mem(frame.previous, &frame, sizeof(frame)) != KERN_SUCCESS) {
            break;
        }
    }

    if (top_frames_to_skip >= frames_size) {
        out_stack_backtrace->frames_size = 0;
        out_stack_backtrace->frames = NULL;
        return false;
    }

    size_t output_frames_size = frames_size - top_frames_to_skip;
    out_stack_backtrace->frames_size = output_frames_size;
    out_stack_backtrace->frames = (uintptr_t *)malloc(sizeof(uintptr_t) * output_frames_size);
    memcpy(out_stack_backtrace->frames, backtrace_frames + top_frames_to_skip, sizeof(uintptr_t) * output_frames_size);


    return true;
}


#pragma mark - 符号化
static uintptr_t firstCmdAfterHeader(const struct mach_header* const header)
{
    switch(header->magic)
    {
        case MH_MAGIC:
        case MH_CIGAM:
            return (uintptr_t)(header + 1);
        case MH_MAGIC_64:
        case MH_CIGAM_64:
            return (uintptr_t)(((struct mach_header_64*)header) + 1);
        default:
            // Header is corrupt
            return 0;
    }
}

static uint32_t imageIndexContainingAddress(const uintptr_t address)
{
    const uint32_t imageCount = _dyld_image_count();
    const struct mach_header* header = 0;
    
    for(uint32_t iImg = 0; iImg < imageCount; iImg++)
    {
        header = _dyld_get_image_header(iImg);
        if(header != NULL)
        {
            // Look for a segment command with this address within its range.
            uintptr_t addressWSlide = address - (uintptr_t)_dyld_get_image_vmaddr_slide(iImg);
            uintptr_t cmdPtr = firstCmdAfterHeader(header);
            if(cmdPtr == 0)
            {
                continue;
            }
            for(uint32_t iCmd = 0; iCmd < header->ncmds; iCmd++)
            {
                const struct load_command* loadCmd = (struct load_command*)cmdPtr;
                if(loadCmd->cmd == LC_SEGMENT)
                {
                    const struct segment_command* segCmd = (struct segment_command*)cmdPtr;
                    if(addressWSlide >= segCmd->vmaddr &&
                       addressWSlide < segCmd->vmaddr + segCmd->vmsize)
                    {
                        return iImg;
                    }
                }
                else if(loadCmd->cmd == LC_SEGMENT_64)
                {
                    const struct segment_command_64* segCmd = (struct segment_command_64*)cmdPtr;
                    if(addressWSlide >= segCmd->vmaddr &&
                       addressWSlide < segCmd->vmaddr + segCmd->vmsize)
                    {
                        return iImg;
                    }
                }
                cmdPtr += loadCmd->cmdsize;
            }
        }
    }
    return UINT_MAX;
}

static uintptr_t segmentBaseOfImageIndex(const uint32_t idx)
{
    const struct mach_header* header = _dyld_get_image_header(idx);
    
    // Look for a segment command and return the file image address.
    uintptr_t cmdPtr = firstCmdAfterHeader(header);
    if(cmdPtr == 0)
    {
        return 0;
    }
    for(uint32_t i = 0;i < header->ncmds; i++)
    {
        const struct load_command* loadCmd = (struct load_command*)cmdPtr;
        if(loadCmd->cmd == LC_SEGMENT)
        {
            const struct segment_command* segmentCmd = (struct segment_command*)cmdPtr;
            if(strcmp(segmentCmd->segname, SEG_LINKEDIT) == 0)
            {
                return segmentCmd->vmaddr - segmentCmd->fileoff;
            }
        }
        else if(loadCmd->cmd == LC_SEGMENT_64)
        {
            const struct segment_command_64* segmentCmd = (struct segment_command_64*)cmdPtr;
            if(strcmp(segmentCmd->segname, SEG_LINKEDIT) == 0)
            {
                return (uintptr_t)(segmentCmd->vmaddr - segmentCmd->fileoff);
            }
        }
        cmdPtr += loadCmd->cmdsize;
    }
    
    return 0;
}

static bool ksdl_dladdr(const uintptr_t address, Dl_info* const info)
{
    info->dli_fname = NULL;
    info->dli_fbase = NULL;
    info->dli_sname = NULL;
    info->dli_saddr = NULL;

    // 首先通过地址在load_command中判断是否在segment的区间中，[segCmd->vmaddr,segCmd->vmaddr + segCmd->vmsize]
    const uint32_t idx = imageIndexContainingAddress(address);
    if(idx == UINT_MAX)
    {
        return false;
    }
    // head目录的地址，这里拿到的的其实就是这个镜像在crash中的首地址
    const struct mach_header* header = _dyld_get_image_header(idx);
    // 镜像的虚拟地址偏移
    const uintptr_t imageVMAddrSlide = (uintptr_t)_dyld_get_image_vmaddr_slide(idx);
    // 传入地址 除去 偏移量相。(初步可以理解相对地址)
    const uintptr_t addressWithSlide = address - imageVMAddrSlide;
    // sgement片段的地址 = 片段在镜像中的位置（??有点问题,line edit 中segmentCmd->vmaddr - segmentCmd->fileoff） + 镜像的虚拟地址偏移
    // 基址 = __LINKEDIT.VM_Address - __LINK.File_Offset + silde
    const uintptr_t segmentBase = segmentBaseOfImageIndex(idx) + imageVMAddrSlide;
    if(segmentBase == 0)
    {
        return false;
    }

    info->dli_fname = _dyld_get_image_name(idx);
    info->dli_fbase = (void*)header;

    // Find symbol tables and get whichever symbol is closest to the address.
    const STRUCT_NLIST* bestMatch = NULL;
    uintptr_t bestDistance = ULONG_MAX;
    uintptr_t cmdPtr = firstCmdAfterHeader(header);
    if(cmdPtr == 0)
    {
        return false;
    }
    for(uint32_t iCmd = 0; iCmd < header->ncmds; iCmd++)
    {
        const struct load_command* loadCmd = (struct load_command*)cmdPtr;
        if(loadCmd->cmd == LC_SYMTAB)// 读取所有load_cmd，找到symtab为止
        {
            const struct symtab_command* symtabCmd = (struct symtab_command*)cmdPtr;
            
            // 这是个数组列表。 这个地址是pagezero的地址
            // 这步有点复杂。基址 = line edit 中segmentCmd->vmaddr - segmentCmd->fileoff + 镜像的虚拟地址偏移 + symtabCmd->symoff
            // 这个寻址过程没理解
            const STRUCT_NLIST* symbolTable = (STRUCT_NLIST*)(segmentBase + symtabCmd->symoff);
            const uintptr_t stringTable = segmentBase + symtabCmd->stroff;

            for(uint32_t iSym = 0; iSym < symtabCmd->nsyms; iSym++)
            {
                // If n_value is 0, the symbol refers to an external 外部 object.
                if(symbolTable[iSym].n_value != 0)
                {
                    // 找到一个最合适的地址，并且这个地址大于符号的基地址
                    uintptr_t symbolBase = symbolTable[iSym].n_value;
                    uintptr_t currentDistance = addressWithSlide - symbolBase;
                    if((addressWithSlide >= symbolBase) &&
                       (currentDistance <= bestDistance))
                    {
                        bestMatch = symbolTable + iSym;
                        bestDistance = currentDistance;
                    }
                }
            }
            if(bestMatch != NULL)
            {
                info->dli_saddr = (void*)(bestMatch->n_value + imageVMAddrSlide);
                if(bestMatch->n_desc == 16)
                {
                    // This image has been stripped. The name is meaningless, and
                    // almost certainly resolves to "_mh_execute_header"
                    info->dli_sname = NULL;
                }
                else
                {
                    info->dli_sname = (char*)((intptr_t)stringTable + (intptr_t)bestMatch->n_un.n_strx);
                    if(*info->dli_sname == '_')
                    {
                        info->dli_sname++;
                    }
                }
                break;
            }
        }
        cmdPtr += loadCmd->cmdsize;
    }

    
    return true;
}


+ (NSString *)backtrace {
    fq_stack_backtrace *stackframes = fq_malloc_stack_backtrace();
    if (stackframes) {
        fq_stack_backtrace_of_thread(mach_thread_self(), stackframes, 50, 5);
    }
    
    Dl_info symbolsBuffer;
    NSMutableString *string = [NSMutableString string];
    for (size_t i = 0; i < stackframes->frames_size;i++)
    {
        if(ksdl_dladdr(CALL_INSTRUCTION_FROM_RETURN_ADDRESS(stackframes->frames[i]), &symbolsBuffer))
        {
            if (!symbolsBuffer.dli_fname || !symbolsBuffer.dli_sname) {
                break;
            }
            
            NSString *funName = [[NSString alloc] initWithUTF8String:symbolsBuffer.dli_sname];
            
            if ([funName rangeOfString:@"<redacted>"].length) {
                NSString *libName = [[NSString alloc] initWithUTF8String:symbolsBuffer.dli_fname];
                NSArray *libNameArray = [libName componentsSeparatedByString:@"/"];
                libName = [[libNameArray subarrayWithRange:NSMakeRange(libNameArray.count - 2, 2)] componentsJoinedByString:@"/"];
                funName = [NSString stringWithFormat:@"%@  %@\n",libName,funName];
            }
            
            [string appendString:funName];
            [string appendString:@"\n"];
//            if (symbolsBuffer.dli_fname) {
//                [string appendString:[[NSString alloc] initWithUTF8String:symbolsBuffer.dli_fname]];
//            }
//            [string appendString:@"    "];
//            if (symbolsBuffer.dli_sname) {
//                [string appendString:[[NSString alloc] initWithUTF8String:symbolsBuffer.dli_fname]];
//            }
//            [string appendString:@"\n"];
        }
        
    }
    fq_free_stack_backtrace(stackframes);
    NSString *strRtn = [NSString stringWithString:string];
    return strRtn;
}




@end
