#include <iostream>
#include <string>
#include <fstream>
#include <map>
#include <cstdint>
#include <intel-pt.h>
#include <capstone/capstone.h>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include "extractor/pt_extractor.hh"
#include "extractor/perf_file.hh"
#include "trace.pb.h"

using namespace google::protobuf::io;

static int extract_branch(csh handle, struct pt_insn& pt_ins, CodeBranch& branch)
{
    cs_insn* cap_ins;

    // Disassembly
    size_t count = cs_disasm(handle, pt_ins.raw, sizeof(pt_ins.raw),
            pt_ins.ip, 1, &cap_ins);

    if(count < 1)
        return -1;

    // Parsing
    cs_detail* d = cap_ins->detail;
    cs_x86_op ins_arg;

    for(int j = 0; j < d->groups_count; j++) {
        switch(d->groups[j]) {
            case X86_GRP_JUMP:
                branch.address = cap_ins->address;

                // A jump has at least an argument
                ins_arg = d->x86.operands[0];

                if(ins_arg.type == X86_OP_IMM) {
                    branch.ok = ins_arg.imm;

                    if(cap_ins->id == X86_INS_JMP) {
                        branch.type = CodeBranchType::Jump;
                    } else {
                        // Conditional branch
                        branch.type = CodeBranchType::CondJump;
                        branch.fail = cap_ins->address + cap_ins->size;
                    }
                } else {
                    branch.type = CodeBranchType::IndJump;
                }

                break;
            case X86_GRP_RET:
                branch.address = cap_ins->address;
                branch.type = CodeBranchType::Return;
                break;
            case X86_GRP_CALL:
                branch.address = cap_ins->address;

                ins_arg = d->x86.operands[0];

                if(ins_arg.type == X86_OP_IMM) {
                    branch.type = CodeBranchType::Call;
                    branch.ok = ins_arg.imm;
                } else {
                    branch.type = CodeBranchType::IndCall;
                }

                break;
        }
    }

    cs_free(cap_ins, 1);

    if(branch.type == CodeBranchType::Invalid)
        return -1;

    return 0;
}

static std::string get_realpath(std::string path)
{
    char* respath = realpath(path.c_str(), NULL);

    if(!respath) {
        std::free(respath);
        return std::string();
    }

    std::string result = std::string(respath);
    std::free(respath);

    return result;
}

static int setup_perf(PerfFile& file, std::string perf_path)
{
    if(parse_perf_data(file, perf_path) < 0)
        return -1;

    if(file.ptstream.size() == 0) {
        std::cerr << perf_path << " does not contain pt traces\n";
        return -1;
    }

    if(file.maps.size() == 0) {
        std::cerr << perf_path << " does not contain any mappings\n";
        return -1;
    }

    return 0;
}

static int setup_pt(struct pt_insn_decoder** ins_dec, PerfFile& file)
{
    struct pt_config config;

    pt_config_init(&config);
    config.begin = (uint8_t*)file.ptstream.c_str();
    config.end = (uint8_t*)file.ptstream.c_str() + file.ptstream.size();

    *ins_dec = pt_insn_alloc_decoder(&config);

    if(!ins_dec) {
        std::cerr << "Could not allocate instruction decoder\n";
        return -1;
    }

    struct pt_image* image = pt_image_alloc(nullptr);
    
    if(!image) {
        std::cerr << "Could not allocate trace image\n";
        return -1;
    }

    for(auto& map : file.maps) {
        if(map.filename != "[vdso]") {
            int err = pt_image_add_file(image, map.filename.c_str(), 
                    map.offset, map.size, nullptr, map.start);

            if(err != 0) {
                std::cerr << "Warning: Could not map " << map.filename << "\n";
            }
        }
    }

    if(pt_insn_set_image(*ins_dec, image) < 0) {
        std::free(*ins_dec);
        std::free(image);

        return -1;
    }

    return 0;
}

static void log_pt_err(struct pt_insn_decoder* dec, enum pt_error_code err)
{
    // use pt_errstr
    uint64_t offset = 0;
    pt_insn_get_offset(dec, &offset);

    std::cerr << "Error at offset ";
    std::cerr << "0x" << std::hex << offset << " ";
    std::cerr << pt_errstr(err) << "\n";
}

static void bb_hit(std::map<uint64_t, uint64_t>& hitmap, uint64_t address)
{
    if(hitmap.find(address) == hitmap.end()) {
        hitmap[address] = 1;
    } else {
        hitmap[address]++;
    }
}

static int get_next_instruction(struct pt_insn_decoder* ins_dec,
        struct pt_insn* instruction, int status)
{
    while(status & pts_event_pending) {
        struct pt_event evt;
        status =  pt_insn_event(ins_dec, &evt, sizeof(evt));

        if(status < 0)
            return status;
    }

    status = pt_insn_next(ins_dec, instruction, sizeof(*instruction));

    if(status == -pte_eos)
        return status;

    if(status == -pte_nosync || status == -pte_nomap) {
        std::cerr << "Warning: Trace out of sync, seeking to next PSB\n";
        status = pt_insn_sync_forward(ins_dec);

        if(status == -pte_eos) {
            std::cerr << "No new PSB\n";
            return status;
        }

        if(status < 0) {
            log_pt_err(ins_dec, (pt_error_code)-status);
            return -1;
        }

        return get_next_instruction(ins_dec, instruction, status);
    }

    return status;
}

int pt_process(std::string perf_path, std::string binary_path,
        std::string output_path)
{
    // Setup main objects
    PerfFile perf_file;
    struct pt_insn_decoder* ins_dec = nullptr;
    csh dis_handle;
    cs_err err;

    // Initialize capstone
    if((err = cs_open(CS_ARCH_X86, CS_MODE_64, &dis_handle)) != CS_ERR_OK ) {
        std::cout << "Capstone error: " << cs_strerror(err) << "\n";
        return 1;
    }

    cs_option(dis_handle, CS_OPT_DETAIL, CS_OPT_ON);

    if(setup_perf(perf_file, perf_path) < 0)
        return 1;
    
    if(setup_pt(&ins_dec, perf_file) < 0)
        return 1;

    // Setup the output file
    std::ofstream out_fstream(output_path, std::ofstream::out);

    if(!out_fstream) {
        std::cerr << "Could not open file: " << output_path << "\n";
        return 1;
    }

    // Setup protobuf
    trace::TraceEvent trace_evt;
    std::map<uint64_t, uint64_t> bb_hitcount;

    // Somehow protobuf writes the message when the stream objects are
    // destroyed. There is no flush method so it is a bit ugly.
    {
        OstreamOutputStream mapping_oos(&out_fstream);
        CodedOutputStream mapping_os(&mapping_oos);

        for(auto& map : perf_file.maps) {
            if(map.filename != "[vdso]") {
                trace::MappingEvent* evt = trace_evt.mutable_mapping_evt();
                evt->set_start(map.start);
                evt->set_size(map.size);
                evt->set_offset(map.offset);
                evt->set_filename(map.filename);

                mapping_os.WriteVarint32(trace_evt.ByteSize());
                trace_evt.SerializeToCodedStream(&mapping_os);
            }
        }
    }

    // Begin processing the trace
    int status = 0;
    CodeBranch prev_branch;
    prev_branch.type = CodeBranchType::Invalid;

    for(;;) {
        // We prepare the trace for processing
        struct pt_insn ins;
        status = pt_insn_sync_forward(ins_dec);

        if(status < 0) {
            if(status == -pte_eos)
                break;

            std::cout << "Warning: Out of sync\n";
            continue;
        }

        for(;;) {
            // Get next instruction already handles the pte_nomap case
            status = get_next_instruction(ins_dec, &ins, status);

            if(status < 0)
                break;

            if(prev_branch.type != CodeBranchType::Invalid) {
                trace::BranchEvent* evt = nullptr;

                if(prev_branch.type == CodeBranchType::CondJump) {
                    if(ins.ip == prev_branch.ok || ins.ip == prev_branch.fail) {
                        bb_hit(bb_hitcount, ins.ip);
                        evt = trace_evt.mutable_branch_evt();
                        evt->set_source(prev_branch.address);
                        evt->set_destination(ins.ip);
                        evt->set_type(trace::BranchType::CONDJUMP);
                    }
                } else if(prev_branch.type == CodeBranchType::Jump) {
                    bb_hit(bb_hitcount, prev_branch.ok);
                    evt = trace_evt.mutable_branch_evt();
                    evt->set_source(prev_branch.address);
                    evt->set_destination(prev_branch.ok);
                    evt->set_type(trace::BranchType::JUMP);
                } else if(prev_branch.type == CodeBranchType::Call) {
                    bb_hit(bb_hitcount, prev_branch.ok);
                    evt = trace_evt.mutable_branch_evt();
                    evt->set_source(prev_branch.address);
                    evt->set_destination(prev_branch.ok);
                    evt->set_type(trace::BranchType::CALL);
                } else if(prev_branch.type == CodeBranchType::IndCall) {
                    bb_hit(bb_hitcount, ins.ip);
                    evt = trace_evt.mutable_branch_evt();
                    evt->set_source(prev_branch.address);
                    evt->set_destination(ins.ip);
                    evt->set_type(trace::BranchType::INDCALL);
                } else if(prev_branch.type == CodeBranchType::IndJump) {
                    bb_hit(bb_hitcount, ins.ip);
                    evt = trace_evt.mutable_branch_evt();
                    evt->set_source(prev_branch.address);
                    evt->set_destination(ins.ip);
                    evt->set_type(trace::BranchType::INDJUMP);
                }

                if(evt) {
                    OstreamOutputStream branch_oos(&out_fstream);
                    CodedOutputStream branch_os(&branch_oos);

                    branch_os.WriteVarint32(trace_evt.ByteSize());
                    trace_evt.SerializeToCodedStream(&branch_os);
                }

                prev_branch.type = CodeBranchType::Invalid;
            }


            if(ins.iclass == ptic_jump || 
                    ins.iclass == ptic_cond_jump ||
                    ins.iclass == ptic_call) {

                if(extract_branch(dis_handle, ins, prev_branch) < 0) {
                    std::cout << "Could not disassemble branch at address: 0x"
                        << std::hex << ins.ip << "\n";
                }
            }
        }

        if(status == -pte_eos)
            break;

        if(status < 0)
            log_pt_err(ins_dec, (pt_error_code)-status);
    }

    // Same flushing trick
    {
        OstreamOutputStream branch_oos(&out_fstream);
        CodedOutputStream branch_os(&branch_oos);

        for(auto& bb_hit: bb_hitcount) {
            trace::HitcountEvent* evt = trace_evt.mutable_hitcount_evt();
            evt->set_address(bb_hit.first);
            evt->set_count(bb_hit.second);

            branch_os.WriteVarint32(trace_evt.ByteSize());
            trace_evt.SerializeToCodedStream(&branch_os);
        }
    }

    out_fstream.close();
    google::protobuf::ShutdownProtobufLibrary();
    
    // pt cleanup
    pt_image_free(pt_insn_get_image(ins_dec));
    pt_insn_free_decoder(ins_dec);

    if(status != -pte_eos)
        return 1;

    return 0;
}
