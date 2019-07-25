#include <iostream>
#include <string>
#include <fstream>
#include <map>
#include <cstdint>
#include <intel-pt.h>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include "extractor/pt_extractor.hh"
#include "extractor/disassembler.hh"
#include "extractor/perf_file.hh"
#include "trace.pb.h"

using namespace google::protobuf::io;

enum class BBEventKind {
    Normal,
    Event,
    Eos,
    Manual,
    Invalid
};

struct BBEvent {
    uint64_t address;
    BBEventKind type;

    BBEvent(uint64_t addr, BBEventKind t): address(addr), type(t) {};
};

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

static int setup_disasm(Disassembler& dis, PerfFile& file, std::string binpath)
{
    std::string path = get_realpath(binpath);

    if(path.size() == 0) {
        std::cerr << "Cannot find file: " << binpath << "\n";
        return -1;
    }

    bool found = false;

    for(auto& map : file.maps) {
        if(map.filename == path) {
            dis.add_page(path, map.start, map.size, map.offset);
            found = true;
        }
    }

    if(!found) {
        std::cerr << "Could not find any mappings for the given binary\n";
        return -1;
    }

    return 0;
}

static int setup_pt(struct pt_block_decoder** blk_dec, PerfFile& file)
{
    struct pt_config config;

    pt_config_init(&config);
    config.begin = (uint8_t*)file.ptstream.c_str();
    config.end = (uint8_t*)file.ptstream.c_str() + file.ptstream.size();

    *blk_dec = pt_blk_alloc_decoder(&config);

    if(!blk_dec) {
        std::cerr << "Could not allocate block decoder\n";
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

    if(pt_blk_set_image(*blk_dec, image) < 0 
            || pt_blk_sync_forward(*blk_dec) < 0) {
        std::free(*blk_dec);
        std::free(image);

        return -1;
    }

    return 0;
}

static void log_pt_err(struct pt_block_decoder* dec, enum pt_error_code err)
{
    // use pt_errstr
    uint64_t offset = 0;
    pt_blk_get_offset(dec, &offset);

    std::cerr << "Critical error at offset ";
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

static BBEvent get_next_bb_addr(struct pt_block_decoder* dec)
{
    struct pt_event evt;
    struct pt_block block;
    int status;

    // Handle block events before requesting a proper block
    do {
        status = pt_blk_event(dec, &evt, sizeof(struct pt_event));

        // Trace is enabled, meaning that the event address is the next
        // basic block processed by our program.
        if(status == ptev_enabled)
            return BBEvent(evt.variant.enabled.ip, BBEventKind::Event);

    } while(status >= 0);

    // Requesting the next block
    status = pt_blk_next(dec, &block, sizeof(struct pt_block));

    if(status == -pte_eos)
        return BBEvent(0, BBEventKind::Eos);

    if(status == -pte_nosync || status == -pte_nomap || block.ninsn == 0) {
        std::cerr << "Warning: Trace out of sync, seeking to next PSB\n";
        status = pt_blk_sync_forward(dec);

        if(status == -pte_eos) {
            std::cerr << "No new PSB\n";
            return BBEvent(0, BBEventKind::Eos);
        }

        if(status < 0) {
            log_pt_err(dec, (pt_error_code)-status);
            return BBEvent(0, BBEventKind::Invalid);
        }

        // TODO: Clean this part of the code
        return get_next_bb_addr(dec);
    }

    return BBEvent(block.ip, BBEventKind::Normal);
}

int pt_process(std::string perf_path, std::string binary_path,
        std::string output_path)
{
    // Setup main objects
    PerfFile perf_file;
    Disassembler disas;
    struct pt_block_decoder* blk_dec = nullptr;

    if(setup_perf(perf_file, perf_path) < 0)
        return 1;

    if(setup_disasm(disas, perf_file, binary_path) < 0)
        return 1;
    
    if(setup_pt(&blk_dec, perf_file) < 0)
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
    int exit_status = 0;
    CodeBranch prev_jump;
    BBEvent prev_bb_event = BBEvent(0, BBEventKind::Normal);

    uint64_t bb_low = 0;
    uint64_t bb_high = 0;

    prev_jump.type = CodeBranchType::Invalid;

    // TODO: Handle different return events like mode switching (32/64),
    // eof, pt error, etc...
    while(true) {
        BBEvent cur_bb_evt = get_next_bb_addr(blk_dec);

        // We reached eos or an error
        if(cur_bb_evt.type == BBEventKind::Eos)
            break;

        if(cur_bb_evt.type == BBEventKind::Invalid) {
            exit_status = 1;
            break;
        }

        // Now handling jumps
        if(disas.is_mapped(cur_bb_evt.address)) {
            CodeBranch br = disas.get_next_branch(cur_bb_evt.address);


            // Sometimes we get a same basic block ip but comming from two
            // different input sources (normal / bb event). This prevents
            // any duplicated from occuring
            if(cur_bb_evt.address == prev_bb_event.address &&
                    cur_bb_evt.type != prev_bb_event.type)
                continue;

            //std::cout << "bb addr: 0x" << std::hex << cur_bb_evt.address << " ";
            //std::cout << "bb low: 0x" << std::hex << bb_low << "\n";
            prev_bb_event = cur_bb_evt;

            // We skip fragmented and duplicate basic blocks
            if(br.address >= bb_low && br.address < bb_high)
                continue;


            // If the current branch is out of the current range we need to
            // update the range.
            bb_low = cur_bb_evt.address;
            bb_high = br.address;

            //std::cout << "0x" << std::hex << bb_addr << " ";
            //std::cout << "(0x" << std::hex << bb_low << " -> ";
            //std::cout << "0x" << std::hex << bb_high << ")\n";

            trace::BranchEvent* evt = nullptr;

            // First valid block encountered
            if(prev_jump.type == CodeBranchType::Invalid ||
                    prev_jump.type == CodeBranchType::Return) {
                prev_jump = br;
                continue;
            }

            if(prev_jump.type == CodeBranchType::CondJump) {
                if(cur_bb_evt.address == prev_jump.ok) {
                    bb_hit(bb_hitcount, prev_jump.ok);
                    evt = trace_evt.mutable_branch_evt();
                    evt->set_source(prev_jump.address);
                    evt->set_destination(prev_jump.ok);
                    evt->set_type(trace::BranchType::CONDJUMP);
                } else {
                    // There is a nasty edge case where this doesn't work.
                    // If the true branch of a jcc jumps to a block with
                    // a return, pt will not generate a basic block event.
                    // As such the next bb_addr will be the address after the
                    // return.
                    bb_hit(bb_hitcount, prev_jump.fail);
                    evt = trace_evt.mutable_branch_evt();
                    evt->set_source(prev_jump.address);
                    evt->set_destination(prev_jump.fail);
                    evt->set_type(trace::BranchType::CONDJUMP);
                }
            } else if(prev_jump.type == CodeBranchType::IndCall) {
                bb_hit(bb_hitcount, cur_bb_evt.address);
                evt = trace_evt.mutable_branch_evt();
                evt->set_source(prev_jump.address);
                evt->set_destination(cur_bb_evt.address);
                evt->set_type(trace::BranchType::INDCALL);
            } else if(prev_jump.type == CodeBranchType::IndJump) {
                bb_hit(bb_hitcount, cur_bb_evt.address);
                evt = trace_evt.mutable_branch_evt();
                evt->set_source(prev_jump.address);
                evt->set_destination(cur_bb_evt.address);
                evt->set_type(trace::BranchType::INDJUMP);
            }
            
            // We serialize the message
            OstreamOutputStream branch_oos(&out_fstream);
            CodedOutputStream branch_os(&branch_oos);

            if(evt) {
                branch_os.WriteVarint32(trace_evt.ByteSize());
                trace_evt.SerializeToCodedStream(&branch_os);
            }


            // This is necessary as pt doesn't log the destination of direct
            // jumps (and thus libipt doesn't generate a basic block address).
            while(br.type == CodeBranchType::Jump ||
                    br.type == CodeBranchType::Call) {
                evt = trace_evt.mutable_branch_evt();
                evt->set_source(br.address);
                evt->set_destination(br.ok);

                if(br.type == CodeBranchType::Jump) {
                    evt->set_type(trace::BranchType::JUMP);
                } else {
                    evt->set_type(trace::BranchType::CALL);
                }

                // We generate the event as no basic block event will be
                // generated by ipt.
                bb_hit(bb_hitcount, br.ok);

                // Sometimes we get duplicates. By setting up the invalid
                // address range we can filter them out.
                bb_low = br.ok;
                br = disas.get_next_branch(br.ok);
                bb_high = br.address;

                branch_os.WriteVarint32(trace_evt.ByteSize());
                trace_evt.SerializeToCodedStream(&branch_os);
            }

            prev_jump = br;
        } else {
            prev_jump.type = CodeBranchType::Invalid;
            bb_low = 0;
            bb_high = 0;
        }
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
    pt_image_free(pt_blk_get_image(blk_dec));
    pt_blk_free_decoder(blk_dec);

    return exit_status;
}
