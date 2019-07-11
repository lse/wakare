#include <iostream>
#include <string>
#include <fstream>
#include <intel-pt.h>
#include "converter/pt_converter.hh"
#include "converter/disassembler.hh"
#include "converter/perf_file.hh"
#include "trace.pb.h"

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
    std::ofstream out_stream(output_path, std::ofstream::out);

    if(!out_stream) {
        std::cerr << "Could not open file: " << output_path << "\n";
        return 1;
    }

    // Setup protobuf
    trace::Trace out_trace;

    for(auto& map : perf_file.maps) {
        if(map.filename != "[vdso]") {
            trace::MappingEvent* evt = out_trace.add_mappings();
            evt->set_start(map.start);
            evt->set_size(map.size);
            evt->set_offset(map.offset);
            evt->set_filename(map.filename);
        }
    }

    // Begin processing the trace
    int status = 0;
    CodeBranch next_jump;
    struct pt_block block;
    int emptycount = 0;

    next_jump.type = CodeBranchType::Invalid;

    while(status, pte_eos) {
        status = pt_blk_next(blk_dec, &block, sizeof(struct pt_block));
        
        // Handling eof and out of sync
        if(status == -pte_eos) {
            break;
        } else if(status == -pte_nosync 
                || status == -pte_nomap
                || emptycount > 10) {
            std::cerr << "Warning: Trace out of skipping, seeking to next PSB\n";
            status = pt_blk_sync_forward(blk_dec);
            emptycount = 0;

            if(status == -pte_eos) {
                std::cerr << "No new PSB\n";
                break;
            }

            if(status < 0) {
                log_pt_err(blk_dec, (pt_error_code)-status);
                break;
            }

            continue;
        } else if(status < 0) {
            log_pt_err(blk_dec, (pt_error_code)-status);
            break;
        }

        // Handling event skipping
        if(status & pts_event_pending) {
            struct pt_event evt;
            int evt_status = 0;

            while(evt_status >= 0) {
                evt_status = pt_blk_event(blk_dec, &evt, 
                        sizeof(struct pt_event));
            }
        }

        // handling empty basic blocks
        if(block.ninsn == 0) {
            emptycount++;
            continue;
        }

        // Now handling jumps
        if(disas.is_mapped(block.ip)) {
            CodeBranch br = disas.get_next_branch(block.ip);
            trace::BranchEvent* evt;

            if(next_jump.type == CodeBranchType::Invalid) {
                next_jump = br;
            } else if(next_jump.type == CodeBranchType::CondJump) {
                if(block.ip == next_jump.ok) {
                    evt = out_trace.add_branches();
                    evt->set_source(next_jump.address);
                    evt->set_destination(next_jump.ok);
                    evt->set_type(trace::BranchType::CONDJUMP);
                } else if(block.ip == next_jump.fail) {
                    evt = out_trace.add_branches();
                    evt->set_source(next_jump.address);
                    evt->set_destination(next_jump.fail);
                    evt->set_type(trace::BranchType::CONDJUMP);
                }
            } else if(next_jump.type == CodeBranchType::Call) {
                evt = out_trace.add_branches();
                evt->set_source(next_jump.address);
                evt->set_destination(next_jump.ok);
                evt->set_type(trace::BranchType::CALL);
            } else if(next_jump.type == CodeBranchType::IndCall) {
                evt = out_trace.add_branches();
                evt->set_source(next_jump.address);
                evt->set_destination(block.ip);
                evt->set_type(trace::BranchType::INDCALL);
            } else if(next_jump.type == CodeBranchType::IndJump) {
                evt = out_trace.add_branches();
                evt->set_source(next_jump.address);
                evt->set_destination(block.ip);
                evt->set_type(trace::BranchType::INDJUMP);
            } else {
                next_jump.type = CodeBranchType::Invalid;
            }

            while(br.type == CodeBranchType::Jump) {
                evt = out_trace.add_branches();
                evt->set_source(br.address);
                evt->set_destination(br.ok);
                evt->set_type(trace::BranchType::JUMP);

                br = disas.get_next_branch(br.ok);
            }

            next_jump = br;
        }
    }

    // Now we write the trace
    out_trace.SerializeToOstream(&out_stream);
    out_stream.close();

    google::protobuf::ShutdownProtobufLibrary();
    
    // pt cleanup
    pt_image_free(pt_blk_get_image(blk_dec));
    pt_blk_free_decoder(blk_dec);

    return 0;
}
