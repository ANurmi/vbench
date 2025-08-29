/* This testbench base class expexts the macros

CLKI
RSTNI

JTAGTCK
JTAGTMS
JTAGTDI
JTAGTDO
JTAGTRSTN

IDCODE

to be defined at start of the top cpp testbench in
accordance with the exact naming used on the DUT,
i.e., "#define CLKI clk_i".
*/

#include <stdint.h>
#include <fstream>

typedef struct {
    // assume 32-bit addressing for now
    uint32_t entry;
    uint32_t phoff;
    uint32_t shoff;
    uint16_t ehsize;
    uint16_t phnum;
    uint16_t phentsize;
    uint16_t shnum;
    uint16_t shentsize;
    uint16_t shstrndx;
} elf_hdr_t;

typedef struct {
    // assume 32-bit addressing for now
    uint32_t type;
    uint32_t offset;
    uint32_t vaddr;
    uint32_t paddr;
    uint32_t filesz;
    uint32_t memsz;
    uint32_t flags;
    uint32_t align;
} prog_hdr_t;

/*
typedef struct {
    // assume 32-bit addressing for now
    uint32_t name;
    uint32_t addr;
    uint32_t offset;
    uint32_t size;
    uint32_t addralign;
    uint32_t entsize;
} sec_hdr_t;
*/
// Clock period in picoseconds, used for generating waveforms
const uint32_t CLOCK_PERIOD_PS = /* 100 MHz */ 10'000;

const uint32_t JTAG_CLK_PER = 1; /* Relative to system clock*/

template <class VA>
class Testbench {
public:
    VA             *m_dut;
    VerilatedFstC*  m_trace;
    uint64_t        m_tickcount;
    uint8_t         m_jtag_ir;

    Testbench(void) : m_trace(NULL), m_tickcount(01), m_jtag_ir(0xFF) {
        m_dut = new VA;
        Verilated::traceEverOn(true);
        m_dut->CLKI = 0;
        eval(); // set initial values
    }

    virtual ~Testbench(void){
        close_trace();
        delete m_dut;
        m_dut = NULL;
    }

    virtual void open_trace(const char* fst_name){
        if (!m_trace) {
            m_trace = new VerilatedFstC;
            m_dut->trace(m_trace, 99);
            m_trace->open(fst_name);
        }
    }

    virtual void close_trace(void) {
        if (m_trace){
            m_trace->close();
            delete m_trace;
            m_trace = NULL;
        }
    }
    
    virtual void eval(void) {
        m_dut->eval();
    }

    virtual void tick(void) {
        m_tickcount++;
        eval();
        if (m_trace) m_trace->dump((vluint64_t)(CLOCK_PERIOD_PS*m_tickcount-CLOCK_PERIOD_PS/5));
        m_dut->CLKI = 1;
        eval();
        if (m_trace) m_trace->dump((vluint64_t)(CLOCK_PERIOD_PS*m_tickcount));
        m_dut->CLKI = 0;
        eval();
        if (m_trace){
            m_trace->dump((vluint64_t)(CLOCK_PERIOD_PS*m_tickcount+CLOCK_PERIOD_PS/2));
            m_trace->flush();
        }
    }

    virtual void reset(void) {
        m_dut->RSTNI = 0;
        tick();
        m_dut->RSTNI = 1;
    }

    uint64_t tickcount(void) {
		return m_tickcount;
	}

    virtual void jtag_tick(void) {
        const uint8_t HalfPer = JTAG_CLK_PER;
        // drive jtag_clk risign edge slightly before input
        for (int i=0;i<HalfPer*2; i++){
            m_dut->JTAGTCK = (i < HalfPer - 1 | i == (HalfPer*2) -1);
            tick();
        }
    }

    virtual void jtag_reset(void) {
        m_dut->JTAGTMS   = 1;
        m_dut->JTAGTDI   = 0;
        m_dut->JTAGTRSTN = 0;
        jtag_tick();
        jtag_tick();
        m_dut->JTAGTRSTN = 1;
        m_jtag_ir = 0xFF;
        jtag_tick();
    }
    virtual void jtag_softreset(void) {
        m_dut->JTAGTMS   = 1;
        m_dut->JTAGTDI    = 0;
        for(int i=0;i<6;i++) jtag_tick();
        m_dut->JTAGTMS   = 0;
        jtag_tick();
        // After softreset the IR should be reset to IDCODE so we have to mirror
        // this in our internal state.
        m_jtag_ir = 0xFF;
    }

    virtual void jtag_reset_master (void) {
        jtag_reset();
        jtag_softreset();
    }

    virtual void write_tms(bool val) {
        m_dut->JTAGTMS = val;
        jtag_tick();
    }

    virtual void write_bits (uint64_t wdata, uint32_t size, bool tms_last) {
        for (int i = 0; i < size; i++){
            m_dut->JTAGTDI = (wdata >> i) & 0x1;
            if (i == size-1) m_dut->JTAGTMS = tms_last;
            jtag_tick();
        }
        m_dut->JTAGTMS = 0;
    }

    virtual void set_ir(uint32_t opcode) {
        const uint32_t mask_5b = 0b11111;
        // check whether IR is already set to the right value
        if( (opcode & mask_5b) == (m_jtag_ir & mask_5b) ) {
            return;
        }
        write_tms(1); // select DR scan
        write_tms(1); // select IR scan
        write_tms(0); // capture IR
        write_tms(0); // shift IR
        write_bits(opcode, 5, 1);
        write_tms(1); // update IR
        write_tms(0); // run test idle
        m_jtag_ir = opcode;
    }

    virtual void shift_dr(void) {
        write_tms(1); // select DR scan
        write_tms(0); // capture DR
        write_tms(0); // shift DR
    }

    virtual uint64_t readwrite_bits(uint64_t wdata, uint32_t size, bool tms_last) {
        uint64_t res = 0;
        // make everything u64 so shifting works
        const uint64_t one = 1;
        for (uint64_t i = 0; i < size; i++) {
            m_dut->JTAGTDI = (wdata >> i) & one;
            if (i == size-1) 
                m_dut->JTAGTMS = tms_last;
            jtag_tick();
            res |= (((uint64_t)m_dut->JTAGTDO) << i) & (one << i);
        }
        return res;
    }

    virtual void update_dr(bool exit_1_dr) {
        // depending on the state `exit_1_dr` is already reached when shifting data (`tms_on_last`).
        if (exit_1_dr) write_tms(1);
        write_tms(1);   // update DR
        write_tms(0);   // run test idle
    }

    virtual uint32_t get_idcode(uint32_t idcode) {
        uint32_t wdata = 0;
        set_ir(idcode);
        shift_dr();
        uint32_t res = readwrite_bits(wdata, 32, 0);
        update_dr(1);
        return res;
    }

    virtual void jtag_write_dmi(uint8_t csr_addr, uint32_t data) {
        const uint32_t DMIWidth = 7 + 2 + 32; // addr + op + data
        const uint8_t  DtmWrite  = 0b10;
        const uint32_t DmiAccess = 0b10001;
        uint64_t write_data = 0;
        write_data |= (DtmWrite << 0);  // op
        write_data |= (((uint64_t) data    ) << 2);  // data
        write_data |= (((uint64_t) csr_addr) << 34); // addr
        set_ir(DmiAccess);
        shift_dr();
        write_bits(write_data, DMIWidth, 1);
        update_dr(0);

    }

    virtual void jtag_write(uint8_t csr_addr, uint32_t data, 
                            bool wait_cmd = 0, bool wait_sba = 0){
        const uint8_t AbstractCSAddr = 0x16;
        const uint8_t SbcsAddr       = 0x38;
        jtag_write_dmi(csr_addr, data);
        if (wait_cmd) {
            uint32_t acs      = 0;
            uint8_t  acs_busy = 0;
            do {
                acs = jtag_read_dmi_exp_backoff(AbstractCSAddr);
                uint8_t acs_err  = (acs >> 8)  & 0b111;
                acs_busy = (acs >> 12) & 0b1;
                if(acs_err) printf("[ERROR] Abstract command error!\n");
            } while (acs_busy);
        }
        if (wait_sba) {
            uint32_t sbcs   = 0;
            uint8_t  sbbusy = 0;
            do {
                sbcs = jtag_read_dmi_exp_backoff(SbcsAddr);
                uint8_t sberror     = (sbcs >> 12) & 0b111;
                uint8_t sbbusyerror = (sbcs >> 22) & 0b1;
                sbbusy              = (sbcs >> 21) & 0b1;
                if (sberror | sbbusyerror ) printf("[ERROR] System bus error!\n");
            } while (sbbusy);
        }
    }

    virtual void wait_idle (uint32_t wait_cycles) {
        for (int i = 0; i<wait_cycles; i++) jtag_tick();
    }

    virtual void write_dtmcs(uint32_t data) {
        const uint32_t DtmCsr = 0b10000;
        set_ir(DtmCsr);
        shift_dr();
        write_bits(data, 32, 1);
        update_dr(0);
    }

    virtual void reset_dmi(void) {
        uint32_t dmireset = 1 << 16;
        write_dtmcs(dmireset);
    }

    virtual uint64_t jtag_read_dmi (uint8_t addr, uint32_t wait_cycles) {
        const uint32_t DMIWidth = 7 + 2 + 32; // addr + op + data
        const uint8_t  DtmNop    = 0b00;
        const uint8_t  DtmRead   = 0b01;
        const uint32_t DmiAccess = 0b10001;
        uint64_t write_data = 0;
        write_data |= (DtmRead << 0);  // op
        //write_data |= (data  << 2);  // data = 0
        write_data |= (((uint64_t) addr) << 34); // addr
        set_ir(DmiAccess);
        // send read command
        shift_dr();
        write_bits(write_data, DMIWidth, 1);
        update_dr(0);
        wait_idle(wait_cycles);
        // shift out read data
        shift_dr();
        write_data = 0;
        write_data |= (DtmNop << 0);  // op
        //write_data |= (data << 2);  // data = 0
        write_data |= (((uint64_t) addr) << 34); // addr
        uint64_t data_out = readwrite_bits(write_data, DMIWidth, 1);
        update_dr(0);

        return data_out;
    }

    virtual uint32_t jtag_read_dmi_exp_backoff (uint8_t addr) {
        const uint8_t DtmSuccess = 0b00;
        const uint8_t DtmBusy    = 0b11;
        uint64_t read_data       = 0;
        uint32_t read_result     = 0;
        uint32_t trial_idx       = 0;
        uint32_t wait_cycles     = 8;
        uint8_t  op              = DtmSuccess;

        do
        {
            if (trial_idx != 0){
                // Not entered upon first iteration, resets the
                // sticky error state if previous read was unsuccessful
                reset_dmi();
            }
            read_data = jtag_read_dmi(addr, wait_cycles);
            op = read_data & 0b11;
            read_result = (uint32_t)(read_data>>2);
            wait_cycles *= 2;
            trial_idx++;
        } while ( op == DtmBusy );
        
        return read_result;
    }

    virtual void jtag_init (void) {
        printf("[JTAG] Perform init \t-\t time %ld\n", m_tickcount);
        const uint32_t IdCodeInstr = 0b11111;
        const uint32_t IdCode      = IDCODE;
        const uint8_t  SbcsAddr    = 0x38;
        const uint32_t SbcsData    = 0x58000;

        for (int i=0;i<10;i++) jtag_tick();
        uint32_t idcode = get_idcode(IdCodeInstr);
        if (idcode != IdCode)
            printf("[JTAG] idcode ERROR: read %x, expected %x\n", idcode, IdCode);
        else
            printf("[JTAG] idcode %x OK\n", idcode);

        // Activate, wait for debug module
        const uint8_t  DMControlAddr = 0x10;
        uint32_t       DMControlData = 0;
        DMControlData               |= 0x1; // set dmactive [bit 0]
        jtag_write(DMControlAddr, DMControlData);
        uint32_t dmcontrol = 0; 
        bool  dmcontrol_active = 0;
        do{
            dmcontrol = jtag_read_dmi_exp_backoff(DMControlAddr);
            dmcontrol_active = dmcontrol & 0x1;
        }while(!dmcontrol_active);

        jtag_write(SbcsAddr, SbcsData, 0, 1);
        printf("[JTAG] init ok      \t-\t time %ld\n", m_tickcount);

    }

    virtual uint32_t jtag_mm_read (uint64_t addr, uint32_t wait_cycles = 20) {
        const uint32_t sbcs    = 0x140000; // sbaccess : 2, sbreadonaddr : 1
        const uint32_t addr_lo = (uint32_t) addr;
        const uint32_t addr_hi = (uint32_t)(addr << 32);
        const uint8_t  SBCS    = 0x38;
        const uint8_t  SbAddr1 = 0x3A;
        const uint8_t  SbAddr0 = 0x39;
        const uint8_t  SbData0 = 0x3C;
        jtag_write(SBCS, sbcs, 0, 1);
        jtag_write(SbAddr1, addr_hi);
        jtag_write(SbAddr0, addr_lo);
        wait_idle(wait_cycles);
        uint32_t rdata = jtag_read_dmi_exp_backoff(SbData0);
        return rdata;
    }
    virtual void jtag_mm_write (uint64_t addr, uint32_t data, 
                uint32_t wait_cycles = 20,  bool verbose = 1) {
        const uint8_t  SBCS    = 0x38;
        const uint8_t  SbAddr1 = 0x3A;
        const uint8_t  SbAddr0 = 0x39;
        const uint8_t  SbData0 = 0x3C;
        const uint32_t sbcs    = 0x40000; // sbaccess : 2
        if (verbose) printf("[JTAG] write %08x to   %08lx\n", data, addr);
        const uint32_t addr_lo = (uint32_t) addr;
        const uint32_t addr_hi = (uint32_t)(addr << 32);
        jtag_write(SBCS, sbcs, 0, 1);
        jtag_write(SbAddr1, addr_hi);
        jtag_write(SbAddr0, addr_lo);
        jtag_write(SbData0, data);
        wait_idle(wait_cycles);
    }

    virtual void jtag_halt_hart(void) {
        const uint32_t DmCmd = 0x80000001; // haltreq = 1, dmactive = 1
        const uint8_t  DmControlAddr = 0x10;
        const uint8_t  DmStatusAddr  = 0x11;
        // halt hart 0
        jtag_write(DmControlAddr, DmCmd);
        uint32_t status = 0;
        do status = jtag_read_dmi_exp_backoff(DmControlAddr);
        while (status & 0x200);
        printf("[JTAG] Halted hart 0\n");
    }

    virtual void jtag_resume_hart_from(uint32_t entry) {
        // repoint execution
        const uint8_t  Data0     = 0x04;
        const uint8_t  Command   = 0x17;
        const uint16_t CsrDpc    = 0x7b1; // 12
        const uint32_t DmiCmd    = 0x2307B1;
        jtag_write(Data0, entry);
        jtag_write(Command, DmiCmd);
        // resume hart
        const uint8_t  DmControlAddr = 0x10;
        const uint32_t DmCmd         = 0x40000001;
        jtag_write(DmControlAddr, DmCmd);
        printf("[JTAG] Resumed hart 0 from 0x%08x\n", entry);
    }

    /**
     * @brief Loads given ELF file to memory via JTAG
     * 
     * @param pat ELF file path
     * @return uint32_t Program startpoint extraxted from ELF 
     */
    virtual uint32_t jtag_load_elf(const std::string path) {

        std::fstream fs;
        std::string line;
        std::string concat = "";
        // Entrypoint
        uint32_t entry = 0;

        // address and size
        std::vector<std::pair<uint64_t, uint64_t>> sections;

        // memory based address and content
        std::map<uint64_t, std::vector<uint8_t>> mems;

        //int section_index = 0;
        uint32_t e_phoff  = 0;
        uint32_t e_shoff  = 0;
        uint32_t e_phnum  = 0;
        uint32_t e_shnum  = 0;

        fs.open(path, std::ios::in);

        // Concatenate ELF contents to single string
        while (getline (fs, line)) {
            concat = concat + line;
        }
        fs.close();

        elf_hdr_t e = parse_elf_hdr(concat);
        entry = e.entry;

        for (unsigned int i = 0; i < e.phnum; i++) {

            const uint32_t prog_hdr_offs = e.phoff + e.phentsize*i;
            prog_hdr_t p = parse_pgr_hdr(concat, prog_hdr_offs);
            bool type_load = (p.type == 1);

            if (p.memsz != 0 & type_load) {
                if (p.filesz) {
                    printf("[ELFLOAD] Writing LOAD section to 0x%08x\n", p.paddr);
                    for (int j = 0; j<p.filesz; j = j+4) {
                        const uint32_t addr = p.paddr + j;
                        const uint32_t data = get_from_offset<uint32_t>(concat, p.offset+j);
                        jtag_mm_write(addr, data, 30, 0);
                        if ((j % 0x40) == 0 && j != 0) printf("[ELFLOAD] Written %d/%d bytes\n", j, p.filesz);
                    }
                }
                if (p.memsz > p.filesz) {
                    printf("[ELFLOAD] WARNING: Section starting at %08x contains %1d zero bytes which will not be loaded!\n",
                        p.paddr, (p.memsz - p.filesz));
                }
            }

        }

        return entry;
    }

    virtual void jtag_run_elf(const std::string path) {
        jtag_halt_hart();
        uint32_t entry = jtag_load_elf(path);
        jtag_resume_hart_from(entry);
    };


    virtual void jtag_wait_eoc (void) {
        printf("[JTAG] Waiting for end of computation\n");
        const uint8_t Data0 = 0x04;
        uint32_t exit_code = 0;
        while (!(exit_code & 0x80000000)){
            exit_code = jtag_read_dmi_exp_backoff(Data0);
        }

        for(int i=0; i<20; i++) tick();

        if (!(exit_code & ~(0x80000000)))
            printf("[TB] Program returned EXIT_SUCCESS\n");
        else {
            printf("[TB] Exit code: %x\n", exit_code);
            printf("[TB] Program execution [FAILED]!\n");
        }
    }

private:

    template<typename T>
    uint32_t get_from_offset(std::string input_string, const uint32_t offs ) {
        uint32_t size   = sizeof(T);
        uint32_t result = 0;
        for (int i=size-1; i>=0; i--){
            result |= ((uint8_t)input_string[offs+i]) << 8*i;
        }
        return result;
    }

    elf_hdr_t parse_elf_hdr(std::string input_string) {

        elf_hdr_t ehdr;

        // Check magic value, implicit ok branch
        if(!(input_string[0] == 0x7F && (input_string.substr(1,3) == "ELF"))) {
            std::cout << "[ELFLOAD] ERROR: ELF Format not OK" << std::endl;
        }

        //std::string bitwidth  = (input_string[4] == 0x1) ? "32" : "64";
        //std::string endianess = (input_string[5] == 0x1) ? "little" : "big";

        // TODO: all offsets statically based on 32-bit addresses
        ehdr.entry = get_from_offset<uint32_t>(input_string, 0x18);
        ehdr.phoff = get_from_offset<uint32_t>(input_string, 0x1C);
        ehdr.shoff = get_from_offset<uint32_t>(input_string, 0x20); 
        ehdr.phnum = get_from_offset<uint16_t>(input_string, 0x2C);
        ehdr.phentsize = get_from_offset<uint16_t>(input_string, 0x2A);
        ehdr.shnum = get_from_offset<uint16_t>(input_string, 0x30);
        ehdr.shentsize = get_from_offset<uint16_t>(input_string, 0x2E);
        ehdr.shstrndx = get_from_offset<uint16_t>(input_string, 0x32);

        return ehdr;
    }

    prog_hdr_t parse_pgr_hdr(std::string input_string, uint32_t offs) {

        prog_hdr_t phdr;

        phdr.type = get_from_offset<uint32_t>(input_string, offs);
        phdr.offset = get_from_offset<uint32_t>(input_string, offs + 0x4);
        phdr.vaddr = get_from_offset<uint32_t>(input_string, offs + 0x8);
        phdr.paddr = get_from_offset<uint32_t>(input_string, offs + 0xC);
        phdr.filesz = get_from_offset<uint32_t>(input_string, offs + 0x10);
        phdr.memsz = get_from_offset<uint32_t>(input_string, offs + 0x14);
        phdr.flags = get_from_offset<uint32_t>(input_string, offs + 0x18);
        phdr.align = get_from_offset<uint32_t>(input_string, offs + 0x1C);

        return phdr;

    }

};