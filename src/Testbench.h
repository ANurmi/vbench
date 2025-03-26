#include <stdint.h>

// Clock period in picoseconds, used for generating waveforms
const uint32_t CLOCK_PERIOD_PS = /* 100 MHz */ 10'000;

template <class VA>
class Testbench {
public:
    VA             *m_dut;
    VerilatedFstC*  m_trace;
    uint64_t        m_tickcount;

    Testbench(void) : m_trace(NULL), m_tickcount(01) {
        m_dut = new VA;
        Verilated::traceEverOn(true);
		m_dut->clk_i = 0;
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
        m_dut->clk_i = 1;
        eval();
        if (m_trace) m_trace->dump((vluint64_t)(CLOCK_PERIOD_PS*m_tickcount));
        m_dut->clk_i = 0;
        eval();
        if (m_trace){
            m_trace->dump((vluint64_t)(CLOCK_PERIOD_PS*m_tickcount+CLOCK_PERIOD_PS/2));
            m_trace->flush();
        }
    }

    virtual void reset(void) {
        m_dut->rst_ni = 0;
        tick();
        m_dut->rst_ni = 1;
    }

    uint64_t tickcount(void) {
		return m_tickcount;
	}


};