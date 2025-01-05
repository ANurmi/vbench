class ClkRstDrv;


class ClkRstDrv {
    private:
        SimCtx* cx;
        vluint64_t rst_counter;
        vluint64_t clk_counter;
        uint32_t   per_counter;

    public:
        ClkRstDrv(SimCtx* cx){
            this->cx = cx;
            this->rst_counter = 0;
            this->clk_counter = 0;
            this->per_counter = 0;
        }

        void reset(vluint64_t rst_delay){
            if(rst_counter == rst_delay)
                cx->dut->rst_ni = 1;
            else
                rst_counter++;
        }

        void clock(vluint64_t clk_delay, uint32_t clk_per) {
            if (clk_counter == clk_delay){
                if (per_counter == clk_per - 1) {
                    per_counter = 0;
                    cx->dut->clk_i ^= 1;
                } else {
                    per_counter++;
                }
            } else
                clk_counter++;
        }
};