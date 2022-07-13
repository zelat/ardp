//
// Created by Administrator on 2022/7/13.
//

#ifndef ARDP_DP_CTRL_INTERNAL_NET_H
#define ARDP_DP_CTRL_INTERNAL_NET_H

#include <apis.h>
#include <base/utils/singleton.h>

namespace dpthreads {
    class DP_CTRL_Internal_Net : public base::Singleton<DP_CTRL_Internal_Net>{
    private:
        io_internal_subnet4_t *g_internal_subnet4;
        io_internal_subnet4_t *g_policy_addr;
    public:
//        DP_CTRL_Internal_Net();
//        ~DP_CTRL_Internal_Net();
        int Init(json_t *msg, bool internal);
        void Exit();
    };
}
#endif //ARDP_DP_CTRL_INTERNAL_NET_H
