/* Synchronous scalar adapter for the differential fixture. The host receives
 * only a translator-issued callback function and borrows its context for this
 * invocation. The guest return slot belongs to the original CALL. */
#include "cpu_state.h"
#include "guest_memory.h"

typedef void (*TranslatedCallback)(BbCpuState *, void *, BbGuestMemory *,
                                   uint64_t, uint32_t *);

void bb_state_host_callback(BbCpuState *state, void *data, BbGuestMemory *stack,
                            uint64_t continuation, uint32_t *budget,
                            TranslatedCallback callback) {
    callback(state, data, stack, continuation, budget);
    if (!state->status)
        state->gpr[0] += UINT64_C(17);
}
