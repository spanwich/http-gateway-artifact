/*
 * domain_schedule.c — seL4 kernel domain schedule for HTTP gateway x86
 *
 * 2-domain configuration:
 *   Domain 0: Data path (E1000Driver, TlsValidator, LwipProxy)
 *             - All at priority 150 (equal = round-robin via seL4_Yield)
 *   Domain 1: Control plane (ControlPlane)
 *             - Runs Batch C RBAC pipeline
 *
 * Equal time slices (length=1 each). All components run on CPU 0
 * with domain scheduling for temporal isolation.
 */

#include <config.h>
#include <object/structures.h>
#include <model/statedata.h>

const dschedule_t ksDomSchedule[] = {
    { .domain = 0, .length = 1 },
    { .domain = 1, .length = 1 },
};

const word_t ksDomScheduleLength = sizeof(ksDomSchedule) / sizeof(dschedule_t);
