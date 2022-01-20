#ifndef CERTIKOS_PRIVATE_H
#define CERTIKOS_PRIVATE_H

uint64_t certikos_el3_world_switch_return(void *);
void certikos_el3_world_switch_enter(void *, uint64_t);


#endif /* CERTIKOS_PRIVATE_H */
