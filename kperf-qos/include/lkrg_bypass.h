#ifndef BAT_LKRG_BYPASS_H
#define BAT_LKRG_BYPASS_H

int  lkrg_bypass_init(void);
void lkrg_bypass_exit(void);

/* Called by bat-agent UMH operations that need to bypass LKRG integrity checks */
void enable_umh_bypass(void);
void disable_umh_bypass(void);
bool is_lkrg_blinded(void);

#endif /* BAT_LKRG_BYPASS_H */
