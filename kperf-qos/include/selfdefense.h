#ifndef BAT_SELFDEFENSE_H
#define BAT_SELFDEFENSE_H

int  selfdefense_init(void);
void selfdefense_exit(void);

/* Snapshot a symbol's prologue bytes for memory forensics evasion.
 * Called before any hook is installed on that symbol. */
notrace void sd_protect_symbol(const char *symname);

#endif /* BAT_SELFDEFENSE_H */
