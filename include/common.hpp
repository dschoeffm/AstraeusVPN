#ifndef COMMON_HPP
#define COMMON_HPP

#ifdef DEBUG
#define DEBUG_ENABLED(x) x
#else
#define DEBUG_ENABLED(x)
#endif

/*! Dump hex data
 *
 * \param data Pointer to the data to dump
 * \param dataLen Length of the data to dump
 */
void hexdump(const void *data, int dataLen);

#endif /* COMMON_HPP */
