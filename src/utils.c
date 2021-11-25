//
// Created by jhc on 2021/11/22.
//
#include "tea.h"

void conv(uint8_t *data, uint32_t size)
{
    uint8_t temp;
    for (uint32_t i = 0; i < size / 2; i++)
    {
        temp = data[i];
        data[i] = data[size - i - 1];
        data[size - i - 1] = temp;
    }
}

void TEA_SwapEndian(uint8_t *data, uint32_t size)
{
    for (uint32_t i = 0; i < size; i += 4)
    {
        conv(data+i,4);
    }
}

int TEA_CheckPy()
{
#ifdef PYTHON
    return 1;
#else
    return 0;
#endif
}