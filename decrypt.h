#pragma once

#include <stdlib.h>
#include "file.h"

file_data decrypt_prepare(char* prog_name, void* start, size_t size, void* entry);
