/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once
#include "drivers_api.h"
#include "../../../native-sgx/engine_v2_protocol.h"

#define CHICAGO_ENGINE_PRINT_TYPE "(susuay)"

void chicago_engine_erase (gpointer data, gsize length);
GBytes *chicago_engine_bytes_new (const guint8 *data, gsize length);
gboolean chicago_engine_set_print (FpPrint *print, GBytes *sealed, GError **error);
GBytes *chicago_engine_get_print (FpPrint *print, GError **error);
